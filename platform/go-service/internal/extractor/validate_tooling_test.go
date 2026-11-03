package extractor

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Each invalid tooling fixture must fail for the reason it was written for,
// not for some other violation that happens to be in it too.
func TestToolingInvalidFixturesFailForTheirReason(t *testing.T) {
	cases := map[string]string{
		"ide-extensions-unknown-key.json":                        "ide_extensions.extensions[0].marketplace_url: additional properties not allowed",
		"ide-extensions-failed-with-empty-list.json":             `ide_extensions.extensions: must be omitted when collection_status is "failed"`,
		"ide-extensions-complete-truncated.json":                 `ide_extensions.truncated: a truncated read cannot be "complete"`,
		"ide-extensions-complete-without-evidence.json":          `ide_extensions.profiles: must not be empty when collection_status is "complete"`,
		"package-managers-bad-source.json":                       "package_managers.packages[0].source: value not in enum",
		"package-managers-not-present-source-lists-package.json": "lists a pipx package although sources.pipx is not_present",
		"local-models-complete-with-partial-runtime.json":        "local_models.runtimes.ollama.collection_status: must be complete or not_present",
		"local-models-negative-size.json":                        "local_models.models[0].size_bytes: must be a non-negative integer",
		"mcp-servers-env-field.json":                             "rejected by the privacy guard (classes: env)",
		"mcp-servers-args-field.json":                            "rejected by the privacy guard (classes: args)",
		"mcp-servers-host-not-bare.json":                         "rejected by the privacy guard (classes: host_not_bare)",
		"mcp-servers-failed-with-servers.json":                   `mcp_servers.servers: must be omitted when collection_status is "failed"`,
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			err := ValidatePayload(readFixture(t, "invalid", name))
			if err == nil {
				t.Fatal("expected a validation error")
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not contain %q", err, want)
			}
		})
	}
}

// fixtureWith returns a valid fixture with the tooling block key replaced.
func fixtureWith(t *testing.T, name string, mutate func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(readFixture(t, "valid", name), &m); err != nil {
		t.Fatal(err)
	}
	mutate(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func firstServer(m map[string]any) map[string]any {
	return m["mcp_servers"].(map[string]any)["servers"].([]any)[0].(map[string]any)
}

// The PAT-2021 privacy guard: an env or args field on any MCP server entry
// rejects the payload, the error is typed so the handler can count it, and
// no key the agent sent or value it carried is echoed.
func TestMCPPrivacyGuardRejectsEnvAndArgsWithoutEchoingValues(t *testing.T) {
	const planted = "placeholder-token-value"
	for _, platformFixture := range []string{"with-tooling-complete-macos.json", "with-tooling-complete-windows.json"} {
		for _, tc := range []struct {
			field string
			value any
			class string
		}{
			{"env", map[string]any{"API_KEY": planted}, "env"},
			{"args", []any{"--token", planted}, "args"},
			{"headers", map[string]any{"Authorization": "Bearer " + planted}, "headers"},
			{"url", "https://mcp.example.test/sse?key=" + planted, "url"},
			{"command", "/usr/local/bin/server --key " + planted, "command"},
			{"X-" + planted, "x", "credential"},
			{"weird_" + planted, "x", "credential"},
			{"cwd2", planted, "other_field"},
		} {
			t.Run(platformFixture+"/"+tc.class, func(t *testing.T) {
				body := fixtureWith(t, platformFixture, func(m map[string]any) {
					firstServer(m)[tc.field] = tc.value
				})
				err := ValidatePayload(body)
				var guard *MCPPrivacyGuardError
				if !errors.As(err, &guard) {
					t.Fatalf("want *MCPPrivacyGuardError, got %v", err)
				}
				if !errors.Is(err, ErrMCPPrivacyGuard) {
					t.Fatal("guard error does not match ErrMCPPrivacyGuard")
				}
				if guard.Entries != 1 || guard.Classes[tc.class] != 1 {
					t.Fatalf("entries=%d classes=%v, want one %q", guard.Entries, guard.Classes, tc.class)
				}
				// A known field is reported by its fixed class name, which
				// may equal the key; an unknown key is never named.
				leaks := []string{planted, "API_KEY", "Authorization", "/Users/alice", "alice"}
				if tc.field != tc.class {
					leaks = append(leaks, tc.field)
				}
				for _, leak := range leaks {
					if strings.Contains(err.Error(), leak) {
						t.Fatalf("guard error echoes %q: %s", leak, err)
					}
				}
			})
		}
	}
}

// Unreduced values in allowlisted fields are guard hits too.
func TestMCPPrivacyGuardRejectsUnreducedValues(t *testing.T) {
	for _, tc := range []struct {
		field, value, class string
	}{
		{"host", "mcp.example.test/v1", "host_not_bare"},
		{"host", "user:pw@mcp.example.test", "host_not_bare"},
		{"host", "mcp.example.test:8443", "host_not_bare"},
		{"executable", "/usr/local/bin/npx", "executable_not_basename"},
		{"executable", `C:\tools\npx.cmd`, "executable_not_basename"},
		{"package", "@scope/pkg --token=abc", "package_not_reduced"},
		{"package", "https://registry.example.test/pkg", "package_not_reduced"},
		{"name", "ghp_" + strings.Repeat("A", 36), "secret_shaped_value"},
		{"name", "server\nsecond-line", "name_not_reduced"},
	} {
		t.Run(tc.field+"/"+tc.class, func(t *testing.T) {
			body := fixtureWith(t, "with-tooling-complete-macos.json", func(m map[string]any) {
				firstServer(m)[tc.field] = tc.value
			})
			err := ValidatePayload(body)
			var guard *MCPPrivacyGuardError
			if !errors.As(err, &guard) || guard.Classes[tc.class] == 0 {
				t.Fatalf("want guard class %q, got %v", tc.class, err)
			}
			if strings.Contains(err.Error(), tc.value) {
				t.Fatalf("guard error echoes the value: %s", err)
			}
		})
	}
	// An IPv6 host and a plain host are reduced forms, not hits.
	for _, host := range []string{"2001:db8::1", "api.githubcopilot.com"} {
		body := fixtureWith(t, "with-tooling-complete-macos.json", func(m map[string]any) {
			s := firstServer(m)
			s["host"], s["transport"] = host, "http"
		})
		if err := ValidatePayload(body); err != nil {
			t.Fatalf("host %q: %v", host, err)
		}
	}
}

// The guard runs before anything else, so a guard hit is counted even when
// the payload is also broken elsewhere.
func TestMCPPrivacyGuardRunsFirst(t *testing.T) {
	body := fixtureWith(t, "with-tooling-complete-macos.json", func(m map[string]any) {
		delete(m, "device")
		firstServer(m)["env"] = map[string]any{"K": "v"}
	})
	var guard *MCPPrivacyGuardError
	if err := ValidatePayload(body); !errors.As(err, &guard) {
		t.Fatalf("want the guard error first, got %v", err)
	}
}

// Other MCP contract errors do not echo unknown key names either.
func TestMCPValidationDoesNotEchoKeysOutsideServers(t *testing.T) {
	body := fixtureWith(t, "with-tooling-complete-macos.json", func(m map[string]any) {
		cfg := m["mcp_servers"].(map[string]any)["configs"].([]any)[0].(map[string]any)
		cfg["sk-planted"] = "x"
	})
	err := ValidatePayload(body)
	if err == nil || strings.Contains(err.Error(), "sk-planted") {
		t.Fatalf("want an error that does not echo the key, got %v", err)
	}
}

// Validation errors never echo an enum value the agent sent.
func TestToolingEnumErrorsDoNotEchoValues(t *testing.T) {
	body := fixtureWith(t, "with-tooling-complete-macos.json", func(m map[string]any) {
		firstServer(m)["transport"] = "stdio-planted-value"
	})
	err := ValidatePayload(body)
	if err == nil || strings.Contains(err.Error(), "planted") {
		t.Fatalf("want an error without the value, got %v", err)
	}
}

// Status invariants shared by the four blocks.
func TestToolingStatusInvariants(t *testing.T) {
	block := func(name string) func(m map[string]any) map[string]any {
		return func(m map[string]any) map[string]any { return m[name].(map[string]any) }
	}
	for _, tc := range []struct {
		name, want string
		mutate     func(m map[string]any)
	}{
		{"packages complete truncated", `package_managers.truncated: a truncated read cannot be "complete"`, func(m map[string]any) {
			b := block("package_managers")(m)
			b["truncated"], b["truncation_reason"] = true, "package_limit"
		}},
		{"reason without truncation", "truncation_reason: set on a read that is not truncated", func(m map[string]any) {
			block("local_models")(m)["truncation_reason"] = "time_limit"
		}},
		{"not_present with servers", `must be not_present when collection_status is "not_present"`, func(m map[string]any) {
			block("mcp_servers")(m)["collection_status"] = "not_present"
		}},
		{"complete with a partial location", `package_managers.locations[1].collection_status: must be "complete"`, func(m map[string]any) {
			block("package_managers")(m)["locations"].([]any)[1].(map[string]any)["collection_status"] = "partial"
		}},
		{"non-failed missing a key", "ide_extensions.profiles: required field is missing", func(m map[string]any) {
			delete(block("ide_extensions")(m), "profiles")
		}},
		{"source missing", "package_managers.sources.pipx: required field is missing", func(m map[string]any) {
			delete(block("package_managers")(m)["sources"].(map[string]any), "pipx")
		}},
		{"vscode family editor", "ide_extensions.extensions[0].editor: value not in enum", func(m map[string]any) {
			block("ide_extensions")(m)["extensions"].([]any)[0].(map[string]any)["editor"] = "IntelliJIdea"
		}},
		{"over the bound", "entries exceeds the contract maximum of 2000", func(m map[string]any) {
			b := block("mcp_servers")(m)
			s := b["servers"].([]any)
			for len(s) <= mcpMaxServers {
				s = append(s, s[0])
			}
			b["servers"] = s
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePayload(fixtureWith(t, "with-tooling-complete-macos.json", tc.mutate))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// Review P3.1: the server accepts exactly the hosts both agents emit
// (updater mcp_servers.sh url_host and McpServerScanLogic.UrlHost): a
// lower-case DNS name that is not secret-shaped, or the inside of an IPv6
// literal matching ^[0-9a-f:.]{2,45}$. Anything else is a guard hit.
func TestMCPHostMatchesAgentReduction(t *testing.T) {
	for host, ok := range map[string]bool{
		"api.githubcopilot.com": true,
		"localhost":             true,
		"::1":                   true,
		"1:2":                   true, // one colon: the agents' IPv6 pattern accepts it
		"fe80:1":                true,
		"2001:db8::1":           true,
		"API.EXAMPLE.COM":       false, // agents lower-case every host
		"user:pw@evil.example":  false,
		"evil.example:8443":     false,
		"evil.example/path":     false,
		"[::1]":                 false,
		// No colon, so not an IPv6 literal: a hex-only token must hit the
		// secret-shape check instead of the IPv6 branch (review round 2).
		"0123456789abcdef0123456789abcdef01234567": false,
	} {
		body := fixtureWith(t, "with-tooling-complete-macos.json", func(m map[string]any) {
			s := firstServer(m)
			s["host"], s["transport"] = host, "http"
		})
		err := ValidatePayload(body)
		if ok && err != nil {
			t.Errorf("host %q rejected: %v", host, err)
		}
		if !ok && err == nil {
			t.Errorf("host %q accepted", host)
		}
	}
}

// Review P3.2: a complete block needs every user row complete or
// not_present (a user with no editor, package, runtime or client is
// not_present), including each user's per-unit statuses.
func TestToolingCompleteRequiresCompleteUsers(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		edit       func(m map[string]any)
	}{
		{"ide user partial", `ide_extensions.users[0].collection_status: must be complete or not_present`, func(m map[string]any) {
			m["ide_extensions"].(map[string]any)["users"].([]any)[0].(map[string]any)["collection_status"] = "partial"
		}},
		{"mcp user failed", `mcp_servers.users[0].collection_status: must be complete or not_present`, func(m map[string]any) {
			m["mcp_servers"].(map[string]any)["users"].([]any)[0].(map[string]any)["collection_status"] = "failed"
		}},
		{"package user unit failed", `package_managers.users[0].sources.pip_user: must be complete or not_present`, func(m map[string]any) {
			m["package_managers"].(map[string]any)["users"].([]any)[0].(map[string]any)["sources"].(map[string]any)["pip_user"] = "failed"
		}},
		{"model user unit partial", `local_models.users[0].runtimes.ollama: must be complete or not_present`, func(m map[string]any) {
			m["local_models"].(map[string]any)["users"].([]any)[0].(map[string]any)["runtimes"].(map[string]any)["ollama"] = "partial"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePayload(fixtureWith(t, "with-tooling-complete-macos.json", tc.edit))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	// A user with nothing installed is not_present, and that is complete.
	err := ValidatePayload(fixtureWith(t, "with-tooling-complete-macos.json", func(m map[string]any) {
		b := m["ide_extensions"].(map[string]any)
		b["users"] = append(b["users"].([]any), map[string]any{"user": "bob", "user_id": "502", "collection_status": "not_present", "profiles": 0})
	}))
	if err != nil {
		t.Fatalf("a not_present user broke a complete block: %v", err)
	}
}

// Review P3.3: issue codes and paths, config paths and server config paths
// in mcp_servers go through the guard too: a URL (userinfo included) or a
// secret shape where a path belongs is a hit.
func TestMCPPathsAndIssuesThroughGuard(t *testing.T) {
	const planted = "ghp_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, tc := range []struct {
		name string
		edit func(m map[string]any)
	}{
		{"server config_path url userinfo", func(m map[string]any) { firstServer(m)["config_path"] = "https://user:pw@evil.example/mcp.json" }},
		{"config path url", func(m map[string]any) {
			m["mcp_servers"].(map[string]any)["configs"].([]any)[0].(map[string]any)["path"] = "file://user:pw@host/x.json"
		}},
		{"issue path url", func(m map[string]any) {
			m["mcp_servers"].(map[string]any)["issues"] = []any{map[string]any{"code": "url_unrecognised", "path": "https://user:pw@evil.example/x"}}
		}},
		{"issue code value", func(m map[string]any) {
			m["mcp_servers"].(map[string]any)["issues"] = []any{map[string]any{"code": "Bearer " + planted, "path": "/Users/alice/.cursor/mcp.json"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePayload(fixtureWith(t, "with-tooling-complete-macos.json", tc.edit))
			var guard *MCPPrivacyGuardError
			if !errors.As(err, &guard) {
				t.Fatalf("want a guard error, got %v", err)
			}
			if strings.Contains(err.Error(), planted) || strings.Contains(err.Error(), "evil.example") {
				t.Fatalf("guard error echoes a value: %v", err)
			}
		})
	}
	// The agents' own forms pass: an issue with the "<unprintable>" path,
	// and paths the agents do not secret-check (a home directory named like
	// a key, an "@" or a drive colon in a Windows path): rejecting those
	// would lock a device out on every check-in.
	err := ValidatePayload(fixtureWith(t, "with-tooling-complete-macos.json", func(m map[string]any) {
		b := m["mcp_servers"].(map[string]any)
		b["issues"] = []any{
			map[string]any{"code": "symlink_not_followed", "path": "<unprintable>"},
			map[string]any{"code": "unreadable", "path": `C:\Users\bob@corp\.cursor\mcp.json`},
		}
		b["configs"].([]any)[0].(map[string]any)["path"] = "/Users/sk_" + planted + "/Library/Application Support/Claude/claude_desktop_config.json"
		firstServer(m)["config_path"] = "/Users/sk_" + planted + "/Library/Application Support/Claude/claude_desktop_config.json"
	}))
	if err != nil {
		t.Fatal(err)
	}
}

// Review round 2 (a): values an agent can legitimately emit pass the server.
// Both agents drop an unbroken 32-character alphanumeric run, so the longest
// values they send carry separators; 32-character ones of those pass.
func TestMCPAgentValidLongValuesPass(t *testing.T) {
	name := "filesystem-server-for-project-01"
	pkg := "@modelcontextprotocol/server-abc"
	if len(name) != 32 || len(pkg) != 32 {
		t.Fatalf("fixture lengths %d %d", len(name), len(pkg))
	}
	err := ValidatePayload(fixtureWith(t, "with-tooling-complete-macos.json", func(m map[string]any) {
		s := firstServer(m)
		s["name"], s["package"] = name, pkg
	}))
	if err != nil {
		t.Fatal(err)
	}
}
