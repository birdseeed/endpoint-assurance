package driverblock

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// PAT-2263: the two source parsers, on hand-written fixtures in each source's
// real format (testdata/README.md). Nothing is fetched.

var fixtureFetchedAt = time.Date(2026, 9, 29, 2, 0, 0, 0, time.UTC)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// microsoftZip packages a policy the way Microsoft publishes it.
func microsoftZip(t *testing.T, policy []byte, extra ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	if _, err := w.Create("VulnerableDriverBlockList/"); err != nil {
		t.Fatal(err)
	}
	f, err := w.Create("VulnerableDriverBlockList/DriverPolicy_Enforced.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(policy); err != nil {
		t.Fatal(err)
	}
	for _, name := range extra {
		g, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = g.Write([]byte("<x/>"))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func entryKeys(entries []Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.HashKind+" "+e.Hash+" "+e.EntryID+" "+e.Category)
	}
	sort.Strings(out)
	return out
}

func TestParseMicrosoft_ZipAsPublished(t *testing.T) {
	policy := readTestdata(t, "DriverPolicy_Enforced.xml")
	snap, err := ParseMicrosoft(microsoftZip(t, policy, "VulnerableDriverBlockList/SiPolicy_Enforced_LegacyFormat.p7b"), fixtureFetchedAt)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Source != SourceMicrosoft || snap.SourceURL != MicrosoftURL || snap.SourceRevision != "10.0.99999.1" || !snap.FetchedAt.Equal(fixtureFetchedAt) {
		t.Fatalf("provenance = %+v", snap)
	}
	want := []string{
		"authenticode_sha1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ID_DENY_OLDONLY_1 vulnerable",
		"authenticode_sha256 8812f0c849e0e9537b5060dd011057885eaf9047af11842840b97d8444eff841 ID_DENY_SYNTH_PE_SHA256 vulnerable",
	}
	if got := entryKeys(snap.Entries); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("entries:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Three page-hash rules and one malformed hash; the FileName rule is not a hash rule.
	if snap.Skipped != 4 {
		t.Fatalf("skipped = %d, want 4", snap.Skipped)
	}
}

func TestParseMicrosoft_ThePolicyAloneIsAccepted_ForAReplayFile(t *testing.T) {
	snap, err := ParseMicrosoft(append([]byte("\xef\xbb\xbf"), readTestdata(t, "DriverPolicy_Enforced.xml")...), fixtureFetchedAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Entries) != 2 {
		t.Fatalf("entries = %d", len(snap.Entries))
	}
}

func TestParseMicrosoft_FileNameRulesAreNeverStored(t *testing.T) {
	snap, err := ParseMicrosoft(readTestdata(t, "DriverPolicy_Enforced.xml"), fixtureFetchedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range snap.Entries {
		if e.EntryID == "ID_DENY_BYNAME" || strings.Contains(e.EntryName, "gdrv") {
			t.Fatalf("a name-only rule became a hash entry: %+v", e)
		}
	}
}

func TestParseMicrosoft_Refusals(t *testing.T) {
	policy := string(readTestdata(t, "DriverPolicy_Enforced.xml"))
	cases := map[string][]byte{
		"not xml":            []byte("hello"),
		"wrong namespace":    []byte(strings.Replace(policy, "urn:schemas-microsoft-com:sipolicy", "urn:example", 1)),
		"no version":         []byte(strings.Replace(policy, "<VersionEx>10.0.99999.1</VersionEx>", "", 1)),
		"no hash rules":      []byte(`<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy"><VersionEx>1.0.0.0</VersionEx><FileRules/></SiPolicy>`),
		"zip without policy": zipWith(t, "VulnerableDriverBlockList/Other.xml", []byte(policy)),
		"zip with two":       microsoftZip(t, []byte(policy), "Other/DriverPolicy_Enforced.xml"),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseMicrosoft(data, fixtureFetchedAt); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestParseMicrosoft_AnOversizedPolicyInTheZipIsRefused(t *testing.T) {
	big := append([]byte(`<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy"><!--`), bytes.Repeat([]byte("a"), maxMicrosoftPolicyBytes)...)
	big = append(big, []byte(`--></SiPolicy>`)...)
	if _, err := ParseMicrosoft(microsoftZip(t, big), fixtureFetchedAt); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v", err)
	}
}

func zipWith(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

func TestParseLOLDrivers_Fixture(t *testing.T) {
	data := readTestdata(t, "drivers.json")
	snap, err := ParseLOLDrivers(data, fixtureFetchedAt)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Source != SourceLOLDrivers || snap.SourceURL != LOLDriversURL || !strings.HasPrefix(snap.SourceRevision, "sha256:") {
		t.Fatalf("provenance = %+v", snap)
	}
	want := []string{
		"authenticode_sha1 9999999999999999999999999999999999999999 00000000-0000-4000-8000-000000000003 vulnerable",
		"authenticode_sha256 7777777777777777777777777777777777777777777777777777777777777777 00000000-0000-4000-8000-000000000001 vulnerable",
		"authenticode_sha256 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee 00000000-0000-4000-8000-000000000002 malicious",
		"sha1 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 00000000-0000-4000-8000-000000000001 vulnerable",
		"sha256 357c27a02e97161fc2fbb97dc21a8b3d60053a591a1f1d760d91159fcc507cf1 00000000-0000-4000-8000-000000000001 vulnerable",
		"sha256 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd 00000000-0000-4000-8000-000000000002 malicious",
		"sha256 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 00000000-0000-4000-8000-000000000003 vulnerable",
	}
	if got := entryKeys(snap.Entries); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("entries:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if snap.Skipped != 1 {
		t.Fatalf("skipped = %d, want 1 (the unknown category)", snap.Skipped)
	}
	for _, e := range snap.Entries {
		if e.EntryID == "00000000-0000-4000-8000-000000000001" && e.EntryName != "gdrv.sys" {
			t.Fatalf("entry name = %q", e.EntryName)
		}
	}
	// A SHA-1 is kept only where the sample had no SHA-256 of the same kind.
	for _, e := range snap.Entries {
		if e.Hash == "d348d0ef0d72cf831c6cbfb9479ff27318bc8715" || e.Hash == "6666666666666666666666666666666666666666" {
			t.Fatalf("SHA-1 stored beside a SHA-256: %+v", e)
		}
	}
	again, _ := ParseLOLDrivers(data, fixtureFetchedAt)
	if again.SourceRevision != snap.SourceRevision {
		t.Fatal("revision is not a stable digest of the document")
	}
}

func TestParseLOLDrivers_Refusals(t *testing.T) {
	for name, data := range map[string]string{
		"not json":          `{`,
		"not an array":      `{"Id": "x"}`,
		"nothing matchable": `[{"Id":"a","Category":"vulnerable driver","KnownVulnerableSamples":[{"SHA256":""}]}]`,
		"empty":             `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseLOLDrivers([]byte(data), fixtureFetchedAt); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestParse_UnknownSource(t *testing.T) {
	if _, err := Parse("elsewhere", []byte("[]"), fixtureFetchedAt); err == nil {
		t.Fatal("accepted")
	}
	if _, err := AuthorityURL("elsewhere"); err == nil {
		t.Fatal("accepted")
	}
}

func TestBoundRunes_StripsControlCharacters(t *testing.T) {
	if got := boundRunes("a\x00b\nc‮", 10); got != "abc" {
		t.Fatalf("got %q", got)
	}
	if got := boundRunes("abcdef", 3); got != "abc" {
		t.Fatalf("got %q", got)
	}
}

func TestSourceStateStale(t *testing.T) {
	now := fixtureFetchedAt.Add(time.Hour)
	fresh := fixtureFetchedAt
	old := fixtureFetchedAt.Add(-SourceFreshFor - time.Minute)
	cases := []struct {
		name  string
		state SourceState
		want  bool
	}{
		{"fresh success", SourceState{Status: "succeeded", FetchedAt: &fresh}, false},
		{"old success", SourceState{Status: "succeeded", FetchedAt: &old}, true},
		{"failed after success", SourceState{Status: "failed", FetchedAt: &fresh}, true},
		{"never fetched", SourceState{Status: "failed"}, true},
	}
	for _, c := range cases {
		if got := c.state.Stale(now); got != c.want {
			t.Errorf("%s: stale = %v", c.name, got)
		}
	}
}

// Review follow-up: a SHA-1 rule is dropped only when its own SHA-256 partner
// rule (same stem, ID ending _SHA256 for _SHA1) exists. Two different drivers
// that happen to share a FriendlyName stem keep every hash.
func TestParseMicrosoft_KeepsAnUnpairedSHA1_EvenWhenAStemCollides(t *testing.T) {
	policy := `<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy"><VersionEx>1.0.0.0</VersionEx><FileRules>
<Deny ID="ID_DENY_A_SHA256" FriendlyName="Shared.sys Hash Sha256" Hash="1212121212121212121212121212121212121212121212121212121212121212" />
<Deny ID="ID_DENY_B_SHA1" FriendlyName="Shared.sys Hash Sha1" Hash="3434343434343434343434343434343434343434" />
<Deny ID="ID_DENY_C_SHA256" FriendlyName="Pair.sys Hash Sha256" Hash="5656565656565656565656565656565656565656565656565656565656565656" />
<Deny ID="ID_DENY_C_SHA1" FriendlyName="Pair.sys Hash Sha1" Hash="7878787878787878787878787878787878787878" />
</FileRules></SiPolicy>`
	snap, err := ParseMicrosoft([]byte(policy), fixtureFetchedAt)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"authenticode_sha1 3434343434343434343434343434343434343434 ID_DENY_B_SHA1 vulnerable",
		"authenticode_sha256 1212121212121212121212121212121212121212121212121212121212121212 ID_DENY_A_SHA256 vulnerable",
		"authenticode_sha256 5656565656565656565656565656565656565656565656565656565656565656 ID_DENY_C_SHA256 vulnerable",
	}
	if got := entryKeys(snap.Entries); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("entries:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// Review follow-up: an empty list never replaces anything, first fetch included.
func TestReplaceSnapshot_RefusesAnEmptySnapshotBeforeTouchingTheDatabase(t *testing.T) {
	err := ReplaceSnapshot(context.Background(), nil, Snapshot{Source: SourceLOLDrivers, SourceURL: LOLDriversURL, FetchedAt: fixtureFetchedAt}, fixtureFetchedAt)
	if err == nil {
		t.Fatal("an empty snapshot was accepted")
	}
}

// Review follow-up: with no URL override the documented authority is fetched,
// and a non-HTTPS override is refused before any request is made.
func TestFetch_DefaultsToTheAuthorityURL_AndRefusesNonHTTPS(t *testing.T) {
	var requested []string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requested = append(requested, r.URL.String())
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})}
	for _, source := range Sources {
		requested = nil
		_, _ = Fetch(context.Background(), client, source, "", fixtureFetchedAt)
		authority, _ := AuthorityURL(source)
		if len(requested) != 1 || requested[0] != authority {
			t.Fatalf("%s: requested %v, want %s", source, requested, authority)
		}
		requested = nil
		for _, bad := range []string{"http://mirror.example/x", "ftp://mirror.example/x", "mirror.example/x"} {
			if _, err := Fetch(context.Background(), client, source, bad, fixtureFetchedAt); err == nil || len(requested) != 0 {
				t.Fatalf("%s: %q accepted or fetched (%v)", source, bad, requested)
			}
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
