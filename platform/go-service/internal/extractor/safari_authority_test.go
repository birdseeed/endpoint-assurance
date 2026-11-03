package extractor

import "testing"

// PAT-2067 review: a Safari complete is only trusted when the report can
// show it was not capped. The macOS agent walks Safari last under one
// shared row cap, so a cap hit by the other browsers skips Safari entirely.
func TestResolveSafariSignalWithholdsWhenCapCannotBeRuledOut(t *testing.T) {
	base := func() *payload {
		return &payload{
			SchemaVersion:            3,
			CollectionStatus:         &collectionStatusPart{SafariExtensions: "complete"},
			BrowserExtensionsPresent: true,
			BrowserExtensionsStatus:  &browserExtensionsStatusPart{CollectionStatus: "complete"},
		}
	}

	if got := resolveSafariSignal(base()); !got.authoritative {
		t.Fatalf("control: a v3 complete with an uncapped status block should be trusted, got %+v", got)
	}

	noBlock := base()
	noBlock.BrowserExtensionsStatus = nil
	if got := resolveSafariSignal(noBlock); got.authoritative || got.withheld != "complete_without_browser_extensions_status" {
		t.Fatalf("complete without browser_extensions_status: got %+v", got)
	}

	full := base()
	full.BrowserExtensions = make([]browserExtensionPart, browserExtensionAgentRowCap)
	if got := resolveSafariSignal(full); got.authoritative || got.withheld != "row_cap_full" {
		t.Fatalf("complete with a full row array: got %+v", got)
	}

	under := base()
	under.BrowserExtensions = make([]browserExtensionPart, browserExtensionAgentRowCap-1)
	if got := resolveSafariSignal(under); !got.authoritative {
		t.Fatalf("complete one row under the cap should be trusted, got %+v", got)
	}
}
