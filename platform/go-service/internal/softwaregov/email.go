package softwaregov

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Customer-facing email copy for the unapproved software alert. UK English,
// "estate" never "fleet", no em dashes. The copy says what the evidence says
// and no more: presence reported by an endpoint, with the report time, and a
// stale device named as stale. It never suggests Patched removes software.

// MaxDigestEmailDevices bounds the devices listed in one email; the counts in
// the email stay exact and the portal has the full list.
const MaxDigestEmailDevices = 200

const emailDateLayout = "02 Jan 2006 15:04 UTC"

// MaxEmailProducts bounds the products listed in one marked email; a bulk
// mark lists this many and says how many more are in the portal.
const MaxEmailProducts = 20

// PortalURL is the customer portal the emails point to.
const PortalURL = "https://app.patched.im"

func platformLabel(p Product) string {
	switch {
	case p.Type == TypeBrowserExtension:
		b := p.Browser
		switch b {
		case "chrome":
			b = "Chrome"
		case "edge":
			b = "Edge"
		case "firefox":
			b = "Firefox"
		case "safari":
			b = "Safari"
		case "any":
			b = "browser"
		}
		return b + " extension"
	case p.Platform == "macos":
		return "macOS"
	case p.Platform == "windows":
		return "Windows"
	}
	return p.Platform
}

func deviceWord(n int) string {
	if n == 1 {
		return "1 device"
	}
	return fmt.Sprintf("%d devices", n)
}

func markedByLine(markedBy *string, via string) string {
	switch {
	case markedBy != nil && *markedBy != "":
		return *markedBy + " in the Patched portal"
	case via == SourceOperator:
		return "your Patched operator"
	}
	return "not recorded"
}

// cleanLine removes characters that could break a plain-text line.
func cleanLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' || r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

func productDetail(b *strings.Builder, p Product) {
	fmt.Fprintf(b, "  Name: %s\n", cleanLine(p.Name))
	fmt.Fprintf(b, "  Type: %s\n", platformLabel(p))
	if p.Type == TypeBrowserExtension {
		fmt.Fprintf(b, "  Extension ID: %s\n", cleanLine(p.ExtensionID))
		return
	}
	fmt.Fprintf(b, "  Identifier: %s\n", cleanLine(p.Identifier))
	if p.TeamID != "" {
		fmt.Fprintf(b, "  Team ID: %s\n", p.TeamID)
	}
}

func deviceLine(d AlertDevice, staleDays int) string {
	line := fmt.Sprintf("  - %s (%s), last reported %s", cleanLine(fallbackText(d.Hostname, d.DeviceID)),
		platformName(d.Platform), d.LastSeen.UTC().Format(emailDateLayout))
	if d.Stale {
		line += fmt.Sprintf(", not reported for over %d days", staleDays)
	}
	return line + "\n"
}

func platformName(p string) string {
	switch p {
	case "macos":
		return "macOS"
	case "windows":
		return "Windows"
	}
	return p
}

func fallbackText(s, alt string) string {
	if strings.TrimSpace(s) == "" {
		return alt
	}
	return s
}

const emailNextSteps = "What to do next\n" +
	"Patched reports the software on your devices. It does not remove it. To remove it, " +
	"use your device management tool, such as Intune or Jamf, or ask whoever manages your devices. " +
	"If the product should be allowed, a portal admin can change its decision in the Patched portal.\n"

func emailFooter(recipient, tenantName string) string {
	return fmt.Sprintf("You are receiving this because %s is the contact address for %s in Patched. "+
		"A portal admin can turn unapproved software alerts off in the Patched portal.\n",
		recipient, cleanLine(fallbackText(tenantName, "your organisation")))
}

// RenderMarkedEmail renders the immediate email for an admin action.
func RenderMarkedEmail(p AlertPayload, tenantName, recipient string) (subject, body string) {
	name := "A product"
	if len(p.Products) > 0 {
		name = cleanLine(p.Products[0].Name)
	}
	if len(p.Products) > 1 {
		name = fmt.Sprintf("%s and %d other products", name, len(p.Products)-1)
	}
	subject = fmt.Sprintf("Patched: %s marked Unapproved and found on %s", name, deviceWord(p.DeviceCount))
	staleDays := int(StaleAfter / (24 * time.Hour))

	var b strings.Builder
	verb, subjectPronoun := "has", "it is"
	if len(p.Products) > 1 {
		verb, subjectPronoun = "have", "they are"
	}
	fmt.Fprintf(&b, "%s %s been marked Unapproved in Patched, and %s installed on %s in your estate.\n\n",
		name, verb, subjectPronoun, deviceWord(p.DeviceCount))
	fmt.Fprintf(&b, "Marked by: %s\n", markedByLine(p.MarkedBy, p.MarkedVia))
	fmt.Fprintf(&b, "Marked at: %s\n\n", p.MarkedAt.UTC().Format(emailDateLayout))
	listed := 0
	for i, prod := range p.Products {
		if i >= MaxEmailProducts {
			fmt.Fprintf(&b, "And %d more products. The full list is in the Patched portal: %s\n\n",
				len(p.Products)-MaxEmailProducts, PortalURL)
			break
		}
		b.WriteString("Product\n")
		productDetail(&b, prod.Product)
		fmt.Fprintf(&b, "\nDevices (%d)\n", prod.DeviceCount)
		shown := 0
		for _, d := range prod.Devices {
			if listed >= MaxDigestEmailDevices {
				break
			}
			b.WriteString(deviceLine(d, staleDays))
			listed++
			shown++
		}
		if shown < prod.DeviceCount {
			b.WriteString("  The full list is in the Patched portal.\n")
		}
		b.WriteString("\n")
	}
	b.WriteString(emailNextSteps)
	b.WriteString("\n")
	b.WriteString(emailFooter(recipient, tenantName))
	return subject, b.String()
}

type digestGroup struct {
	product  Product
	markedBy *string
	via      string
	markedAt time.Time
	devices  []AlertDevice
}

// groupDigest groups alert payloads by (policy, product), most widespread
// first, and adds every device to seen.
func groupDigest(payloads []AlertPayload, seen map[string]bool) []*digestGroup {
	groups := map[string]*digestGroup{}
	var keys []string
	for _, p := range payloads {
		for _, prod := range p.Products {
			k := fmt.Sprintf("%s|%d|%s", p.Policy.Kind, p.Policy.ID, prod.ProductKey)
			g, ok := groups[k]
			if !ok {
				g = &digestGroup{product: prod.Product, markedBy: p.MarkedBy, via: p.MarkedVia, markedAt: p.MarkedAt}
				groups[k] = g
				keys = append(keys, k)
			}
			for _, d := range prod.Devices {
				g.devices = append(g.devices, d)
				seen[d.DeviceID] = true
			}
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		gi, gj := groups[keys[i]], groups[keys[j]]
		if len(gi.devices) != len(gj.devices) {
			return len(gi.devices) > len(gj.devices)
		}
		return strings.ToLower(gi.product.Name) < strings.ToLower(gj.product.Name)
	})
	out := make([]*digestGroup, 0, len(keys))
	for _, k := range keys {
		out = append(out, groups[k])
	}
	return out
}

// RenderDigestEmail renders the daily summary of devices newly observed with
// Unapproved software, and (PAT-2097) of devices where an Unapproved product
// that had been reported gone was found again. A re-open sends no email of
// its own; this digest is where it is reported.
func RenderDigestEmail(payloads, reopened []AlertPayload, tenantName, recipient string) (subject, body string) {
	devices := map[string]bool{}
	fresh := groupDigest(payloads, devices)
	again := groupDigest(reopened, devices)
	subject = fmt.Sprintf("Patched: unapproved software found on %s", deviceWord(len(devices)))
	staleDays := int(StaleAfter / (24 * time.Hour))
	org := cleanLine(fallbackText(tenantName, "your organisation"))

	var b strings.Builder
	listed := 0
	section := func(groups []*digestGroup, heading string, showMarked bool) {
		for _, g := range groups {
			b.WriteString("Product\n")
			productDetail(&b, g.product)
			if showMarked {
				fmt.Fprintf(&b, "  Marked Unapproved by %s", markedByLine(g.markedBy, g.via))
				if !g.markedAt.IsZero() {
					fmt.Fprintf(&b, " on %s", g.markedAt.UTC().Format(emailDateLayout))
				}
				b.WriteString("\n")
			}
			fmt.Fprintf(&b, "\n%s (%d)\n", heading, len(g.devices))
			for _, d := range g.devices {
				if listed >= MaxDigestEmailDevices {
					b.WriteString("  The full list is in the Patched portal.\n")
					break
				}
				b.WriteString(deviceLine(d, staleDays))
				listed++
			}
			b.WriteString("\n")
		}
	}
	if len(fresh) > 0 {
		productWord := "products"
		if len(fresh) == 1 {
			productWord = "product"
		}
		freshDevices := map[string]bool{}
		groupDigest(payloads, freshDevices)
		fmt.Fprintf(&b, "Patched found software marked Unapproved on devices where it had not been reported before. "+
			"This is the daily summary for %s: %d %s on %s.\n\n",
			org, len(fresh), productWord, deviceWord(len(freshDevices)))
		section(fresh, "Newly found on", true)
	}
	if len(again) > 0 {
		againDevices := map[string]bool{}
		groupDigest(reopened, againDevices)
		if len(fresh) == 0 {
			fmt.Fprintf(&b, "This is the daily summary of unapproved software for %s.\n\n", org)
		}
		fmt.Fprintf(&b, "Found again\nSoftware marked Unapproved that had been reported as removed is reported again on %s. "+
			"Its alert is open again in the Patched portal.\n\n", deviceWord(len(againDevices)))
		section(again, "Found again on", false)
	}
	b.WriteString(emailNextSteps)
	b.WriteString("\n")
	b.WriteString(emailFooter(recipient, tenantName))
	return subject, b.String()
}
