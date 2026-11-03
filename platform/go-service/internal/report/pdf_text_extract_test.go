package report

// Pure-Go PDF text extraction for PAT-2265's round-trip tests. Purpose-built
// for this package's own renderers rather than a general PDF text extractor
// (that's why it lives in a _test.go file, not a third-party dependency):
// every renderer in this package registers its body text through
// registerReportFont / fpdf's AddUTF8FontFromBytes, and fpdf always emits the
// same trivial identity ToUnicode CMap for a UTF-8 font
// (<0000> <FFFF> <0000> — see go-pdf/fpdf's utf8fontfile.go toUnicode
// constant), meaning every 2-byte character code in a Tj/TJ operand for that
// font IS the Unicode code point directly, with no CMap lookup required.
// General-purpose pure-Go PDF text libraries evaluated for this ticket
// (github.com/ledongthuc/pdf) mis-decoded several of the fixture's non-ASCII
// characters against fpdf's own output, so this targets fpdf's actual
// output shape directly instead.
//
// It does not attempt to parse the PDF object graph, xref table or page
// tree: it scans every indirect object for a stream, decompresses
// FlateDecode streams, and pulls text out of any BT...ET block it finds.
// That is enough for a renderer this package controls end to end.

import (
	"bytes"
	"compress/zlib"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

var (
	reReportObjStream = regexp.MustCompile(`(?s)\d+\s+0\s+obj\s*(<<.*?>>)\s*stream\r?\n`)
	reReportBTET      = regexp.MustCompile(`(?s)BT(.*?)ET`)
	reReportTjOp      = regexp.MustCompile(`(?s)(\((?:\\.|[^\\()])*\)|<[0-9A-Fa-f\s]*>)\s*(?:Tj|'|")`)
	reReportTJArrayOp = regexp.MustCompile(`(?s)\[((?:\\.|[^\[\]\\]|\((?:\\.|[^\\()])*\))*)\]\s*TJ`)
	reReportTJElem    = regexp.MustCompile(`(?s)(\((?:\\.|[^\\()])*\)|<[0-9A-Fa-f\s]*>)`)
)

// extractReportPDFText returns the visible text of a PDF rendered by this
// package's own renderers, decoded from every content stream it can find.
// Distinct BT/ET blocks (roughly: distinct lines/cells) are joined with "\n".
func extractReportPDFText(pdfBytes []byte) (string, error) {
	streams, err := reportPDFContentStreams(pdfBytes)
	if err != nil {
		return "", err
	}

	var out strings.Builder
	for _, s := range streams {
		for _, block := range reReportBTET.FindAllStringSubmatch(string(s), -1) {
			body := block[1]
			for _, m := range reReportTjOp.FindAllStringSubmatch(body, -1) {
				out.WriteString(decodeReportPDFTextOperand(m[1]))
			}
			for _, m := range reReportTJArrayOp.FindAllStringSubmatch(body, -1) {
				for _, elem := range reReportTJElem.FindAllString(m[1], -1) {
					out.WriteString(decodeReportPDFTextOperand(elem))
				}
			}
			out.WriteString("\n")
		}
	}
	return out.String(), nil
}

// decodeReportPDFTextOperand decodes one Tj/TJ string operand -- a literal string
// "(...)" (with PDF backslash escapes) or a hex string "<...>" -- into raw
// bytes, then reinterprets those bytes as big-endian UTF-16 code units
// (fpdf's Identity-H + identity-ToUnicode convention: 2-byte code == Unicode
// code point) and returns the decoded text.
func decodeReportPDFTextOperand(op string) string {
	var raw []byte
	switch {
	case strings.HasPrefix(op, "("):
		raw = decodeReportPDFLiteralString(op[1 : len(op)-1])
	case strings.HasPrefix(op, "<"):
		raw = decodeReportPDFHexString(op[1 : len(op)-1])
	default:
		return ""
	}
	if len(raw)%2 != 0 {
		raw = raw[:len(raw)-1]
	}
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		units = append(units, uint16(raw[i])<<8|uint16(raw[i+1]))
	}
	return string(utf16.Decode(units))
}

// decodeReportPDFLiteralString unescapes a PDF "(...)" literal string body
// (backslash escapes for \n \r \t \b \f, escaped parens/backslash, octal
// \ddd, and line-continuation) into raw bytes.
func decodeReportPDFLiteralString(s string) []byte {
	var out bytes.Buffer
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out.WriteByte(c)
			continue
		}
		i++
		if i >= len(s) {
			break
		}
		switch s[i] {
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case 'b':
			out.WriteByte('\b')
		case 'f':
			out.WriteByte('\f')
		case '(', ')', '\\':
			out.WriteByte(s[i])
		case '\r', '\n':
			// line continuation: emits nothing
		default:
			if s[i] >= '0' && s[i] <= '7' {
				j := i
				for j < len(s) && j < i+3 && s[j] >= '0' && s[j] <= '7' {
					j++
				}
				n, _ := strconv.ParseUint(s[i:j], 8, 16)
				out.WriteByte(byte(n))
				i = j - 1
			} else {
				out.WriteByte(s[i])
			}
		}
	}
	return out.Bytes()
}

// decodeReportPDFHexString decodes a PDF "<...>" hex string body into raw bytes.
func decodeReportPDFHexString(s string) []byte {
	clean := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			clean = append(clean, c)
		}
	}
	if len(clean)%2 != 0 {
		clean = append(clean, '0')
	}
	out := make([]byte, len(clean)/2)
	for i := range out {
		v, _ := strconv.ParseUint(string(clean[i*2:i*2+2]), 16, 8)
		out[i] = byte(v)
	}
	return out
}

// reportPDFContentStreams finds every indirect object's stream in a raw PDF byte
// slice and returns its decompressed bytes (or raw bytes, if not
// FlateDecode-filtered). Deliberately does not distinguish content streams
// from font/image streams -- BT...ET scanning downstream only finds text in
// the ones that have any, and fpdf's simple single-generation output has no
// object streams or cross-reference streams to worry about.
func reportPDFContentStreams(data []byte) ([][]byte, error) {
	var result [][]byte
	locs := reReportObjStream.FindAllSubmatchIndex(data, -1)
	for _, loc := range locs {
		dict := data[loc[2]:loc[3]]
		streamStart := loc[1]
		endIdx := bytes.Index(data[streamStart:], []byte("endstream"))
		if endIdx < 0 {
			continue
		}
		raw := bytes.TrimRight(data[streamStart:streamStart+endIdx], "\r\n")
		if bytes.Contains(dict, []byte("FlateDecode")) {
			zr, err := zlib.NewReader(bytes.NewReader(raw))
			if err != nil {
				continue
			}
			decompressed, err := io.ReadAll(zr)
			zr.Close()
			if err != nil {
				continue
			}
			result = append(result, decompressed)
		} else {
			result = append(result, raw)
		}
	}
	return result, nil
}
