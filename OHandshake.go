// OHandshake — WPA Handshake Capture/Analyzer
// Author  : khaled.s.haddad
// Website : owlsec.org
// Language: Go (stdlib only, static, CGO disabled)
// OWL Security Tools — Batch 3 (Wireless). Authorized testing only.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const APPNAME = "OHandshake"
const SUITE = "Owl Wireless Suite"
const TAGLINE = "WPA/WPA2 Handshake Analyzer"
const SUBLINE = "pcap/pcapng · 4-way M1–M4 · PMKID · MIC · hashcat -m 22000 · TXT/MD/JSON/CSV/SARIF"
const VERSION = "1.0"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"
const CATEGORY = "OWireless"
const MITRE = "T1040, T1110.002, T1557.002"

const BANNER = `
 ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗██████╗ ███████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗
██╔═══██╗██║  ██║██╔══██╗████╗  ██║██╔══██╗██╔════╝██║  ██║██╔══██╗██║ ██╔╝██╔════╝
██║   ██║███████║███████║██╔██╗ ██║██║  ██║███████╗███████║███████║█████╔╝ █████╗
██║   ██║██╔══██║██╔══██║██║╚██╗██║██║  ██║╚════██║██╔══██║██╔══██║██╔═██╗ ██╔══╝
╚██████╔╝██║  ██║██║  ██║██║ ╚████║██████╔╝███████║██║  ██║██║  ██║██║  ██╗███████╗
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
`

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
// CYAN is the primary brand/frame colour; red is reserved for errors and
// CRITICAL/HIGH severities.
const (
	R   = "\033[91m"       // red     — errors / critical
	GRN = "\033[92m"       // green   — success / low
	YLW = "\033[93m"       // yellow  — prompts / warning text
	CY  = "\033[96m"       // cyan    — primary brand & frames
	W   = "\033[97m"       // white   — body text
	B   = "\033[1m"        // bold
	X   = "\033[0m"        // reset
	MG  = "\033[95m"       // magenta — suite name / accents
	DIM = "\033[2m"        // dim     — secondary text
	OR  = "\033[38;5;208m" // orange  — warning markers
	GY  = "\033[90m"       // gray    — muted
	DR  = CY               // legacy alias (was dark-red frame) → cyan
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear()           { fmt.Print("\033[H\033[2J") }
func line(w int)       { fmt.Println(col(strings.Repeat("─", w), DR)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }

// BANNER = pyfiglet.figlet_format(APPNAME, font="small"), each backtick->apostrophe, 2-space indent
func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}
func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0) // stdin closed (Ctrl-D / end of piped input)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	bufio.NewReader(os.Stdin).ReadString('\n')
}
func menu(title string, items []menuAction) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for i, it := range items {
		fmt.Println("  " + col(pad(fmt.Sprintf("[%02d]", i+1), 5), CY+B) + "  " +
			col(pad(it.label, 24), W) + col("─ "+it.desc, DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 5), YLW+B) + "  " + col(pad("Help & Usage", 24), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 5), R+B) + "  " + col(pad("Exit", 24), W) + col("─ Quit "+APPNAME, DIM))
	fmt.Println()
	rule()
	return prompt("Select option")
}
func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && len(c) > w[i] {
				w[i] = len(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), CY+B))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DR))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DR))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DR))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

// ============================================================================
//  OWL shared core — formatting, grading, numeric + byte helpers
// ============================================================================

var startedAt = time.Now()

func appVersion() string { return VERSION }

// sectionHeader prints a colored section heading used by help/howto/report views.
func sectionHeader(s string) {
	fmt.Println()
	rule()
	fmt.Println("  " + col("⬡  "+s, B+CY))
	rule()
}

func subHeader(s string) { fmt.Println("  " + col("» "+s, CY+B)) }

func kvRow(k, v string) {
	fmt.Println("  " + col(pad(k, 22), GY) + col(v, W))
}

func bullet(s string) { fmt.Println("   " + col("•", CY) + " " + col(s, W)) }

func numbered(i int, s string) {
	fmt.Println("   " + col(fmt.Sprintf("%2d.", i), CY+B) + " " + col(s, W))
}

// hr draws a plain separator (no ANSI) for exported text reports.
func hr(w int) string { return strings.Repeat("-", w) }

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ---------------------------------------------------------------------------
//  Grading engine (A+ .. F) based on a 0..100 posture/quality score.
// ---------------------------------------------------------------------------

func gradeFromScore(score float64) string {
	switch {
	case score >= 97:
		return "A+"
	case score >= 93:
		return "A"
	case score >= 90:
		return "A-"
	case score >= 87:
		return "B+"
	case score >= 83:
		return "B"
	case score >= 80:
		return "B-"
	case score >= 77:
		return "C+"
	case score >= 73:
		return "C"
	case score >= 70:
		return "C-"
	case score >= 67:
		return "D+"
	case score >= 63:
		return "D"
	case score >= 60:
		return "D-"
	default:
		return "F"
	}
}

func gradeColor(g string) string {
	switch {
	case strings.HasPrefix(g, "A"):
		return GRN + B
	case strings.HasPrefix(g, "B"):
		return GRN
	case strings.HasPrefix(g, "C"):
		return YLW
	case strings.HasPrefix(g, "D"):
		return R
	default:
		return R + B
	}
}

func gradeLabel(g string) string {
	switch {
	case strings.HasPrefix(g, "A"):
		return "Excellent posture"
	case strings.HasPrefix(g, "B"):
		return "Good posture, minor gaps"
	case strings.HasPrefix(g, "C"):
		return "Fair, several weaknesses"
	case strings.HasPrefix(g, "D"):
		return "Poor, material exposure"
	default:
		return "Critical exposure"
	}
}

// ---------------------------------------------------------------------------
//  Severity model
// ---------------------------------------------------------------------------

const (
	SevInfo     = "INFO"
	SevLow      = "LOW"
	SevMedium   = "MEDIUM"
	SevHigh     = "HIGH"
	SevCritical = "CRITICAL"
)

func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

func sevColor(s string) string {
	switch strings.ToUpper(s) {
	case SevCritical:
		return R + B
	case SevHigh:
		return R
	case SevMedium:
		return YLW
	case SevLow:
		return W
	default:
		return GY
	}
}

func scoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return SevCritical
	case score >= 7.0:
		return SevHigh
	case score >= 4.0:
		return SevMedium
	case score >= 0.1:
		return SevLow
	default:
		return SevInfo
	}
}

// sarifLevel maps severity to SARIF result levels.
func sarifLevel(s string) string {
	switch strings.ToUpper(s) {
	case SevCritical, SevHigh:
		return "error"
	case SevMedium:
		return "warning"
	case SevLow:
		return "note"
	}
	return "none"
}

// ---------------------------------------------------------------------------
//  Numeric / statistics helpers
// ---------------------------------------------------------------------------

func meanF(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func stddevF(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	m := meanF(xs)
	s := 0.0
	for _, x := range xs {
		d := x - m
		s += d * d
	}
	return math.Sqrt(s / float64(len(xs)-1))
}

func minF(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	m := xs[0]
	for _, x := range xs {
		if x < m {
			m = x
		}
	}
	return m
}

func maxF(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	m := xs[0]
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	return m
}

func percentileF(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]float64(nil), xs...)
	sort.Float64s(cp)
	idx := int(clamp(p/100.0*float64(len(cp)-1), 0, float64(len(cp)-1)) + 0.5)
	return cp[idx]
}

// shannonEntropy returns bits/byte entropy of a buffer (0..8).
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	e := 0.0
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		e -= p * math.Log2(p)
	}
	return e
}

// ---------------------------------------------------------------------------
//  Byte reader with endian-aware helpers
// ---------------------------------------------------------------------------

type byteReader struct {
	b   []byte
	pos int
	le  bool
}

func newReader(b []byte, le bool) *byteReader { return &byteReader{b: b, le: le} }

func (r *byteReader) remaining() int { return len(r.b) - r.pos }
func (r *byteReader) eof() bool      { return r.pos >= len(r.b) }

func (r *byteReader) u8() (uint8, bool) {
	if r.pos+1 > len(r.b) {
		return 0, false
	}
	v := r.b[r.pos]
	r.pos++
	return v, true
}

func (r *byteReader) u16() (uint16, bool) {
	if r.pos+2 > len(r.b) {
		return 0, false
	}
	var v uint16
	if r.le {
		v = binary.LittleEndian.Uint16(r.b[r.pos:])
	} else {
		v = binary.BigEndian.Uint16(r.b[r.pos:])
	}
	r.pos += 2
	return v, true
}

func (r *byteReader) u32() (uint32, bool) {
	if r.pos+4 > len(r.b) {
		return 0, false
	}
	var v uint32
	if r.le {
		v = binary.LittleEndian.Uint32(r.b[r.pos:])
	} else {
		v = binary.BigEndian.Uint32(r.b[r.pos:])
	}
	r.pos += 4
	return v, true
}

func (r *byteReader) u64() (uint64, bool) {
	if r.pos+8 > len(r.b) {
		return 0, false
	}
	var v uint64
	if r.le {
		v = binary.LittleEndian.Uint64(r.b[r.pos:])
	} else {
		v = binary.BigEndian.Uint64(r.b[r.pos:])
	}
	r.pos += 8
	return v, true
}

func (r *byteReader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.pos+n > len(r.b) {
		return nil, false
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v, true
}

func (r *byteReader) skip(n int) bool {
	if r.pos+n > len(r.b) || n < 0 {
		return false
	}
	r.pos += n
	return true
}

func (r *byteReader) align(n int) {
	if n <= 1 {
		return
	}
	if m := r.pos % n; m != 0 {
		r.pos += n - m
	}
}

// ============================================================================
//  Hex dump loader — tolerant of xxd / tcpdump / wireshark / raw hex layouts
// ============================================================================

// parseHexDump extracts raw bytes from assorted textual hex representations.
// It strips offsets (leading "0000  "), ASCII side panes, 0x prefixes, commas
// and whitespace, then decodes the remaining hex nibbles.
func parseHexDump(s string) ([]byte, error) {
	var out []byte
	lines := strings.Split(s, "\n")
	for _, ln := range lines {
		ln = strings.TrimRight(ln, "\r")
		if t := strings.TrimSpace(ln); t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
			continue
		}
		// Drop a trailing ASCII pane after 2+ spaces or a '|' guard.
		if i := strings.Index(ln, "  |"); i >= 0 {
			ln = ln[:i]
		}
		fields := strings.Fields(ln)
		// Heuristic: if first field looks like an offset (hex, len>=4, no more
		// hex pairs resembling it), drop it.
		if len(fields) > 1 && looksLikeOffset(fields[0]) {
			fields = fields[1:]
		}
		for _, f := range fields {
			f = strings.TrimPrefix(f, "0x")
			f = strings.TrimPrefix(f, "0X")
			f = strings.TrimSuffix(f, ",")
			f = strings.TrimSuffix(f, ":")
			f = strings.TrimSuffix(f, "h")
			if f == "" {
				continue
			}
			// a chunk may be a run of nibbles with colons (aa:bb:cc)
			f = strings.ReplaceAll(f, ":", "")
			f = strings.ReplaceAll(f, "-", "")
			if !isHexRun(f) {
				continue
			}
			if len(f)%2 == 1 {
				// odd nibble count — ignore trailing nibble gracefully
				f = f[:len(f)-1]
			}
			d, err := hex.DecodeString(f)
			if err != nil {
				continue
			}
			out = append(out, d...)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no hex bytes recovered from input")
	}
	return out, nil
}

func looksLikeOffset(s string) bool {
	s = strings.TrimSuffix(s, ":")
	if len(s) < 4 {
		return false
	}
	return isHexRun(s)
}

func isHexRun(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func hexPreview(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return hex.EncodeToString(b)
}

// hexDumpBlock returns a classic offset | hex | ascii dump for display.
func hexDumpBlock(b []byte, maxBytes int) string {
	if len(b) > maxBytes {
		b = b[:maxBytes]
	}
	var sb strings.Builder
	for off := 0; off < len(b); off += 16 {
		end := off + 16
		if end > len(b) {
			end = len(b)
		}
		fmt.Fprintf(&sb, "  %04x  ", off)
		for i := off; i < off+16; i++ {
			if i < end {
				fmt.Fprintf(&sb, "%02x ", b[i])
			} else {
				sb.WriteString("   ")
			}
			if i-off == 7 {
				sb.WriteString(" ")
			}
		}
		sb.WriteString(" ")
		for i := off; i < end; i++ {
			c := b[i]
			if c >= 32 && c < 127 {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// ============================================================================
//  MAC address utilities
// ============================================================================

func macStr(b []byte) string {
	if len(b) < 6 {
		return "00:00:00:00:00:00"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func parseMAC(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", ":")
	s = strings.ReplaceAll(s, ".", ":")
	parts := strings.Split(s, ":")
	if len(parts) == 1 && len(s) == 12 {
		// bare 12-nibble form
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 6 {
			return nil, errors.New("invalid MAC")
		}
		return b, nil
	}
	if len(parts) != 6 {
		return nil, errors.New("invalid MAC format")
	}
	out := make([]byte, 6)
	for i, p := range parts {
		if len(p) == 1 {
			p = "0" + p
		}
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(v)
	}
	return out, nil
}

// macIsBroadcast reports an all-FF address.
func macIsBroadcast(b []byte) bool {
	if len(b) < 6 {
		return false
	}
	for _, c := range b[:6] {
		if c != 0xff {
			return false
		}
	}
	return true
}

func macIsMulticast(b []byte) bool {
	return len(b) >= 1 && b[0]&0x01 == 0x01
}

// macIsLocallyAdministered detects the U/L bit → randomized / software MAC.
func macIsLocallyAdministered(b []byte) bool {
	return len(b) >= 1 && b[0]&0x02 == 0x02
}

// macRandomizationClass classifies a MAC's address type.
func macRandomizationClass(b []byte) string {
	if len(b) < 6 {
		return "invalid"
	}
	if macIsBroadcast(b) {
		return "broadcast"
	}
	if macIsMulticast(b) {
		return "multicast"
	}
	if macIsLocallyAdministered(b) {
		// Second nibble 2,6,A,E indicate randomized device identifiers.
		switch b[0] & 0x0f {
		case 0x02, 0x06, 0x0a, 0x0e:
			return "randomized"
		}
		return "locally-administered"
	}
	return "global-OUI"
}

func ouiKey(b []byte) string {
	if len(b) < 3 {
		return "000000"
	}
	return fmt.Sprintf("%02X%02X%02X", b[0], b[1], b[2])
}

// lookupVendor resolves the OUI (first 3 bytes) to a vendor name.
func lookupVendor(b []byte) string {
	if len(b) < 3 {
		return "Unknown"
	}
	if macIsBroadcast(b) {
		return "Broadcast"
	}
	if macRandomizationClass(b) == "randomized" {
		return "Randomized/Private"
	}
	if v, ok := ouiDB[ouiKey(b)]; ok {
		return v
	}
	return "Unknown"
}

// ouiDB — curated IEEE OUI → vendor prefixes commonly seen in wireless gear.
var ouiDB = map[string]string{
	"000C43": "Ralink", "001018": "Broadcom", "00037F": "Atheros",
	"000D93": "Apple", "001451": "Apple", "0017F2": "Apple",
	"001B63": "Apple", "0021E9": "Apple", "002332": "Apple",
	"3C0754": "Apple", "A4C361": "Apple", "F0DBF8": "Apple",
	"DC2B2A": "Apple", "88665A": "Apple", "A85C2C": "Apple",
	"001A11": "Google", "3C5AB4": "Google", "F4F5E8": "Google",
	"DA A1 19": "Google", "D4F547": "Google", "001FF3": "Apple",
	"F8E079": "Samsung", "5C0A5B": "Samsung", "B479A7": "Samsung",
	"0012FB": "Samsung", "002567": "Samsung", "386077": "Samsung",
	"001D0F": "TP-Link", "14CC20": "TP-Link", "50C7BF": "TP-Link",
	"A42BB0": "TP-Link", "C46E1F": "TP-Link", "EC086B": "TP-Link",
	"001A2B": "Cisco", "00400B": "Cisco", "0024C4": "Cisco",
	"58971E": "Cisco", "6400F1": "Cisco", "00059A": "Cisco",
	"0018F3": "ASUSTek", "001BFC": "ASUSTek", "2C56DC": "ASUSTek",
	"50465D": "ASUSTek", "AC220B": "ASUSTek", "D850E6": "ASUSTek",
	"001195": "D-Link", "00265A": "D-Link", "1CBDB9": "D-Link",
	"002401": "D-Link", "C8BE19": "D-Link", "B8A386": "D-Link",
	"000FB5": "Netgear", "00223F": "Netgear", "100D7F": "Netgear",
	"20E52A": "Netgear", "A040A0": "Netgear", "9C3DCF": "Netgear",
	"001601": "Buffalo", "00247E": "Ubiquiti", "0418D6": "Ubiquiti",
	"24A43C": "Ubiquiti", "68D79A": "Ubiquiti", "802AA8": "Ubiquiti",
	"FCECDA": "Ubiquiti", "74ACB9": "Ubiquiti", "B4FBE4": "Ubiquiti",
	"001346": "DLink", "0090A9": "Western Digital", "001C10": "Cisco-Linksys",
	"002369": "Cisco-Linksys", "C0C1C0": "Cisco-Linksys", "48F8B3": "Cisco-Linksys",
	"000625": "Linksys", "001217": "Cisco-Linksys", "0020A6": "Proxim",
	"001CDF": "Belkin", "08863B": "Belkin", "94103E": "Belkin",
	"B4750E": "Belkin", "001501": "Zyxel", "5C6A80": "Zyxel",
	"0013492": "Zyxel", "001349": "Zyxel", "FC3497": "Zyxel",
	"000393": "Apple", "0003AA": "Watlow", "009069": "Juniper",
	"2C6BF5": "Juniper", "3CE5A6": "Hangzhou", "0018E7": "Cameo",
	"001E58": "WistronNe", "001CF0": "D-Link", "001E2A": "Netgear",
	"00037A": "Taiyo", "001E8C": "ASUSTek", "0024B2": "Netgear",
	"0026F2": "Netgear", "E0469A": "Netgear", "C03F0E": "Netgear",
	"00904C": "Epigram", "ACF7F3": "Xiaomi", "286C07": "Xiaomi",
	"640980": "Xiaomi", "F8A45F": "Xiaomi", "742344": "Xiaomi",
	"4CB16C": "Huawei", "002568": "Huawei", "48435A": "Huawei",
	"5CA86A": "Huawei", "80B686": "Huawei", "E8CD2D": "Huawei",
	"001986": "Intel", "001F3B": "Intel", "0024D7": "Intel",
	"7C7A91": "Intel", "A0A8CD": "Intel", "E4A471": "Intel",
	"34E6D7": "Intel", "9CB6D0": "Intel", "5CE0C5": "Intel",
	"001DE1": "Intel", "00037B": "Dlink", "001B2F": "Netgear",
	"002275": "Belkin", "08BD43": "Netgear", "0C8268": "TP-Link",
	"3872C0": "CloudNet", "00156D": "Ubiquiti", "DC9FDB": "Ubiquiti",
	"44D9E7": "Ubiquiti", "788A20": "Ubiquiti", "F09FC2": "Ubiquiti",
	"0CB2B7": "Sonos", "5CAAFD": "Sonos", "949F3E": "Sonos",
	"B8E937": "Sonos", "347E5C": "Sonos", "F0F6C1": "Sonos",
	"001124": "Apple", "002608": "Apple", "0026BB": "Apple",
	"28CFE9": "Apple", "7CD1C3": "Apple", "9027E4": "Apple",
	"C82A14": "Apple", "E0ACCB": "Apple", "F0989D": "Apple",
	"40B395": "Apple", "6C4008": "Apple", "8866A5": "Apple",
}

// ============================================================================
//  CSV + file helpers
// ============================================================================

func readFileString(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func readFileBytes(path string) ([]byte, error) { return os.ReadFile(path) }

func readCSVRecords(path string) ([][]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	return r.ReadAll()
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func atoiSafe(s string) int {
	s = strings.TrimSpace(s)
	v, _ := strconv.Atoi(s)
	return v
}

func atofSafe(s string) float64 {
	s = strings.TrimSpace(s)
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// ============================================================================
//  PCAP / PCAPNG reader (classic libpcap + minimal pcapng EPB)
// ============================================================================

// Link-layer header types we care about.
const (
	DLT_NULL        = 0
	DLT_EN10MB      = 1
	DLT_IEEE802_11  = 105
	DLT_RADIOTAP    = 127
	DLT_PPI         = 192
	DLT_BLUETOOTH   = 201 // BLUETOOTH_HCI_H4_WITH_PHDR
	DLT_BLE_LL      = 251 // BLUETOOTH_LE_LL
	DLT_IEEE802154  = 195 // IEEE802_15_4_WITHFCS
	DLT_IEEE802154B = 230 // IEEE802_15_4_NOFCS
	DLT_NORDIC_BLE  = 272
)

type capPacket struct {
	TsSec    uint32
	TsUsec   uint32
	OrigLen  uint32
	Data     []byte
	LinkType int
	Index    int
}

func (p capPacket) Time() time.Time {
	return time.Unix(int64(p.TsSec), int64(p.TsUsec)*1000).UTC()
}

type capFile struct {
	LinkType int
	Packets  []capPacket
	Format   string
}

// loadCapture auto-detects pcap, pcapng or raw-hex and returns parsed packets.
func loadCapture(path string) (*capFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCaptureBytes(b)
}

func parseCaptureBytes(b []byte) (*capFile, error) {
	if len(b) < 4 {
		return nil, errors.New("file too small")
	}
	magic := binary.BigEndian.Uint32(b[:4])
	switch magic {
	case 0x0a0d0d0a:
		return parsePcapng(b)
	case 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1:
		return parsePcap(b)
	}
	return nil, errors.New("unrecognized capture magic (not pcap/pcapng)")
}

func parsePcap(b []byte) (*capFile, error) {
	if len(b) < 24 {
		return nil, errors.New("short pcap global header")
	}
	magic := binary.BigEndian.Uint32(b[:4])
	var le bool
	var nano bool
	switch magic {
	case 0xa1b2c3d4:
		le = false
	case 0xd4c3b2a1:
		le = true
	case 0xa1b23c4d:
		le = false
		nano = true
	case 0x4d3cb2a1:
		le = true
		nano = true
	default:
		return nil, errors.New("bad pcap magic")
	}
	_ = nano
	ord := binary.ByteOrder(binary.BigEndian)
	if le {
		ord = binary.LittleEndian
	}
	linktype := int(ord.Uint32(b[20:24]))
	cf := &capFile{LinkType: linktype, Format: "pcap"}
	pos := 24
	idx := 0
	for pos+16 <= len(b) {
		tsSec := ord.Uint32(b[pos : pos+4])
		tsUsec := ord.Uint32(b[pos+4 : pos+8])
		caplen := ord.Uint32(b[pos+8 : pos+12])
		origlen := ord.Uint32(b[pos+12 : pos+16])
		pos += 16
		if caplen > 262144 || pos+int(caplen) > len(b) {
			break
		}
		data := make([]byte, caplen)
		copy(data, b[pos:pos+int(caplen)])
		pos += int(caplen)
		cf.Packets = append(cf.Packets, capPacket{
			TsSec: tsSec, TsUsec: tsUsec, OrigLen: origlen,
			Data: data, LinkType: linktype, Index: idx,
		})
		idx++
	}
	return cf, nil
}

func parsePcapng(b []byte) (*capFile, error) {
	cf := &capFile{Format: "pcapng"}
	pos := 0
	le := true
	linktype := DLT_EN10MB
	for pos+12 <= len(b) {
		btype := binary.LittleEndian.Uint32(b[pos : pos+4])
		blen := binary.LittleEndian.Uint32(b[pos+4 : pos+8])
		if btype == 0x0a0d0d0a {
			// SHB sets byte order via BOM
			if pos+12 <= len(b) {
				bom := binary.LittleEndian.Uint32(b[pos+8 : pos+12])
				le = bom == 0x1a2b3c4d
			}
		}
		if blen < 12 || pos+int(blen) > len(b) {
			break
		}
		ord := binary.ByteOrder(binary.LittleEndian)
		if !le {
			ord = binary.BigEndian
		}
		switch btype {
		case 0x00000001: // Interface Description Block
			if pos+10 <= len(b) {
				linktype = int(ord.Uint16(b[pos+8 : pos+10]))
				cf.LinkType = linktype
			}
		case 0x00000006: // Enhanced Packet Block
			if pos+28 <= len(b) {
				caplen := int(ord.Uint32(b[pos+20 : pos+24]))
				origlen := ord.Uint32(b[pos+24 : pos+28])
				dstart := pos + 28
				if caplen >= 0 && dstart+caplen <= len(b) && caplen < 262144 {
					data := make([]byte, caplen)
					copy(data, b[dstart:dstart+caplen])
					cf.Packets = append(cf.Packets, capPacket{
						OrigLen: origlen, Data: data,
						LinkType: linktype, Index: len(cf.Packets),
					})
				}
			}
		case 0x00000003: // Simple Packet Block
			if pos+12 <= len(b) {
				origlen := ord.Uint32(b[pos+8 : pos+12])
				dstart := pos + 12
				caplen := int(blen) - 16
				if caplen > 0 && dstart+caplen <= len(b) {
					data := make([]byte, caplen)
					copy(data, b[dstart:dstart+caplen])
					cf.Packets = append(cf.Packets, capPacket{
						OrigLen: origlen, Data: data,
						LinkType: linktype, Index: len(cf.Packets),
					})
				}
			}
		}
		pos += int(blen)
	}
	return cf, nil
}

// ============================================================================
//  Radiotap header parser (subset of the common present fields)
// ============================================================================

type radiotapInfo struct {
	Present    bool
	Length     int
	TSFT       uint64
	Flags      uint8
	Rate       float64 // Mbps
	ChannelMHz uint16
	ChanFlags  uint16
	SignalDBm  int8
	NoiseDBm   int8
	Antenna    uint8
	HasSignal  bool
	HasRate    bool
	HasChannel bool
	MCS        uint8
	HasMCS     bool
	BadFCS     bool
}

// present bit indices
const (
	rtTSFT      = 0
	rtFlags     = 1
	rtRate      = 2
	rtChannel   = 3
	rtFHSS      = 4
	rtDBmSignal = 5
	rtDBmNoise  = 6
	rtLockQual  = 7
	rtTxAtten   = 8
	rtDbTxAtten = 9
	rtDBmTxPow  = 10
	rtAntenna   = 11
	rtDBAnt     = 12
	rtDBAntNo   = 13
	rtMCS       = 19
)

func parseRadiotap(b []byte) (radiotapInfo, []byte) {
	var ri radiotapInfo
	if len(b) < 8 {
		return ri, b
	}
	// it_version(1) it_pad(1) it_len(2) it_present(4...)
	length := int(binary.LittleEndian.Uint16(b[2:4]))
	if length < 8 || length > len(b) {
		return ri, b
	}
	ri.Present = true
	ri.Length = length
	// collect present words (extended bit 31)
	var presents []uint32
	off := 4
	for {
		if off+4 > len(b) {
			break
		}
		p := binary.LittleEndian.Uint32(b[off : off+4])
		presents = append(presents, p)
		off += 4
		if p&(1<<31) == 0 {
			break
		}
	}
	r := newReader(b[:length], true)
	r.pos = off
	has := func(word, bit int) bool {
		if word >= len(presents) {
			return false
		}
		return presents[word]&(1<<uint(bit)) != 0
	}
	// Only parse first present word's common fields in order.
	if has(0, rtTSFT) {
		r.align(8)
		ri.TSFT, _ = r.u64()
	}
	if has(0, rtFlags) {
		v, _ := r.u8()
		ri.Flags = v
		if v&0x40 != 0 {
			ri.BadFCS = true
		}
	}
	if has(0, rtRate) {
		v, _ := r.u8()
		ri.Rate = float64(v) / 2.0
		ri.HasRate = true
	}
	if has(0, rtChannel) {
		r.align(2)
		f, _ := r.u16()
		fl, _ := r.u16()
		ri.ChannelMHz = f
		ri.ChanFlags = fl
		ri.HasChannel = true
	}
	if has(0, rtFHSS) {
		r.skip(2)
	}
	if has(0, rtDBmSignal) {
		v, _ := r.u8()
		ri.SignalDBm = int8(v)
		ri.HasSignal = true
	}
	if has(0, rtDBmNoise) {
		v, _ := r.u8()
		ri.NoiseDBm = int8(v)
	}
	if has(0, rtLockQual) {
		r.align(2)
		r.skip(2)
	}
	if has(0, rtTxAtten) {
		r.align(2)
		r.skip(2)
	}
	if has(0, rtDbTxAtten) {
		r.align(2)
		r.skip(2)
	}
	if has(0, rtDBmTxPow) {
		r.skip(1)
	}
	if has(0, rtAntenna) {
		v, _ := r.u8()
		ri.Antenna = v
	}
	if has(0, rtMCS) {
		if known, ok := r.u8(); ok {
			_ = known
			r.skip(1)
			if mcs, ok2 := r.u8(); ok2 {
				ri.MCS = mcs
				ri.HasMCS = true
			}
		}
	}
	// payload is everything after the radiotap header
	if length <= len(b) {
		return ri, b[length:]
	}
	return ri, b
}

// ============================================================================
//  IEEE 802.11 MAC header dissector
// ============================================================================

const (
	TypeMgmt = 0
	TypeCtrl = 1
	TypeData = 2
)

// management subtypes
const (
	MgmtAssocReq    = 0
	MgmtAssocResp   = 1
	MgmtReassocReq  = 2
	MgmtReassocResp = 3
	MgmtProbeReq    = 4
	MgmtProbeResp   = 5
	MgmtBeacon      = 8
	MgmtATIM        = 9
	MgmtDisassoc    = 10
	MgmtAuth        = 11
	MgmtDeauth      = 12
	MgmtAction      = 13
)

type dot11Frame struct {
	Version   int
	Type      int
	Subtype   int
	ToDS      bool
	FromDS    bool
	MoreFrag  bool
	Retry     bool
	PwrMgmt   bool
	MoreData  bool
	Protected bool
	Order     bool
	Duration  uint16
	Addr1     []byte // RA / DA
	Addr2     []byte // TA / SA
	Addr3     []byte // BSSID / DA / SA
	Addr4     []byte
	SeqNum    int
	FragNum   int
	QoS       uint16
	HasQoS    bool
	Body      []byte // frame body after fixed header (mgmt: starts at fixed params)
	FCSValid  bool
	Raw       []byte
}

func parseDot11(b []byte) (*dot11Frame, error) {
	if len(b) < 10 {
		return nil, errors.New("frame too short for 802.11 header")
	}
	f := &dot11Frame{Raw: b}
	fc := binary.LittleEndian.Uint16(b[0:2])
	f.Version = int(fc & 0x3)
	f.Type = int((fc >> 2) & 0x3)
	f.Subtype = int((fc >> 4) & 0xf)
	f.ToDS = fc&0x0100 != 0
	f.FromDS = fc&0x0200 != 0
	f.MoreFrag = fc&0x0400 != 0
	f.Retry = fc&0x0800 != 0
	f.PwrMgmt = fc&0x1000 != 0
	f.MoreData = fc&0x2000 != 0
	f.Protected = fc&0x4000 != 0
	f.Order = fc&0x8000 != 0
	f.Duration = binary.LittleEndian.Uint16(b[2:4])
	// addr1 always present
	if len(b) >= 10 {
		f.Addr1 = b[4:10]
	}
	off := 10
	if f.Type == TypeCtrl {
		// control frames: variable; only addr1 (and maybe addr2) present
		if len(b) >= 16 {
			f.Addr2 = b[10:16]
		}
		return f, nil
	}
	if len(b) >= 16 {
		f.Addr2 = b[10:16]
		off = 16
	}
	if len(b) >= 22 {
		f.Addr3 = b[16:22]
		off = 22
	}
	if len(b) >= 24 {
		sc := binary.LittleEndian.Uint16(b[22:24])
		f.FragNum = int(sc & 0xf)
		f.SeqNum = int(sc >> 4)
		off = 24
	}
	// 4-address data frame
	if f.Type == TypeData && f.ToDS && f.FromDS {
		if len(b) >= 30 {
			f.Addr4 = b[24:30]
			off = 30
		}
	}
	// QoS data
	if f.Type == TypeData && (f.Subtype&0x08) != 0 {
		if len(b) >= off+2 {
			f.QoS = binary.LittleEndian.Uint16(b[off : off+2])
			f.HasQoS = true
			off += 2
		}
	}
	if off <= len(b) {
		f.Body = b[off:]
	}
	return f, nil
}

func (f *dot11Frame) typeName() string {
	switch f.Type {
	case TypeMgmt:
		return "Management"
	case TypeCtrl:
		return "Control"
	case TypeData:
		return "Data"
	}
	return "Reserved"
}

func (f *dot11Frame) subtypeName() string {
	if f.Type == TypeMgmt {
		switch f.Subtype {
		case MgmtAssocReq:
			return "Assoc Request"
		case MgmtAssocResp:
			return "Assoc Response"
		case MgmtReassocReq:
			return "Reassoc Request"
		case MgmtReassocResp:
			return "Reassoc Response"
		case MgmtProbeReq:
			return "Probe Request"
		case MgmtProbeResp:
			return "Probe Response"
		case MgmtBeacon:
			return "Beacon"
		case MgmtATIM:
			return "ATIM"
		case MgmtDisassoc:
			return "Disassociation"
		case MgmtAuth:
			return "Authentication"
		case MgmtDeauth:
			return "Deauthentication"
		case MgmtAction:
			return "Action"
		}
	}
	if f.Type == TypeData {
		if f.Subtype == 0 {
			return "Data"
		}
		if f.Subtype == 4 {
			return "Null"
		}
		if f.Subtype&0x08 != 0 {
			return "QoS Data"
		}
	}
	if f.Type == TypeCtrl {
		switch f.Subtype {
		case 8:
			return "Block Ack Req"
		case 9:
			return "Block Ack"
		case 11:
			return "RTS"
		case 12:
			return "CTS"
		case 13:
			return "ACK"
		}
	}
	return fmt.Sprintf("Subtype-%d", f.Subtype)
}

// bssid returns the best-effort BSSID depending on DS bits.
func (f *dot11Frame) bssid() []byte {
	switch {
	case f.Type == TypeMgmt:
		return f.Addr3
	case !f.ToDS && !f.FromDS:
		return f.Addr3
	case f.ToDS && !f.FromDS:
		return f.Addr1
	case !f.ToDS && f.FromDS:
		return f.Addr2
	default:
		return f.Addr3
	}
}

// ============================================================================
//  Information Element (tagged parameter) parsing
// ============================================================================

type infoElement struct {
	ID   int
	Len  int
	Data []byte
}

const (
	eidSSID      = 0
	eidRates     = 1
	eidDSParam   = 3
	eidTIM       = 5
	eidCountry   = 7
	eidERP       = 42
	eidHTCap     = 45
	eidRSN       = 48
	eidExtRates  = 50
	eidHTInfo    = 61
	eidRMEnabled = 70
	eidExtCap    = 127
	eidVHTCap    = 191
	eidVHTOp     = 192
	eidVendor    = 221
	eidExtension = 255
)

// parseIEs reads tag/len/value triples from a management-frame body offset.
func parseIEs(body []byte) []infoElement {
	var ies []infoElement
	pos := 0
	for pos+2 <= len(body) {
		id := int(body[pos])
		l := int(body[pos+1])
		pos += 2
		if pos+l > len(body) {
			break
		}
		data := body[pos : pos+l]
		ies = append(ies, infoElement{ID: id, Len: l, Data: data})
		pos += l
	}
	return ies
}

func findIE(ies []infoElement, id int) *infoElement {
	for i := range ies {
		if ies[i].ID == id {
			return &ies[i]
		}
	}
	return nil
}

func ieSSID(ies []infoElement) string {
	ie := findIE(ies, eidSSID)
	if ie == nil {
		return ""
	}
	if ie.Len == 0 {
		return "<hidden>"
	}
	s := string(ie.Data)
	// hidden SSIDs can be all-zero
	allZero := true
	for _, c := range ie.Data {
		if c != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "<hidden>"
	}
	return sanitizeSSID(s)
}

func sanitizeSSID(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			sb.WriteRune(r)
		} else {
			sb.WriteString(fmt.Sprintf("\\x%02x", r))
		}
	}
	return sb.String()
}

func ieChannel(ies []infoElement) int {
	if ie := findIE(ies, eidDSParam); ie != nil && ie.Len >= 1 {
		return int(ie.Data[0])
	}
	if ie := findIE(ies, eidHTInfo); ie != nil && ie.Len >= 1 {
		return int(ie.Data[0])
	}
	return 0
}

func ieSupportedRates(ies []infoElement) []float64 {
	var rates []float64
	for _, id := range []int{eidRates, eidExtRates} {
		if ie := findIE(ies, id); ie != nil {
			for _, r := range ie.Data {
				rates = append(rates, float64(r&0x7f)/2.0)
			}
		}
	}
	return rates
}

// ============================================================================
//  RSN / WPA security parsing
// ============================================================================

type rsnInfo struct {
	Present     bool
	WPA1        bool
	WPA2        bool
	WPA3        bool
	GroupCipher string
	Pairwise    []string
	AKM         []string
	MFPCapable  bool
	MFPRequired bool
	PMKIDs      [][]byte
}

func cipherName(suite [4]byte) string {
	// OUI 00-0F-AC (RSN) / 00-50-F2 (WPA)
	t := suite[3]
	switch t {
	case 0:
		return "Use-Group"
	case 1:
		return "WEP-40"
	case 2:
		return "TKIP"
	case 4:
		return "CCMP-128"
	case 5:
		return "WEP-104"
	case 6:
		return "BIP-CMAC-128"
	case 8:
		return "GCMP-128"
	case 9:
		return "GCMP-256"
	case 10:
		return "CCMP-256"
	}
	return fmt.Sprintf("cipher-%d", t)
}

func akmName(suite [4]byte) string {
	t := suite[3]
	switch t {
	case 1:
		return "802.1X"
	case 2:
		return "PSK"
	case 3:
		return "FT-802.1X"
	case 4:
		return "FT-PSK"
	case 5:
		return "802.1X-SHA256"
	case 6:
		return "PSK-SHA256"
	case 8:
		return "SAE"
	case 9:
		return "FT-SAE"
	case 11:
		return "802.1X-SuiteB"
	case 12:
		return "802.1X-SuiteB-192"
	case 18:
		return "OWE"
	}
	return fmt.Sprintf("akm-%d", t)
}

func parseRSN(ie *infoElement) rsnInfo {
	var ri rsnInfo
	if ie == nil || ie.Len < 2 {
		return ri
	}
	ri.Present = true
	ri.WPA2 = true
	d := ie.Data
	pos := 2 // version
	readSuite := func() ([4]byte, bool) {
		var s [4]byte
		if pos+4 > len(d) {
			return s, false
		}
		copy(s[:], d[pos:pos+4])
		pos += 4
		return s, true
	}
	if g, ok := readSuite(); ok {
		ri.GroupCipher = cipherName(g)
	}
	if pos+2 <= len(d) {
		n := int(binary.LittleEndian.Uint16(d[pos : pos+2]))
		pos += 2
		for i := 0; i < n; i++ {
			if s, ok := readSuite(); ok {
				ri.Pairwise = append(ri.Pairwise, cipherName(s))
			}
		}
	}
	if pos+2 <= len(d) {
		n := int(binary.LittleEndian.Uint16(d[pos : pos+2]))
		pos += 2
		for i := 0; i < n; i++ {
			if s, ok := readSuite(); ok {
				name := akmName(s)
				ri.AKM = append(ri.AKM, name)
				if name == "SAE" || name == "FT-SAE" {
					ri.WPA3 = true
				}
			}
		}
	}
	if pos+2 <= len(d) {
		caps := binary.LittleEndian.Uint16(d[pos : pos+2])
		pos += 2
		ri.MFPRequired = caps&0x0040 != 0
		ri.MFPCapable = caps&0x0080 != 0
		// PMKID count + list
		if pos+2 <= len(d) {
			pc := int(binary.LittleEndian.Uint16(d[pos : pos+2]))
			pos += 2
			for i := 0; i < pc; i++ {
				if pos+16 <= len(d) {
					id := make([]byte, 16)
					copy(id, d[pos:pos+16])
					ri.PMKIDs = append(ri.PMKIDs, id)
					pos += 16
				}
			}
		}
	}
	return ri
}

// parseWPA1 handles the Microsoft WPA vendor IE (221, OUI 00-50-F2 type 1).
func parseWPA1(ies []infoElement) bool {
	for _, ie := range ies {
		if ie.ID == eidVendor && ie.Len >= 4 {
			if ie.Data[0] == 0x00 && ie.Data[1] == 0x50 && ie.Data[2] == 0xf2 && ie.Data[3] == 0x01 {
				return true
			}
		}
	}
	return false
}

// securityString summarises the privacy posture of a BSS.
func securityString(privacy bool, rsn rsnInfo, wpa1 bool) string {
	if rsn.WPA3 {
		if contains(rsn.AKM, "OWE") {
			return "OWE"
		}
		return "WPA3-SAE"
	}
	if rsn.Present {
		if contains(rsn.AKM, "802.1X") || contains(rsn.AKM, "802.1X-SHA256") {
			return "WPA2-Enterprise"
		}
		return "WPA2-PSK"
	}
	if wpa1 {
		return "WPA-TKIP"
	}
	if privacy {
		return "WEP"
	}
	return "OPEN"
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// ============================================================================
//  Channel / frequency maps (2.4 / 5 / 6 GHz)
// ============================================================================

func freqToChannel(mhz int) int {
	switch {
	case mhz == 2484:
		return 14
	case mhz >= 2412 && mhz <= 2472:
		return (mhz - 2407) / 5
	case mhz >= 5160 && mhz <= 5885:
		return (mhz - 5000) / 5
	case mhz >= 5955 && mhz <= 7115: // 6 GHz
		return (mhz - 5950) / 5
	}
	return 0
}

func channelToFreq(ch int) int {
	switch {
	case ch == 14:
		return 2484
	case ch >= 1 && ch <= 13:
		return 2407 + ch*5
	case ch >= 32 && ch <= 177:
		return 5000 + ch*5
	}
	return 0
}

func bandForChannel(ch int) string {
	switch {
	case ch >= 1 && ch <= 14:
		return "2.4GHz"
	case ch >= 32 && ch <= 177:
		return "5GHz"
	case ch >= 1 && ch <= 233:
		return "6GHz"
	}
	return "?"
}

func bandForFreq(mhz int) string {
	switch {
	case mhz >= 2400 && mhz < 2500:
		return "2.4GHz"
	case mhz >= 4900 && mhz < 5900:
		return "5GHz"
	case mhz >= 5925 && mhz <= 7125:
		return "6GHz"
	}
	return "?"
}

// is24NonOverlap reports whether a 2.4GHz channel is one of 1/6/11.
func is24NonOverlap(ch int) bool { return ch == 1 || ch == 6 || ch == 11 }

// dfsChannel reports whether a 5GHz channel requires DFS.
func dfsChannel(ch int) bool {
	return (ch >= 52 && ch <= 64) || (ch >= 100 && ch <= 144)
}

// signalQuality maps dBm to a 0..100 quality and label.
func signalQuality(dbm int) (int, string) {
	q := 2 * (dbm + 100)
	q = clampInt(q, 0, 100)
	label := "Unusable"
	switch {
	case dbm >= -50:
		label = "Excellent"
	case dbm >= -60:
		label = "Good"
	case dbm >= -70:
		label = "Fair"
	case dbm >= -80:
		label = "Weak"
	}
	return q, label
}

// ============================================================================
//  EAPOL / 802.1X key-frame parser
// ============================================================================

type eapolKey struct {
	Valid       bool
	Version     int
	Type        int
	KeyDescType int
	KeyInfo     uint16
	KeyLength   int
	ReplayCtr   uint64
	Nonce       []byte
	KeyIV       []byte
	KeyRSC      []byte
	MIC         []byte
	KeyDataLen  int
	KeyData     []byte
	MsgNum      int // 1..4 within 4-way handshake
	Pairwise    bool
	Install     bool
	ACK         bool
	MICSet      bool
	Secure      bool
	HasPMKID    bool
	PMKID       []byte
}

// parseEAPOL parses an EAPOL frame body (after the LLC/SNAP, starting at the
// EAPOL version byte). micLen chosen by key descriptor.
func parseEAPOL(b []byte) eapolKey {
	var k eapolKey
	if len(b) < 4 {
		return k
	}
	k.Version = int(b[0])
	k.Type = int(b[1])
	plen := int(binary.BigEndian.Uint16(b[2:4]))
	if k.Type != 3 { // 3 = EAPOL-Key
		return k
	}
	body := b[4:]
	if plen <= len(body) {
		body = body[:plen]
	}
	if len(body) < 95 {
		return k
	}
	k.Valid = true
	k.KeyDescType = int(body[0])
	k.KeyInfo = binary.BigEndian.Uint16(body[1:3])
	k.KeyLength = int(binary.BigEndian.Uint16(body[3:5]))
	k.ReplayCtr = binary.BigEndian.Uint64(body[5:13])
	k.Nonce = append([]byte(nil), body[13:45]...)
	k.KeyIV = append([]byte(nil), body[45:61]...)
	k.KeyRSC = append([]byte(nil), body[61:69]...)
	// 69:77 reserved
	k.MIC = append([]byte(nil), body[77:93]...)
	k.KeyDataLen = int(binary.BigEndian.Uint16(body[93:95]))
	if 95+k.KeyDataLen <= len(body) {
		k.KeyData = append([]byte(nil), body[95:95+k.KeyDataLen]...)
	}
	ki := k.KeyInfo
	k.Pairwise = ki&0x0008 != 0
	k.Install = ki&0x0040 != 0
	k.ACK = ki&0x0080 != 0
	k.MICSet = ki&0x0100 != 0
	k.Secure = ki&0x0200 != 0
	// classify message number of 4-way handshake
	switch {
	case k.ACK && !k.MICSet && !k.Install:
		k.MsgNum = 1
	case !k.ACK && k.MICSet && !k.Secure && !k.Install:
		k.MsgNum = 2
	case k.ACK && k.MICSet && k.Install:
		k.MsgNum = 3
	case !k.ACK && k.MICSet && k.Secure && !k.Install:
		k.MsgNum = 4
	}
	// scan key data for PMKID KDE (00-0F-AC type 4)
	k.PMKID, k.HasPMKID = extractPMKID(k.KeyData)
	return k
}

func extractPMKID(kd []byte) ([]byte, bool) {
	pos := 0
	for pos+2 <= len(kd) {
		if kd[pos] != 0xdd {
			// not a KDE; bail (RSN KDE uses 0xdd type)
			break
		}
		l := int(kd[pos+1])
		if pos+2+l > len(kd) {
			break
		}
		kde := kd[pos+2 : pos+2+l]
		if len(kde) >= 4 && kde[0] == 0x00 && kde[1] == 0x0f && kde[2] == 0xac && kde[3] == 0x04 {
			if len(kde) >= 20 {
				return append([]byte(nil), kde[4:20]...), true
			}
		}
		pos += 2 + l
	}
	return nil, false
}

// findEAPOLInPayload locates an EAPOL payload within a data frame body by
// scanning for the 888E ethertype after LLC/SNAP (AA AA 03 00 00 00 88 8E).
func findEAPOLInPayload(body []byte) []byte {
	snap := []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e}
	if idx := bytes.Index(body, snap); idx >= 0 {
		return body[idx+8:]
	}
	// try raw 888E
	e := []byte{0x88, 0x8e}
	if idx := bytes.Index(body, e); idx >= 0 && idx+2 < len(body) {
		return body[idx+2:]
	}
	return nil
}

// ============================================================================
//  Findings + Report model and 5-format export engine
// ============================================================================

type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Score       float64  `json:"score"`
	Entity      string   `json:"entity"`
	Detail      string   `json:"detail"`
	Remediation string   `json:"remediation"`
	MITRE       []string `json:"mitre,omitempty"`
}

type Report struct {
	Tool      string            `json:"tool"`
	Version   string            `json:"version"`
	Target    string            `json:"target"`
	Generated string            `json:"generated"`
	Grade     string            `json:"grade"`
	Score     float64           `json:"score"`
	Summary   map[string]string `json:"summary"`
	Findings  []Finding         `json:"findings"`
	TextBody  string            `json:"-"`
}

func newReport(target string) *Report {
	return &Report{
		Tool:      APPNAME,
		Version:   VERSION,
		Target:    target,
		Generated: time.Now().UTC().Format(time.RFC3339),
		Summary:   map[string]string{},
	}
}

func (rep *Report) add(f Finding) {
	if f.Severity == "" {
		f.Severity = scoreToSeverity(f.Score)
	}
	rep.Findings = append(rep.Findings, f)
}

func (rep *Report) sortFindings() {
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		ri, rj := sevRank(rep.Findings[i].Severity), sevRank(rep.Findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return rep.Findings[i].Score > rep.Findings[j].Score
	})
}

func (rep *Report) countBySeverity() map[string]int {
	m := map[string]int{}
	for _, f := range rep.Findings {
		m[strings.ToUpper(f.Severity)]++
	}
	return m
}

// computeGrade derives a posture grade from finding severities.
func (rep *Report) computeGrade() {
	penalty := 0.0
	for _, f := range rep.Findings {
		switch strings.ToUpper(f.Severity) {
		case SevCritical:
			penalty += 22
		case SevHigh:
			penalty += 12
		case SevMedium:
			penalty += 6
		case SevLow:
			penalty += 2
		}
	}
	score := clamp(100-penalty, 0, 100)
	rep.Score = score
	rep.Grade = gradeFromScore(score)
}

func summaryKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// ---------------------------------------------------------------------------
//  Export: TXT
// ---------------------------------------------------------------------------

func exportTXT(rep *Report) string {
	var sb strings.Builder
	w := 72
	sb.WriteString(hr(w) + "\n")
	sb.WriteString(fmt.Sprintf("%s  —  %s\n", APPNAME, TAGLINE))
	sb.WriteString("Author: khaled.s.haddad    Website: owlsec.org\n")
	sb.WriteString(hr(w) + "\n")
	sb.WriteString(fmt.Sprintf("Target     : %s\n", rep.Target))
	sb.WriteString(fmt.Sprintf("Generated  : %s\n", rep.Generated))
	sb.WriteString(fmt.Sprintf("Version    : %s\n", rep.Version))
	sb.WriteString(fmt.Sprintf("Posture    : %s  (score %.1f/100 — %s)\n", rep.Grade, rep.Score, gradeLabel(rep.Grade)))
	sb.WriteString(hr(w) + "\n\n")
	if len(rep.Summary) > 0 {
		sb.WriteString("SUMMARY\n")
		for _, k := range summaryKeys(rep.Summary) {
			sb.WriteString(fmt.Sprintf("  %-24s %s\n", k+":", rep.Summary[k]))
		}
		sb.WriteString("\n")
	}
	if rep.TextBody != "" {
		sb.WriteString(rep.TextBody)
		sb.WriteString("\n")
	}
	counts := rep.countBySeverity()
	sb.WriteString(fmt.Sprintf("FINDINGS (%d)  [C:%d H:%d M:%d L:%d I:%d]\n",
		len(rep.Findings), counts[SevCritical], counts[SevHigh],
		counts[SevMedium], counts[SevLow], counts[SevInfo]))
	sb.WriteString(hr(w) + "\n")
	for i, f := range rep.Findings {
		sb.WriteString(fmt.Sprintf("[%d] (%s) %s\n", i+1, f.Severity, f.Title))
		if f.Entity != "" {
			sb.WriteString(fmt.Sprintf("    Entity : %s\n", f.Entity))
		}
		if f.Detail != "" {
			sb.WriteString(fmt.Sprintf("    Detail : %s\n", f.Detail))
		}
		if len(f.MITRE) > 0 {
			sb.WriteString(fmt.Sprintf("    MITRE  : %s\n", strings.Join(f.MITRE, ", ")))
		}
		if f.Remediation != "" {
			sb.WriteString(fmt.Sprintf("    Fix    : %s\n", f.Remediation))
		}
		sb.WriteString("\n")
	}
	sb.WriteString(hr(w) + "\n")
	sb.WriteString("Authorized testing only. Generated by " + APPNAME + " v" + VERSION + ".\n")
	return sb.String()
}

// ---------------------------------------------------------------------------
//  Export: Markdown
// ---------------------------------------------------------------------------

func exportMD(rep *Report) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# %s — Report\n\n", APPNAME))
	sb.WriteString(fmt.Sprintf("*%s*\n\n", TAGLINE))
	sb.WriteString(fmt.Sprintf("- **Target:** %s\n", rep.Target))
	sb.WriteString(fmt.Sprintf("- **Generated:** %s\n", rep.Generated))
	sb.WriteString(fmt.Sprintf("- **Version:** %s\n", rep.Version))
	sb.WriteString(fmt.Sprintf("- **Posture:** `%s` (score %.1f/100 — %s)\n\n", rep.Grade, rep.Score, gradeLabel(rep.Grade)))
	if len(rep.Summary) > 0 {
		sb.WriteString("## Summary\n\n")
		sb.WriteString("| Metric | Value |\n|---|---|\n")
		for _, k := range summaryKeys(rep.Summary) {
			sb.WriteString(fmt.Sprintf("| %s | %s |\n", k, rep.Summary[k]))
		}
		sb.WriteString("\n")
	}
	if rep.TextBody != "" {
		sb.WriteString("## Details\n\n```\n")
		sb.WriteString(rep.TextBody)
		sb.WriteString("\n```\n\n")
	}
	sb.WriteString(fmt.Sprintf("## Findings (%d)\n\n", len(rep.Findings)))
	sb.WriteString("| # | Severity | Title | Entity | MITRE |\n|---|---|---|---|---|\n")
	for i, f := range rep.Findings {
		sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s |\n",
			i+1, f.Severity, mdEsc(f.Title), mdEsc(f.Entity), strings.Join(f.MITRE, " ")))
	}
	sb.WriteString("\n")
	for i, f := range rep.Findings {
		sb.WriteString(fmt.Sprintf("### %d. %s (%s)\n\n", i+1, f.Title, f.Severity))
		if f.Entity != "" {
			sb.WriteString(fmt.Sprintf("- **Entity:** %s\n", f.Entity))
		}
		if f.Detail != "" {
			sb.WriteString(fmt.Sprintf("- **Detail:** %s\n", f.Detail))
		}
		if f.Remediation != "" {
			sb.WriteString(fmt.Sprintf("- **Remediation:** %s\n", f.Remediation))
		}
		if len(f.MITRE) > 0 {
			sb.WriteString(fmt.Sprintf("- **MITRE ATT&CK:** %s\n", strings.Join(f.MITRE, ", ")))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n---\n*Authorized testing only. " + APPNAME + " v" + VERSION + " — owlsec.org*\n")
	return sb.String()
}

func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// ---------------------------------------------------------------------------
//  Export: JSON
// ---------------------------------------------------------------------------

func exportJSON(rep *Report) string {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ---------------------------------------------------------------------------
//  Export: CSV
// ---------------------------------------------------------------------------

func exportCSV(rep *Report) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"index", "severity", "score", "title", "entity", "detail", "mitre", "remediation"})
	for i, f := range rep.Findings {
		w.Write([]string{
			strconv.Itoa(i + 1),
			f.Severity,
			fmt.Sprintf("%.1f", f.Score),
			f.Title,
			f.Entity,
			f.Detail,
			strings.Join(f.MITRE, " "),
			f.Remediation,
		})
	}
	w.Flush()
	return buf.String()
}

// ---------------------------------------------------------------------------
//  Export: SARIF 2.1.0
// ---------------------------------------------------------------------------

func exportSARIF(rep *Report) string {
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type sarifProps struct {
		Severity string   `json:"severity,omitempty"`
		Score    float64  `json:"score,omitempty"`
		MITRE    []string `json:"mitre,omitempty"`
		Entity   string   `json:"entity,omitempty"`
	}
	type sarifRule struct {
		ID               string     `json:"id"`
		Name             string     `json:"name"`
		ShortDescription sarifMsg   `json:"shortDescription"`
		FullDescription  sarifMsg   `json:"fullDescription"`
		HelpURI          string     `json:"helpUri,omitempty"`
		Properties       sarifProps `json:"properties"`
	}
	type sarifArtifactLoc struct {
		URI string `json:"uri"`
	}
	type sarifRegion struct {
		StartLine int `json:"startLine"`
	}
	type sarifPhysLoc struct {
		ArtifactLocation sarifArtifactLoc `json:"artifactLocation"`
		Region           sarifRegion      `json:"region"`
	}
	type sarifLoc struct {
		PhysicalLocation sarifPhysLoc `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID     string     `json:"ruleId"`
		Level      string     `json:"level"`
		Message    sarifMsg   `json:"message"`
		Locations  []sarifLoc `json:"locations"`
		Properties sarifProps `json:"properties"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifToolBlock struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifToolBlock `json:"tool"`
		Results []sarifResult  `json:"results"`
	}
	type sarifDoc struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	ruleIdx := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult
	for i, f := range rep.Findings {
		rid := f.ID
		if rid == "" {
			rid = fmt.Sprintf("%s-RULE-%d", APPNAME, i+1)
		}
		if !ruleIdx[rid] {
			ruleIdx[rid] = true
			rules = append(rules, sarifRule{
				ID:               rid,
				Name:             f.Title,
				ShortDescription: sarifMsg{Text: f.Title},
				FullDescription:  sarifMsg{Text: f.Detail},
				HelpURI:          "https://owlsec.org",
				Properties:       sarifProps{Severity: f.Severity, Score: f.Score, MITRE: f.MITRE},
			})
		}
		entity := f.Entity
		if entity == "" {
			entity = rep.Target
		}
		results = append(results, sarifResult{
			RuleID:  rid,
			Level:   sarifLevel(f.Severity),
			Message: sarifMsg{Text: f.Detail},
			Locations: []sarifLoc{{PhysicalLocation: sarifPhysLoc{
				ArtifactLocation: sarifArtifactLoc{URI: entity},
				Region:           sarifRegion{StartLine: 1},
			}}},
			Properties: sarifProps{Severity: f.Severity, Score: f.Score, MITRE: f.MITRE, Entity: f.Entity},
		})
	}
	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifToolBlock{Driver: sarifDriver{
				Name:           APPNAME,
				Version:        VERSION,
				InformationURI: "https://owlsec.org",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

// renderReport returns the report in the requested format.
func renderReport(rep *Report, format string) (string, error) {
	switch strings.ToLower(format) {
	case "txt", "text", "":
		return exportTXT(rep), nil
	case "md", "markdown":
		return exportMD(rep), nil
	case "json":
		return exportJSON(rep), nil
	case "csv":
		return exportCSV(rep), nil
	case "sarif":
		return exportSARIF(rep), nil
	}
	return "", fmt.Errorf("unknown format %q (use txt|md|json|csv|sarif)", format)
}

// writeReport emits to stdout or a file.
func writeReport(rep *Report, format, outPath string) error {
	out, err := renderReport(rep, format)
	if err != nil {
		return err
	}
	if outPath == "" {
		fmt.Print(out)
		if !strings.HasSuffix(out, "\n") {
			fmt.Println()
		}
		return nil
	}
	if err := os.WriteFile(outPath, []byte(out), 0644); err != nil {
		return err
	}
	abs, _ := filepath.Abs(outPath)
	okMsg("Report written: " + abs + " (" + format + ")")
	return nil
}

// ============================================================================
//  HOW TO USE renderer (mandatory help view) + CLI plumbing
// ============================================================================

type howSection struct {
	Title string
	Lines []string
}

// renderHowto prints the full HOW TO USE screen with the cyan UI.
func renderHowto(secs []howSection) {
	clear()
	banner()
	for _, s := range secs {
		sectionHeader(s.Title)
		for _, ln := range s.Lines {
			if strings.HasPrefix(ln, "#") {
				fmt.Println("  " + col(strings.TrimPrefix(ln, "#"), YLW+B))
			} else if strings.HasPrefix(ln, "- ") {
				bullet(strings.TrimPrefix(ln, "- "))
			} else if ln == "" {
				fmt.Println()
			} else {
				fmt.Println("  " + col(ln, W))
			}
		}
	}
	fmt.Println()
	line(64)
	fmt.Println("  " + col("Authorized testing only — written permission required.", OR+B))
}

// legalWarningLines is the standard LEGAL & ETHICAL WARNING block shared by all
// tools (each tool appends protocol-specific notes).
func legalWarningLines() []string {
	return []string{
		"This tool is for AUTHORIZED security testing and education ONLY.",
		"",
		"- Use ONLY on networks, devices and spectrum you own or have",
		"  EXPLICIT WRITTEN PERMISSION to assess.",
		"- Interception, jamming, deauthentication or spoofing of radio",
		"  networks without authorization is ILLEGAL in most jurisdictions",
		"  (e.g. CFAA, Computer Misuse Act, Wireless Telegraphy Act, RF",
		"  regulatory law) and may carry criminal penalties.",
		"- This build operates OFFLINE on capture/log files you supply; it",
		"  does not transmit, inject, or control any radio hardware.",
		"- You are solely responsible for lawful, ethical use. The author",
		"  (khaled.s.haddad) and owlsec.org accept NO liability for misuse.",
	}
}

func navigationLines(items []string) []string {
	out := []string{"Use the number keys shown in the main menu:"}
	out = append(out, "")
	for i, it := range items {
		out = append(out, fmt.Sprintf("- [%02d] %s", i+1, it))
	}
	out = append(out, "- [00] Exit the program")
	out = append(out, "")
	out = append(out, "Press Enter at any [↩] prompt to return to the menu.")
	return out
}

// ---------------------------------------------------------------------------
//  CLI helpers
// ---------------------------------------------------------------------------

func printVersion() {
	fmt.Printf("%s v%s\n", APPNAME, VERSION)
	fmt.Println("Author : khaled.s.haddad")
	fmt.Println("Website: owlsec.org")
	fmt.Println("Build  : Go stdlib, static (CGO disabled), OWL Batch 3 (Wireless)")
}

// severitySummaryLine renders a compact finding tally.
func severitySummaryLine(rep *Report) string {
	c := rep.countBySeverity()
	return fmt.Sprintf("Critical:%d High:%d Medium:%d Low:%d Info:%d",
		c[SevCritical], c[SevHigh], c[SevMedium], c[SevLow], c[SevInfo])
}

// printFindingsTable renders findings to the interactive TUI.
func printFindingsTable(rep *Report) {
	if len(rep.Findings) == 0 {
		info("No findings for this run.")
		return
	}
	rows := [][]string{}
	for i, f := range rep.Findings {
		rows = append(rows, []string{
			strconv.Itoa(i + 1),
			f.Severity,
			truncStr(f.Title, 34),
			truncStr(f.Entity, 20),
			strings.Join(f.MITRE, " "),
		})
	}
	table([]string{"#", "SEVERITY", "FINDING", "ENTITY", "MITRE"}, rows)
}

// gradeBanner prints the posture grade with color.
func gradeBanner(rep *Report) {
	rep.computeGrade()
	g := rep.Grade
	fmt.Println()
	fmt.Println("  " + col(" POSTURE GRADE ", gradeColor(g)+"\033[7m") + "  " +
		col(g, gradeColor(g)) + col(fmt.Sprintf("   score %.1f/100 — %s", rep.Score, gradeLabel(g)), GY))
}

// writeOrShow writes the report (file or stdout) and reports status in the TUI.
func writeOrShow(rep *Report, format, out string) {
	if err := writeReport(rep, format, out); err != nil {
		errMsg(err.Error())
	}
}

// chooseFormat validates a format string.
func chooseFormat(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "txt", "md", "json", "csv", "sarif":
		return s
	}
	return "txt"
}

// parseIntList parses "1,2,3" or "1-11" style lists.
func parseIntList(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			r := strings.SplitN(part, "-", 2)
			a := atoiSafe(r[0])
			b := atoiSafe(r[1])
			if a <= b {
				for i := a; i <= b; i++ {
					out = append(out, i)
				}
			}
		} else {
			out = append(out, atoiSafe(part))
		}
	}
	return out
}

// nowStamp is a filesystem-friendly timestamp.
func nowStamp() string { return time.Now().Format("20060102-150405") }

// defaultOutName builds an export filename when the user omits one.
func defaultOutName(kind, format string) string {
	ext := format
	if format == "md" {
		ext = "md"
	}
	return fmt.Sprintf("%s-%s-%s.%s", strings.ToLower(APPNAME), kind, nowStamp(), ext)
}

// ensure helpers are considered used even by lean tools.
var _ = errors.New
var _ = math.Sqrt
var _ = hex.EncodeToString
var _ = sort.Ints
var _ = filepath.Base
var _ = bufio.NewReader

// ============================================================================
//  Tool contract hooks + unified main/CLI/interactive engine
// ============================================================================

// Each tool wires these in its init(). The engine below is identical across the
// batch; the domain depth lives in each tool's hook implementations.
var (
	hookHowto         func() []howSection
	hookDemo          func() *Report
	hookAnalyze       func(path string) (*Report, error)
	hookActions       func() []menuAction
	hookRegisterFlags func(*flag.FlagSet)
	hookUsageExtra    func()
)

type menuAction struct {
	label string
	desc  string
	run   func()
}

// lastReport is the most recent analysis result, shared across menu actions.
var lastReport *Report

// common CLI flags
var (
	flagInput   string
	flagFormat  string
	flagOutput  string
	flagNoColor bool
)

func printUsage() {
	if !noColor {
		banner()
	} else {
		fmt.Printf("%s — %s\n", APPNAME, TAGLINE)
		fmt.Println("Author: khaled.s.haddad | owlsec.org")
	}
	fmt.Println()
	fmt.Println(col("USAGE", CY+B))
	fmt.Printf("  %s [flags]\n", APPNAME)
	fmt.Printf("  %s                 # launch interactive TUI\n", APPNAME)
	fmt.Printf("  %s --input FILE    # analyze a capture/log and print a report\n", APPNAME)
	fmt.Printf("  %s --demo          # run a self-contained synthetic demo\n", APPNAME)
	fmt.Println()
	fmt.Println(col("CORE FLAGS", CY+B))
	fmt.Println("  -h, --help            Show this help")
	fmt.Println("      --version         Show version information")
	fmt.Println("      --howto           Show the HOW TO USE screen (legal, steps, nav)")
	fmt.Println("      --demo            Run a synthetic, self-contained demonstration")
	fmt.Println("      --input FILE      Input capture/log file (alias: --pcap)")
	fmt.Println("      --format FMT      Output format: txt|md|json|csv|sarif (default txt)")
	fmt.Println("      --output FILE     Write report to FILE instead of stdout")
	fmt.Println("      --no-color        Disable ANSI colors")
	if hookUsageExtra != nil {
		fmt.Println()
		fmt.Println(col("TOOL FLAGS", CY+B))
		hookUsageExtra()
	}
	fmt.Println()
	fmt.Println(col("CATEGORY", CY+B) + "  " + CATEGORY)
	fmt.Println(col("MITRE   ", CY+B) + "  " + MITRE)
	fmt.Println()
	fmt.Println(col("EXAMPLES", CY+B))
	fmt.Println("  " + APPNAME + " --input handshake.pcapng")
	fmt.Println("  " + APPNAME + " --input wifi.pcap --format json --output hs.json")
	fmt.Println("  " + APPNAME + " --input wifi.pcap --format sarif --output hs.sarif")
	fmt.Println("  " + APPNAME + " --demo --format md")
	fmt.Println()
	fmt.Println(col("Authorized testing only. No warranty. See --howto for legal terms.", DIM))
}

func main() {
	fs := flag.NewFlagSet(APPNAME, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var showHelp, showHelpS, showVer, showHowto, demo, self bool
	fs.BoolVar(&showHelp, "help", false, "show help")
	fs.BoolVar(&showHelpS, "h", false, "show help")
	fs.BoolVar(&showVer, "version", false, "show version")
	fs.BoolVar(&showHowto, "howto", false, "show HOW TO USE")
	fs.BoolVar(&demo, "demo", false, "run synthetic demo")
	fs.BoolVar(&self, "selftest", false, "run internal self-tests")
	fs.StringVar(&flagInput, "input", "", "input capture/log file")
	fs.StringVar(&flagInput, "pcap", "", "input capture file (alias of --input)")
	fs.StringVar(&flagFormat, "format", "txt", "txt|md|json|csv|sarif")
	fs.StringVar(&flagOutput, "output", "", "write report to file")
	fs.BoolVar(&flagNoColor, "no-color", false, "disable colors")
	if hookRegisterFlags != nil {
		hookRegisterFlags(fs)
	}
	fs.Usage = printUsage
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			printUsage()
			return
		}
		errMsg(err.Error())
		os.Exit(2)
	}
	if flagNoColor {
		noColor = true
	}
	flagFormat = chooseFormat(flagFormat)

	switch {
	case self:
		os.Exit(runSelfTest())
	case showHelp || showHelpS:
		printUsage()
		return
	case showVer:
		printVersion()
		return
	case showHowto:
		renderHowto(hookHowto())
		return
	case demo:
		rep := hookDemo()
		rep.computeGrade()
		rep.sortFindings()
		lastReport = rep
		if flagOutput == "" && flagFormat == "txt" {
			fmt.Println(col(APPNAME+" — synthetic demo run", CY+B))
		}
		writeOrShow(rep, flagFormat, flagOutput)
		return
	case flagInput != "":
		rep, err := hookAnalyze(flagInput)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		rep.computeGrade()
		rep.sortFindings()
		lastReport = rep
		writeOrShow(rep, flagFormat, flagOutput)
		return
	}

	// No actionable flags → interactive TUI.
	if len(os.Args) == 1 {
		standardInteractive()
		return
	}
	// Flags given but nothing to do.
	printUsage()
}

// standardInteractive drives the menu-based cyan TUI loop.
func standardInteractive() {
	for {
		acts := hookActions()
		sel := strings.TrimSpace(menu(TAGLINE, acts))
		if sel == "00" || sel == "0" || strings.EqualFold(sel, "q") || strings.EqualFold(sel, "exit") {
			clear()
			banner()
			okMsg("Session closed. Authorized testing only — stay ethical.")
			return
		}
		if strings.EqualFold(sel, "h") || strings.EqualFold(sel, "help") || sel == "?" {
			tuiHelp()
			continue
		}
		n, err := strconv.Atoi(sel)
		if err != nil {
			continue
		}
		if n >= 1 && n <= len(acts) {
			clear()
			banner()
			acts[n-1].run()
			pause()
			continue
		}
	}
}

// ---------------------------------------------------------------------------
//  Interactive helpers shared by tools
// ---------------------------------------------------------------------------

// promptExistingPath asks for a file path and validates it exists.
func promptExistingPath(label string) (string, bool) {
	p := prompt(label)
	p = strings.TrimSpace(p)
	if p == "" {
		warnMsg("No path entered.")
		return "", false
	}
	if !fileExists(p) {
		errMsg("File not found: " + p)
		return "", false
	}
	return p, true
}

// interactiveExport writes lastReport in a chosen format.
func interactiveExport() {
	if lastReport == nil {
		warnMsg("No report yet. Run an analysis or the demo first.")
		return
	}
	sectionHeader("Export Report")
	f := chooseFormat(prompt("format txt|md|json|csv|sarif"))
	out := prompt("output file (blank = screen)")
	writeOrShow(lastReport, f, strings.TrimSpace(out))
}

// showLastReport renders the last report to the TUI.
func showLastReport() {
	if lastReport == nil {
		warnMsg("No report yet. Run an analysis or the demo first.")
		return
	}
	sectionHeader("Last Report — " + lastReport.Target)
	for _, k := range summaryKeys(lastReport.Summary) {
		kvRow(k, lastReport.Summary[k])
	}
	fmt.Println()
	printFindingsTable(lastReport)
	gradeBanner(lastReport)
}

// runDemoInteractive runs the synthetic demo inside the TUI.
func runDemoInteractive() {
	sectionHeader("Synthetic Demo")
	info("Generating self-contained sample data...")
	rep := hookDemo()
	rep.computeGrade()
	rep.sortFindings()
	lastReport = rep
	okMsg("Demo analysis complete.")
	fmt.Println()
	for _, k := range summaryKeys(rep.Summary) {
		kvRow(k, rep.Summary[k])
	}
	fmt.Println()
	printFindingsTable(rep)
	gradeBanner(rep)
}

// analyzeInteractive prompts for a file and runs the tool's analyzer.
func analyzeInteractive() {
	sectionHeader("Analyze Input File")
	p, ok := promptExistingPath("path to capture/log file")
	if !ok {
		return
	}
	info("Analyzing " + p + " ...")
	rep, err := hookAnalyze(p)
	if err != nil {
		errMsg(err.Error())
		return
	}
	rep.computeGrade()
	rep.sortFindings()
	lastReport = rep
	okMsg("Analysis complete.")
	fmt.Println()
	for _, k := range summaryKeys(rep.Summary) {
		kvRow(k, rep.Summary[k])
	}
	fmt.Println()
	printFindingsTable(rep)
	gradeBanner(rep)
}

// ============================================================================
//  Generic 802.11 frame-crafting toolkit (offline lab + demo synthesis)
// ============================================================================

// craftWrapPcap wraps raw link-layer frames into a little-endian pcap buffer.
func craftWrapPcap(frames [][]byte, linktype int, usecStep uint32) []byte {
	var b []byte
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 262144)
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(linktype))
	b = append(b, hdr...)
	ts := uint32(time.Now().Unix())
	us := uint32(0)
	for _, fr := range frames {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], ts)
		binary.LittleEndian.PutUint32(rec[4:8], us)
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(fr)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(len(fr)))
		b = append(b, rec...)
		b = append(b, fr...)
		us += usecStep
		if us >= 1000000 {
			ts += us / 1000000
			us %= 1000000
		}
	}
	return b
}

// craftBeaconOpen builds a minimal open-network beacon carrying SSID + DS param.
func craftBeaconOpen(bssid []byte, ssid string, ch int) []byte {
	var f []byte
	f = append(f, 0x80, 0x00, 0x00, 0x00)
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	f = append(f, bssid...)
	f = append(f, bssid...)
	f = append(f, 0x00, 0x00)
	f = append(f, 0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0x00, 0x11, 0x00)
	f = append(f, eidSSID, byte(len(ssid)))
	f = append(f, []byte(ssid)...)
	f = append(f, eidRates, 0x04, 0x82, 0x84, 0x8b, 0x96)
	f = append(f, eidDSParam, 0x01, byte(ch))
	return f
}

// craftDataEAPOL wraps an EAPOL payload inside an 802.11 data frame (LLC/SNAP).
func craftDataEAPOL(fromDS bool, ap, sta, eapol []byte) []byte {
	var f []byte
	if fromDS {
		f = append(f, 0x08, 0x02, 0x00, 0x00)
		f = append(f, sta...)
		f = append(f, ap...)
		f = append(f, sta...)
	} else {
		f = append(f, 0x08, 0x01, 0x00, 0x00)
		f = append(f, ap...)
		f = append(f, sta...)
		f = append(f, ap...)
	}
	f = append(f, 0x00, 0x00)
	f = append(f, 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e)
	f = append(f, eapol...)
	return f
}

// craftProbeReq builds a probe request from a client with a directed SSID.
func craftProbeReq(client []byte, ssid string) []byte {
	var f []byte
	f = append(f, 0x40, 0x00, 0x00, 0x00)
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	f = append(f, client...)
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	f = append(f, 0x00, 0x00)
	f = append(f, eidSSID, byte(len(ssid)))
	f = append(f, []byte(ssid)...)
	f = append(f, eidRates, 0x04, 0x82, 0x84, 0x8b, 0x96)
	f = append(f, eidExtRates, 0x04, 0x0c, 0x12, 0x18, 0x24)
	return f
}

// craftProbeResp builds a probe response from a BSSID to a client for an SSID.
func craftProbeResp(bssid, client []byte, ssid string, ch int, privacy bool) []byte {
	var f []byte
	f = append(f, 0x50, 0x00, 0x00, 0x00)
	f = append(f, client...)
	f = append(f, bssid...)
	f = append(f, bssid...)
	f = append(f, 0x00, 0x00)
	f = append(f, 0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0x00)
	caps := uint16(0x0021)
	if privacy {
		caps |= 0x0010
	}
	cb := make([]byte, 2)
	binary.LittleEndian.PutUint16(cb, caps)
	f = append(f, cb...)
	f = append(f, eidSSID, byte(len(ssid)))
	f = append(f, []byte(ssid)...)
	f = append(f, eidRates, 0x04, 0x82, 0x84, 0x8b, 0x96)
	f = append(f, eidDSParam, 0x01, byte(ch))
	return f
}

// craftBeaconSec builds a beacon with a chosen security posture (reuses RSN).
func craftBeaconSec(bssid []byte, ssid string, ch int, sec string) []byte {
	var f []byte
	f = append(f, 0x80, 0x00, 0x00, 0x00)
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	f = append(f, bssid...)
	f = append(f, bssid...)
	f = append(f, 0x00, 0x00)
	f = append(f, 0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0x00)
	caps := uint16(0x0001)
	if sec != "OPEN" {
		caps |= 0x0010
	}
	cb := make([]byte, 2)
	binary.LittleEndian.PutUint16(cb, caps)
	f = append(f, cb...)
	f = append(f, eidSSID, byte(len(ssid)))
	f = append(f, []byte(ssid)...)
	f = append(f, eidRates, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c)
	f = append(f, eidDSParam, 0x01, byte(ch))
	switch sec {
	case "WPA2-PSK":
		f = append(f, craftRSN(2, false)...)
	case "WPA3-SAE":
		f = append(f, craftRSN(8, true)...)
	case "WPA2-Enterprise":
		f = append(f, craftRSN(1, false)...)
	}
	return f
}

func craftRSN(akm int, mfpReq bool) []byte {
	var d []byte
	d = append(d, 0x01, 0x00)
	d = append(d, 0x00, 0x0f, 0xac, 0x04)
	d = append(d, 0x01, 0x00)
	d = append(d, 0x00, 0x0f, 0xac, 0x04)
	d = append(d, 0x01, 0x00)
	d = append(d, 0x00, 0x0f, 0xac, byte(akm))
	caps := uint16(0x0000)
	if mfpReq {
		caps |= 0x00c0
	}
	cb := make([]byte, 2)
	binary.LittleEndian.PutUint16(cb, caps)
	d = append(d, cb...)
	ie := []byte{eidRSN, byte(len(d))}
	return append(ie, d...)
}

// parseBeaconLike extracts SSID/channel/security from a beacon/probe-resp frame.
func parseBeaconLike(f *dot11Frame) (ssid string, ch int, sec string, hidden bool) {
	if len(f.Body) < 12 {
		return "", 0, "OPEN", false
	}
	caps := binary.LittleEndian.Uint16(f.Body[10:12])
	privacy := caps&0x0010 != 0
	ies := parseIEs(f.Body[12:])
	ssid = ieSSID(ies)
	if ssid == "<hidden>" || ssid == "" {
		hidden = true
	}
	ch = ieChannel(ies)
	var rsn rsnInfo
	if r := findIE(ies, eidRSN); r != nil {
		rsn = parseRSN(r)
	}
	sec = securityString(privacy, rsn, parseWPA1(ies))
	return ssid, ch, sec, hidden
}

// ============================================================================
//  OHandshake — WPA/WPA2 4-way handshake detector, validator & hashcat export
// ============================================================================

type hsMsg struct {
	Num      int
	Replay   uint64
	Nonce    []byte
	MIC      []byte
	MICSet   bool
	Idx      int
	EAPOLRaw []byte
}

type hsConv struct {
	AP    string
	STA   string
	ESSID string
	Msgs  map[int]*hsMsg
}

func (c *hsConv) has(n int) bool { _, ok := c.Msgs[n]; return ok }

func (c *hsConv) completeness() (int, string, string) {
	score := 0
	for i := 1; i <= 4; i++ {
		if c.has(i) {
			score++
		}
	}
	// crackable needs ANONCE (M1 or M3) + SNONCE+MIC (M2 or M4)
	crack := "no"
	grade := "F"
	switch {
	case c.has(1) && c.has(2) && c.has(3) && c.has(4):
		crack, grade = "full", "A"
	case c.has(1) && c.has(2):
		crack, grade = "M1+M2", "B"
	case c.has(2) && c.has(3):
		crack, grade = "M2+M3", "B"
	case c.has(3) && c.has(4):
		crack, grade = "M3+M4", "C"
	case score >= 1:
		crack, grade = "partial", "D"
	}
	return score, crack, grade
}

type hsResult struct {
	Target string
	Convs  map[string]*hsConv
	SSIDs  map[string]string // bssid -> ssid
	Frames int
	EAPOL  int
}

var hsState *hsResult

func hsKey(ap, sta string) string { return ap + "|" + sta }

func hsAnalyzeCap(cf *capFile, target string) *hsResult {
	res := &hsResult{Target: target, Convs: map[string]*hsConv{}, SSIDs: map[string]string{}}
	for _, pkt := range cf.Packets {
		res.Frames++
		data := pkt.Data
		if pkt.LinkType == DLT_RADIOTAP {
			_, data = parseRadiotap(data)
		} else if pkt.LinkType == DLT_PPI && len(data) >= 8 {
			l := int(binary.LittleEndian.Uint16(data[2:4]))
			if l > 0 && l <= len(data) {
				data = data[l:]
			}
		}
		f, err := parseDot11(data)
		if err != nil {
			continue
		}
		if f.Type == TypeMgmt && (f.Subtype == MgmtBeacon || f.Subtype == MgmtProbeResp) {
			if len(f.Body) >= 12 {
				ssid := ieSSID(parseIEs(f.Body[12:]))
				if ssid != "" && ssid != "<hidden>" {
					res.SSIDs[macStr(f.Addr3)] = ssid
				}
			}
			continue
		}
		if f.Type != TypeData {
			continue
		}
		eap := findEAPOLInPayload(f.Body)
		if eap == nil {
			continue
		}
		k := parseEAPOL(eap)
		if !k.Valid || k.MsgNum == 0 {
			continue
		}
		res.EAPOL++
		var ap, sta string
		if f.FromDS {
			ap = macStr(f.Addr2)
			sta = macStr(f.Addr1)
		} else {
			ap = macStr(f.Addr1)
			sta = macStr(f.Addr2)
		}
		key := hsKey(ap, sta)
		conv := res.Convs[key]
		if conv == nil {
			conv = &hsConv{AP: ap, STA: sta, Msgs: map[int]*hsMsg{}}
			res.Convs[key] = conv
		}
		conv.Msgs[k.MsgNum] = &hsMsg{
			Num: k.MsgNum, Replay: k.ReplayCtr, Nonce: k.Nonce, MIC: k.MIC,
			MICSet: k.MICSet, Idx: pkt.Index, EAPOLRaw: eap,
		}
	}
	for _, c := range res.Convs {
		if s, ok := res.SSIDs[c.AP]; ok {
			c.ESSID = s
		}
	}
	hsState = res
	return res
}

// hs22000 builds a hashcat -m 22000 (WPA-PBKDF2-PMKID+EAPOL) handshake line.
func hs22000(c *hsConv) string {
	m2 := c.Msgs[2]
	m1 := c.Msgs[1]
	if m2 == nil || (m1 == nil && c.Msgs[3] == nil) {
		return ""
	}
	anonce := []byte{}
	if m1 != nil {
		anonce = m1.Nonce
	} else if c.Msgs[3] != nil {
		anonce = c.Msgs[3].Nonce
	}
	mic := m2.MIC
	eapol := m2.EAPOLRaw
	apMac := strings.ReplaceAll(c.AP, ":", "")
	staMac := strings.ReplaceAll(c.STA, ":", "")
	essidHex := hex.EncodeToString([]byte(c.ESSID))
	return fmt.Sprintf("WPA*02*%s*%s*%s*%s*%s*%s*02",
		hex.EncodeToString(mic), apMac, staMac, essidHex,
		hex.EncodeToString(anonce), hex.EncodeToString(eapol))
}

func hsBuildReport(res *hsResult) *Report {
	rep := newReport(res.Target)
	rep.Summary["Frames"] = strconv.Itoa(res.Frames)
	rep.Summary["EAPOL Key Frames"] = strconv.Itoa(res.EAPOL)
	rep.Summary["Conversations"] = strconv.Itoa(len(res.Convs))
	usable := 0
	for _, c := range hsSortedConvs(res) {
		_, crack, grade := c.completeness()
		ent := fmt.Sprintf("%s↔%s (%s)", c.AP, c.STA, c.ESSID)
		if crack != "no" && crack != "partial" {
			usable++
			rep.add(Finding{
				ID: "OHANDSHAKE-CAPTURE", Title: "Crackable WPA handshake captured", Severity: SevHigh, Score: 7.5,
				Entity: ent, Detail: fmt.Sprintf("Handshake completeness %s (grade %s) is sufficient for offline PSK recovery (hashcat -m 22000).", crack, grade),
				Remediation: "Use a long, high-entropy passphrase or WPA3-SAE (resistant to offline dictionary attacks).",
				MITRE:       []string{"T1040", "T1110.002"},
			})
		} else if crack == "partial" {
			rep.add(Finding{
				ID: "OHANDSHAKE-PARTIAL", Title: "Partial handshake", Severity: SevLow, Score: 2.0,
				Entity: ent, Detail: "Incomplete handshake (insufficient messages for cracking).",
				Remediation: "N/A — informational.", MITRE: []string{"T1040"},
			})
		}
		if c.ESSID == "" {
			rep.add(Finding{
				ID: "OHANDSHAKE-NOESSID", Title: "Handshake without observed ESSID", Severity: SevInfo, Score: 0,
				Entity: ent, Detail: "No beacon/probe-response seen for this BSSID; ESSID required for hash export.",
				Remediation: "Capture a beacon for the BSSID to complete the 22000 hashline.", MITRE: nil,
			})
		}
	}
	rep.Summary["Usable Handshakes"] = strconv.Itoa(usable)
	rep.TextBody = hsTextBody(res)
	return rep
}

func hsTextBody(res *hsResult) string {
	var sb strings.Builder
	sb.WriteString("HANDSHAKE CONVERSATIONS\n")
	sb.WriteString(fmt.Sprintf("%-18s %-18s %-16s %-8s %-8s %s\n", "AP(BSSID)", "STA", "ESSID", "MSGS", "CRACK", "GRADE"))
	for _, c := range hsSortedConvs(res) {
		sc, crack, grade := c.completeness()
		msgs := ""
		for i := 1; i <= 4; i++ {
			if c.has(i) {
				msgs += strconv.Itoa(i)
			} else {
				msgs += "-"
			}
		}
		sb.WriteString(fmt.Sprintf("%-18s %-18s %-16s %-8s %-8s %s(%d/4)\n", c.AP, c.STA, truncStr(c.ESSID, 16), msgs, crack, grade, sc))
	}
	sb.WriteString("\nHASHCAT 22000 LINES (usable handshakes)\n")
	for _, c := range hsSortedConvs(res) {
		if l := hs22000(c); l != "" {
			sb.WriteString("  " + truncStr(l, 160) + "\n")
		}
	}
	return sb.String()
}

func hsSortedConvs(res *hsResult) []*hsConv {
	out := []*hsConv{}
	for _, c := range res.Convs {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AP != out[j].AP {
			return out[i].AP < out[j].AP
		}
		return out[i].STA < out[j].STA
	})
	return out
}

// ---- synthetic handshake crafting -----------------------------------------

func hsBuildEAPOL(msgNum int, replay uint64, nonce, mic []byte) []byte {
	var ki uint16
	switch msgNum {
	case 1:
		ki = 0x008a
	case 2:
		ki = 0x010a
	case 3:
		ki = 0x03ca
	case 4:
		ki = 0x030a
	}
	body := make([]byte, 0, 99)
	body = append(body, 0x02) // desc type RSN
	k := make([]byte, 2)
	binary.BigEndian.PutUint16(k, ki)
	body = append(body, k...)
	body = append(body, 0x00, 0x10) // key length 16
	r := make([]byte, 8)
	binary.BigEndian.PutUint64(r, replay)
	body = append(body, r...)
	n := make([]byte, 32)
	copy(n, nonce)
	body = append(body, n...)
	body = append(body, make([]byte, 16)...) // key IV
	body = append(body, make([]byte, 8)...)  // key RSC
	body = append(body, make([]byte, 8)...)  // reserved
	m := make([]byte, 16)
	copy(m, mic)
	body = append(body, m...)       // MIC
	body = append(body, 0x00, 0x00) // key data length 0
	// EAPOL header
	out := []byte{0x02, 0x03}
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(body)))
	out = append(out, l...)
	out = append(out, body...)
	return out
}

func hsWrapData(fromDS bool, ap, sta []byte, eapol []byte) []byte {
	var f []byte
	if fromDS {
		f = append(f, 0x08, 0x02, 0x00, 0x00) // FC(data,fromDS) + duration
		f = append(f, sta...)                 // addr1 DA=STA
		f = append(f, ap...)                  // addr2 BSSID
		f = append(f, sta...)                 // addr3 SA
	} else {
		f = append(f, 0x08, 0x01, 0x00, 0x00) // FC(data,toDS) + duration
		f = append(f, ap...)                  // addr1 BSSID
		f = append(f, sta...)                 // addr2 STA
		f = append(f, ap...)                  // addr3 BSSID
	}
	f = append(f, 0x00, 0x00) // seq ctrl
	f = append(f, 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e)
	f = append(f, eapol...)
	return f
}

func hsSynthCapture() []byte {
	ap := []byte{0x00, 0x1a, 0x2b, 0xaa, 0xbb, 0xcc}
	sta := []byte{0x3c, 0x07, 0x54, 0x11, 0x22, 0x33}
	anonce := bytes.Repeat([]byte{0xa1}, 32)
	snonce := bytes.Repeat([]byte{0x5b}, 32)
	mic := bytes.Repeat([]byte{0xcd}, 16)
	var frames [][]byte
	// beacon for ESSID
	frames = append(frames, wmBeaconForHS(ap, "SecureCorp", 6))
	frames = append(frames, hsWrapData(true, ap, sta, hsBuildEAPOL(1, 1, anonce, nil)))
	frames = append(frames, hsWrapData(false, ap, sta, hsBuildEAPOL(2, 1, snonce, mic)))
	frames = append(frames, hsWrapData(true, ap, sta, hsBuildEAPOL(3, 2, anonce, mic)))
	frames = append(frames, hsWrapData(false, ap, sta, hsBuildEAPOL(4, 2, make([]byte, 32), mic)))
	return hsWrapPcap(frames)
}

func wmBeaconForHS(bssid []byte, ssid string, ch int) []byte {
	var f []byte
	f = append(f, 0x80, 0x00, 0x00, 0x00)
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	f = append(f, bssid...)
	f = append(f, bssid...)
	f = append(f, 0x00, 0x00)
	f = append(f, 0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0x00, 0x11, 0x00)
	f = append(f, eidSSID, byte(len(ssid)))
	f = append(f, []byte(ssid)...)
	f = append(f, eidDSParam, 0x01, byte(ch))
	return f
}

func hsWrapPcap(frames [][]byte) []byte {
	var b []byte
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 262144)
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(DLT_IEEE802_11))
	b = append(b, hdr...)
	ts := uint32(time.Now().Unix())
	for i, fr := range frames {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], ts)
		binary.LittleEndian.PutUint32(rec[4:8], uint32(i*5000))
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(fr)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(len(fr)))
		b = append(b, rec...)
		b = append(b, fr...)
	}
	return b
}

// ---- hooks ----------------------------------------------------------------

func hsExportHashcat() {
	if hsState == nil {
		warnMsg("Run an analysis or demo first.")
		return
	}
	sectionHeader("Hashcat 22000 Export")
	n := 0
	for _, c := range hsSortedConvs(hsState) {
		if l := hs22000(c); l != "" {
			fmt.Println("  " + col(l, GRN))
			n++
		}
	}
	if n == 0 {
		warnMsg("No usable handshakes to export.")
	} else {
		okMsg(fmt.Sprintf("%d hashline(s) ready for: hashcat -m 22000", n))
	}
}

func hsViewConvs() {
	if hsState == nil {
		warnMsg("Run an analysis or demo first.")
		return
	}
	sectionHeader("Handshake Conversations")
	rows := [][]string{}
	for _, c := range hsSortedConvs(hsState) {
		sc, crack, grade := c.completeness()
		msgs := ""
		for i := 1; i <= 4; i++ {
			if c.has(i) {
				msgs += strconv.Itoa(i)
			} else {
				msgs += "-"
			}
		}
		rows = append(rows, []string{c.AP, c.STA, truncStr(c.ESSID, 14), msgs, crack, fmt.Sprintf("%s(%d/4)", grade, sc)})
	}
	table([]string{"AP", "STA", "ESSID", "MSGS", "CRACK", "GRADE"}, rows)
}

func hsAnalyzePath(path string) (*Report, error) {
	cf, err := loadCapture(path)
	if err != nil {
		return nil, err
	}
	return hsBuildReport(hsAnalyzeCap(cf, filepath.Base(path))), nil
}

func hsDemoReport() *Report {
	cf, err := parseCaptureBytes(hsSynthCapture())
	if err != nil {
		r := newReport("synthetic-demo")
		r.add(Finding{Title: "demo error", Detail: err.Error(), Severity: SevInfo})
		return r
	}
	return hsBuildReport(hsAnalyzeCap(cf, "synthetic-demo"))
}

func hsHowto() []howSection {
	return []howSection{
		{"LEGAL & ETHICAL WARNING", legalWarningLines()},
		{"HOW TO USE", []string{
			"OHandshake detects and validates WPA/WPA2 4-way handshakes offline.",
			"",
			"1. Capture EAPOL frames (deauth-assisted reauth is a separate step",
			"   and must be authorized).",
			"2. Run:  OHandshake --input handshake.pcap",
			"3. Review completeness grade per AP↔STA conversation.",
			"4. Export hashcat 22000 lines:  menu → 'Export hashcat 22000'.",
			"5. Crack OFFLINE with your own wordlist (authorized engagements).",
			"6. Demo:  OHandshake --demo  (synthetic M1-M4).",
		}},
		{"REQUIREMENTS", []string{
			"- A pcap/pcapng containing EAPOL-Key frames and a beacon for ESSID.",
			"- Offline only; no deauth is transmitted by this build.",
		}},
		{"PROTOCOL NOTES", []string{
			"- 4-way handshake: M1(ANonce), M2(SNonce+MIC), M3(install), M4(ack).",
			"- Crackable minimum is M1+M2 or M2+M3 with a known ESSID.",
			"- hashcat -m 22000 unifies PMKID + EAPOL (WPA*02*).",
			"- WPA3-SAE is immune to offline dictionary attacks on the PMK.",
		}},
	}
}

func hsActions() []menuAction {
	return []menuAction{
		{"Analyze capture", "pcap/pcapng: handshakes, PMKID, grade", analyzeInteractive},
		{"Run synthetic demo", "built-in M1-M4 sample, no file needed", runDemoInteractive},
		{"View conversations", "AP/client table: messages & grade", hsViewConvs},
		{"Export hashcat 22000", "22000 lines for complete handshakes", hsExportHashcat},
		{"Show last report", "re-display the most recent analysis", showLastReport},
		{"Export report", "txt/md/json/csv/sarif to a file", interactiveExport},
	}
}

func init() {
	hookHowto = hsHowto
	hookDemo = hsDemoReport
	hookAnalyze = hsAnalyzePath
	hookActions = hsActions
}

// ============================================================
//  Self-test — exercises the real parse/detect/export pipeline
//  on a synthetic capture and known helper vectors.
// ============================================================

func runSelfTest() int {
	pass, fail := 0, 0
	check := func(name string, cond bool, detail string) {
		if cond {
			pass++
			okMsg(name)
		} else {
			fail++
			errMsg(name + " — " + detail)
		}
	}
	sectionHeader("OHandshake self-test")
	fmt.Println()

	// Helpers.
	m, err := parseMAC("00:1a:2b:aa:bb:cc")
	check("parseMAC round-trip", err == nil && macStr(m) == "00:1a:2b:aa:bb:cc", macStr(m))
	check("macIsBroadcast", macIsBroadcast([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}), "")
	check("macIsMulticast", macIsMulticast([]byte{0x01, 0, 0, 0, 0, 0}), "")

	// EAPOL message classification on crafted M1..M4.
	anonce := bytes.Repeat([]byte{0xa1}, 32)
	snonce := bytes.Repeat([]byte{0x5b}, 32)
	mic := bytes.Repeat([]byte{0xcd}, 16)
	k1 := parseEAPOL(hsBuildEAPOL(1, 1, anonce, nil))
	k2 := parseEAPOL(hsBuildEAPOL(2, 1, snonce, mic))
	k3 := parseEAPOL(hsBuildEAPOL(3, 2, anonce, mic))
	k4 := parseEAPOL(hsBuildEAPOL(4, 2, make([]byte, 32), mic))
	check("EAPOL M1 classified", k1.MsgNum == 1, strconv.Itoa(k1.MsgNum))
	check("EAPOL M2 classified", k2.MsgNum == 2, strconv.Itoa(k2.MsgNum))
	check("EAPOL M3 classified", k3.MsgNum == 3, strconv.Itoa(k3.MsgNum))
	check("EAPOL M4 classified", k4.MsgNum == 4, strconv.Itoa(k4.MsgNum))
	check("M2 MIC captured", k2.MICSet && hex.EncodeToString(k2.MIC) == hex.EncodeToString(mic), hex.EncodeToString(k2.MIC))

	// Full pipeline: synth pcap → parse → analyze → export.
	raw := hsSynthCapture()
	cf, err := parseCaptureBytes(raw)
	check("synth pcap parses", err == nil && cf != nil, errStr(err))
	if cf != nil {
		res := hsAnalyzeCap(cf, "selftest")
		check("4 EAPOL key frames", res.EAPOL == 4, strconv.Itoa(res.EAPOL))
		check("1 handshake conversation", len(res.Convs) == 1, strconv.Itoa(len(res.Convs)))
		for _, c := range res.Convs {
			score, crack, grade := c.completeness()
			check("handshake complete (4/4)", score == 4 && grade == "A", fmt.Sprintf("%d/%s/%s", score, crack, grade))
			line := hs22000(c)
			parts := strings.Split(line, "*")
			check("22000 line well-formed", strings.HasPrefix(line, "WPA*02*") && len(parts) == 9, strconv.Itoa(len(parts)))
			check("22000 AP MAC field", parts[3] == strings.ReplaceAll(c.AP, ":", ""), parts[3])
			check("22000 ESSID is hex of ESSID", parts[5] == hex.EncodeToString([]byte(c.ESSID)), parts[5])
		}
	}

	// pcapng path parses the same crafted frames as pcap.
	check("pcap format detected", cf != nil && cf.Format == "pcap", fmtStr(cf))

	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("All %d checks passed.", pass))
		return 0
	}
	errMsg(fmt.Sprintf("%d passed, %d failed.", pass, fail))
	return 1
}

func errStr(e error) string {
	if e == nil {
		return "nil"
	}
	return e.Error()
}
func fmtStr(cf *capFile) string {
	if cf == nil {
		return "(nil)"
	}
	return cf.Format
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"OHandshake reads Wi-Fi capture files offline and rebuilds WPA / WPA2 authentication exchanges. For each access point and client it shows which of the four handshake messages were captured, whether a PMKID is present, and whether the exchange is complete enough for an offline PSK audit. It groups everything by conversation, grades completeness and exports in the hashcat 22000 format so the data can be checked against your own wordlist.",
	"It only reads files you supply and does not transmit, inject or connect to anything.",
}

var owlHelpFlow = []string{
	"Type the number of an option and press Enter. Start with [1] and give it a capture, or try [2] to see a full example. Options [3] to [6] then work on that last result. [H] opens this help, [0] or q quits.",
	"The capture must contain EAPOL frames (the 4-way handshake) or a PMKID. Record in monitor mode and, if needed, reconnect a client you control so the handshake is captured.",
}

var owlHelpMenu = []owlHelpItem{
	{"01", "Analyze capture: enter the path of a .pcap / .pcapng. Shows every AP/client conversation, the messages captured (1-4), PMKID, completeness grade and findings."},
	{"02", "Run synthetic demo: analyzes a built-in sample capture so you can see a full result without a file."},
	{"03", "View conversations: the AP/client table again, with ESSID, which messages are present and the completeness grade."},
	{"04", "Export hashcat 22000: prints the 22000 hash lines for the complete handshakes in the last result."},
	{"05", "Show last report: prints the most recent analysis again."},
	{"06", "Export report: choose txt, md, json, csv or sarif and an output file (blank = print to screen)."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "M1+M2 of one session, or a PMKID alone, is enough for an offline PSK audit. A full 1-4 handshake is best."},
	{"*", "Save the 22000 lines to a file and audit them against your own wordlist with your usual tool (hashcat -m 22000)."},
	{"*", "A strong, unique passphrase defeats this entirely. The point of the audit is to prove weak PSKs before an attacker does."},
	{"*", "Use only on networks you own or are authorised to test. The legal notes are on page 3."},
}

func owlHelpCLI() {
	printUsage()
	pause()
	renderHowto(hookHowto())
}
