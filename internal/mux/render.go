package mux

import (
	"image"
	"strconv"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/mattn/go-runewidth"
)

// HUDInfo holds server status for the HUD overlay.
type HUDInfo struct {
	SSHAddr   string // empty = not listening
	WebAddr   string // empty = not listening
	RelayAddr string // empty = not connected
	PrefixKey byte
}

// Render composites the session's active window into ANSI output.
func Render(sess *Session, totalCols, totalRows int, hud *HUDInfo) []byte {
	if totalCols < 1 || totalRows < 1 {
		return nil
	}

	win := sess.ActiveWindow()
	if win == nil {
		return nil
	}

	pane := win.Snapshot()
	if pane == nil {
		return nil
	}

	paneArea := Rect{0, 0, totalCols, totalRows}

	var buf []byte
	// Reset SGR state and hide cursor during render. No bracketed paste
	// here — it's enabled once at attach time, not every frame.
	buf = append(buf, "\x1b[0m\x1b[?25l"...)

	var cursor image.Point
	buf, cursor = renderPaneCells(buf, pane, paneArea)

	// Place cursor from the same atomic snapshot as the cells.
	buf = appendCUP(buf, cursor.Y+1, cursor.X+1)
	if pane.CursorVisible() {
		buf = append(buf, "\x1b[?25h"...)
	}

	if hud != nil {
		buf = renderHUD(buf, sess, hud, totalCols, totalRows)
	}

	if pane.DrainBell() {
		buf = append(buf, '\a')
	}

	if clip := pane.DrainClipboard(); validClipboard(clip) {
		buf = append(buf, "\x1b]52;"...)
		buf = append(buf, clip...)
		buf = append(buf, '\a')
	}

	return buf
}

// RenderScroll composites a scrolled view of the active pane.
// offset is the number of lines scrolled up from the bottom.
func RenderScroll(sess *Session, totalCols, totalRows, offset int) []byte {
	if totalCols < 1 || totalRows < 1 {
		return nil
	}

	win := sess.ActiveWindow()
	if win == nil {
		return nil
	}

	pane := win.Snapshot()
	if pane == nil {
		return nil
	}

	var buf []byte
	buf = append(buf, "\x1b[?25l"...) // hide cursor during scroll mode

	scr := pane.ScrollScreen(offset, totalCols, totalRows)
	var prev uv.Style

	for row := 0; row < totalRows; row++ {
		buf = appendCUP(buf, row+1, 1)
		for col := 0; col < totalCols; col++ {
			if row < scr.H && col < scr.W {
				cell := scr.Cells[row*scr.W+col]
				if cell.Content != "" && cell.Width > 0 {
					buf = appendStyleTransition(buf, &prev, &cell.Style)
					buf = append(buf, cell.Content...)
					if cell.Width > 1 {
						col += cell.Width - 1
					}
					continue
				}
			}
			buf = appendStyleTransition(buf, &prev, &uv.Style{})
			buf = append(buf, ' ')
		}
	}
	buf = append(buf, "\x1b[0m"...)

	total := pane.ScrollbackLen() + totalRows
	buf = RenderScrollIndicator(buf, offset, total, totalCols, totalRows)

	return buf
}

func validClipboard(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, b := range data {
		if b < 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}

func renderPaneCells(buf []byte, p *Pane, r Rect) ([]byte, image.Point) {
	scr := p.Screen()
	var prev uv.Style

	for row := 0; row < r.H; row++ {
		buf = appendCUP(buf, r.Y+row+1, r.X+1)
		for col := 0; col < r.W; col++ {
			if row < scr.H && col < scr.W {
				cell := scr.Cells[row*scr.W+col]
				if cell.Content != "" && cell.Width > 0 {
					buf = appendStyleTransition(buf, &prev, &cell.Style)
					buf = append(buf, cell.Content...)
					if cell.Width > 1 {
						col += cell.Width - 1
					}
					continue
				}
			}
			buf = appendStyleTransition(buf, &prev, &uv.Style{})
			buf = append(buf, ' ')
		}
	}
	buf = append(buf, "\x1b[0m"...)
	return buf, scr.Cursor
}

func appendStyleTransition(buf []byte, prev, next *uv.Style) []byte {
	s := uv.StyleDiff(prev, next)
	*prev = *next
	if len(s) == 0 {
		return buf
	}
	return append(buf, s...)
}

// appendCUP appends \x1b[row;colH cursor position sequence.
func appendCUP(buf []byte, row, col int) []byte {
	buf = append(buf, "\x1b["...)
	buf = strconv.AppendInt(buf, int64(row), 10)
	buf = append(buf, ';')
	buf = strconv.AppendInt(buf, int64(col), 10)
	buf = append(buf, 'H')
	return buf
}

// appendSpaces appends n space characters.
func appendSpaces(buf []byte, n int) []byte {
	for n > 0 {
		buf = append(buf, ' ')
		n--
	}
	return buf
}

// padOrTruncate pads the string with spaces or truncates it to exactly
// cols display columns.
func padOrTruncate(s string, cols int) string {
	w := runewidth.StringWidth(s)
	if w < cols {
		pad := make([]byte, cols-w)
		for i := range pad {
			pad[i] = ' '
		}
		return s + string(pad)
	}
	if w > cols {
		return runewidth.Truncate(s, cols, "")
	}
	return s
}

// renderHUD draws two slim full-width bars: keybindings on top, status on bottom.
func renderHUD(buf []byte, sess *Session, info *HUDInfo, cols, rows int) []byte {
	if cols < 20 || rows < 3 {
		return buf
	}

	const (
		bg  = "\x1b[48;5;235m"
		k   = "\x1b[1;38;5;75m"
		d   = "\x1b[38;5;245m"
		hi  = "\x1b[38;5;252m"
		grn = "\x1b[38;5;76m"
		dim = "\x1b[38;5;242m"
		sep = "\x1b[38;5;238m"
		rst = "\x1b[0m"
	)

	// Top bar: keybindings.
	buf = append(buf, "\x1b[1;1H"...)
	buf = append(buf, bg...)

	pfx := prefixName(info.PrefixKey)

	type item struct {
		vis int
		s   string
	}
	items := [7]item{
		{1 + len(pfx) + 8, " " + hi + pfx + d + " prefix "},
		{7, " " + k + "c" + d + " win "},
		{9, " " + k + "n" + d + "/" + k + "p" + d + " nav "},
		{9, " " + k + "0-9" + d + " sel "},
		{9, " " + k + "g" + d + "N goto "},
		{9, " " + k + "x" + d + " close "},
		{10, " " + k + "d" + d + " detach "},
	}

	topVis := 0
	for _, it := range items {
		if topVis+it.vis > cols {
			break
		}
		buf = append(buf, it.s...)
		topVis += it.vis
	}
	buf = appendSpaces(buf, cols-topVis)
	buf = append(buf, rst...)

	// Bottom bar: status.
	buf = appendCUP(buf, rows, 1)
	buf = append(buf, bg...)

	// Left: session + window list.
	windows := sess.Windows()
	activeIdx := sess.ActiveWindowIndex()

	buf = append(buf, ' ')
	buf = append(buf, hi...)
	buf = append(buf, sess.Name...)
	leftVis := 1 + len(sess.Name)

	for i, w := range windows {
		marker := byte(' ')
		if i == activeIdx {
			marker = '*'
		}
		wt := w.Title()
		pieceVis := 2 + 1 + numWidth(i) + 1 + len(wt) + 1
		buf = append(buf, ' ')
		buf = append(buf, sep...)
		buf = append(buf, "│"...)
		buf = append(buf, d...)
		buf = append(buf, ' ')
		buf = strconv.AppendInt(buf, int64(i), 10)
		buf = append(buf, ':')
		buf = append(buf, wt...)
		buf = append(buf, marker)
		leftVis += pieceVis
	}

	// Right: ssh + web status.
	rightVis := 0
	var right []byte

	if info.SSHAddr != "" {
		right = append(right, d...)
		right = append(right, "ssh "...)
		right = append(right, grn...)
		right = append(right, "● "...)
		right = append(right, hi...)
		right = append(right, info.SSHAddr...)
		rightVis += 4 + 2 + len(info.SSHAddr)
	} else {
		right = append(right, d...)
		right = append(right, "ssh "...)
		right = append(right, dim...)
		right = append(right, "○ off"...)
		rightVis += 4 + 2 + 3
	}

	right = append(right, "  "...)
	rightVis += 2

	if info.WebAddr != "" {
		right = append(right, d...)
		right = append(right, "web "...)
		right = append(right, grn...)
		right = append(right, "● "...)
		right = append(right, hi...)
		right = append(right, info.WebAddr...)
		rightVis += 4 + 2 + len(info.WebAddr)
	} else {
		right = append(right, d...)
		right = append(right, "web "...)
		right = append(right, dim...)
		right = append(right, "○ off"...)
		rightVis += 4 + 2 + 3
	}

	right = append(right, "  "...)
	rightVis += 2

	if info.RelayAddr != "" {
		right = append(right, d...)
		right = append(right, "relay "...)
		right = append(right, grn...)
		right = append(right, "● "...)
		right = append(right, hi...)
		right = append(right, info.RelayAddr...)
		rightVis += 6 + 2 + len(info.RelayAddr)
	} else {
		right = append(right, d...)
		right = append(right, "relay "...)
		right = append(right, dim...)
		right = append(right, "○ off"...)
		rightVis += 6 + 2 + 3
	}

	right = append(right, ' ')
	rightVis++

	gap := cols - leftVis - rightVis
	if gap < 1 {
		gap = 1
	}

	buf = appendSpaces(buf, gap)
	buf = append(buf, right...)
	buf = append(buf, rst...)

	return buf
}

func prefixName(b byte) string {
	if b >= 1 && b <= 26 {
		return "C-" + string(rune('a'+b-1))
	}
	switch b {
	case 0x1b:
		return "C-["
	case 0x1c:
		return "C-\\"
	case 0x1d:
		return "C-]"
	case 0x1e:
		return "C-^"
	case 0x1f:
		return "C-_"
	}
	return "0x" + strconv.FormatInt(int64(b), 16)
}

func numWidth(n int) int {
	if n == 0 {
		return 1
	}
	w := 0
	for n > 0 {
		w++
		n /= 10
	}
	return w
}
