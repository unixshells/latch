package mux

import "strconv"

// Scroll actions sent in MsgScrollAction payloads.
const (
	ScrollUp       byte = 0x01 // one line up
	ScrollDown     byte = 0x02 // one line down
	ScrollHalfUp   byte = 0x03 // half page up
	ScrollHalfDown byte = 0x04 // half page down
	ScrollTop      byte = 0x05 // jump to top of scrollback
	ScrollBottom   byte = 0x06 // jump to bottom (exit scroll)
)

// RenderScrollIndicator appends a right-aligned "[scroll: LINE/TOTAL]" bar
// on the last row of the terminal.
func RenderScrollIndicator(buf []byte, offset, total, cols, rows int) []byte {
	if cols < 10 || rows < 1 {
		return buf
	}

	const (
		bg  = "\x1b[48;5;178m"
		fg  = "\x1b[30m"
		rst = "\x1b[0m"
	)

	line := total - offset
	label := "[scroll: " + strconv.Itoa(line) + "/" + strconv.Itoa(total) + "]"

	if len(label) > cols {
		label = label[:cols]
	}
	col := cols - len(label) + 1
	if col < 1 {
		col = 1
	}

	buf = appendCUP(buf, rows, col)
	buf = append(buf, bg...)
	buf = append(buf, fg...)
	buf = append(buf, label...)
	buf = append(buf, rst...)
	return buf
}
