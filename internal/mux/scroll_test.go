package mux

import (
	"strings"
	"testing"
)

func TestRenderScrollIndicator(t *testing.T) {
	var buf []byte
	buf = RenderScrollIndicator(buf, 10, 100, 80, 24)
	s := string(buf)
	if !strings.Contains(s, "scroll:") {
		t.Fatal("expected scroll indicator")
	}
	if !strings.Contains(s, "90/100") {
		t.Fatalf("expected 90/100, got %q", s)
	}
}

func TestRenderScrollIndicatorTooSmall(t *testing.T) {
	var buf []byte
	buf = RenderScrollIndicator(buf, 10, 100, 5, 1)
	if len(buf) != 0 {
		t.Fatal("expected empty for small terminal")
	}
}

func TestScrollActionConstants(t *testing.T) {
	// Verify all constants are distinct.
	vals := map[byte]string{
		ScrollUp:       "ScrollUp",
		ScrollDown:     "ScrollDown",
		ScrollHalfUp:   "ScrollHalfUp",
		ScrollHalfDown: "ScrollHalfDown",
		ScrollTop:      "ScrollTop",
		ScrollBottom:   "ScrollBottom",
	}
	if len(vals) != 6 {
		t.Fatal("scroll action constants are not all distinct")
	}
}
