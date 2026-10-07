package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// trayIcon is the menu-bar icon: the console's shield mark, black + alpha only so macOS treats it as a TEMPLATE
// image and renders it correctly in both light and dark menu bars (and inverted when selected). It is 32px
// because systray shows it at 16pt, which is 32px on a Retina display. Embedded rather than loaded from disk —
// a menu-bar app must not depend on finding a file at runtime.
//
//go:embed tray-icon.png
var trayIcon []byte

// iconState is what the menu-bar icon says at a glance. A template image has one color, so each state is a
// shape on the shield, never a tint.
type iconState int

const (
	iconIdle      iconState = iota // no server, or no daemon: the shield faded
	iconSignedIn                   // the plain shield
	iconExpiring                   // a clock badge: a sign-in ends soon
	iconSignedOut                  // a slash: a configured server is signed out
	iconBusy                       // three dots: a browser sign-in is open
)

var stateIcons = buildStateIcons()

func buildStateIcons() map[iconState][]byte {
	base, err := png.Decode(bytes.NewReader(trayIcon))
	if err != nil {
		panic(err)
	}
	icons := map[iconState][]byte{iconSignedIn: trayIcon}
	for state, draw := range map[iconState]func(*image.NRGBA){
		iconIdle:      func(m *image.NRGBA) { fade(m, 0.35) },
		iconExpiring:  drawClockBadge,
		iconSignedOut: func(m *image.NRGBA) { fade(m, 0.55); drawSlash(m) },
		iconBusy:      func(m *image.NRGBA) { fade(m, 0.75); drawDots(m) },
	} {
		m := image.NewNRGBA(base.Bounds())
		for y := range m.Bounds().Dy() {
			for x := range m.Bounds().Dx() {
				m.Set(x, y, base.At(x, y))
			}
		}
		draw(m)
		var buf bytes.Buffer
		if err := png.Encode(&buf, m); err != nil {
			panic(err)
		}
		icons[state] = buf.Bytes()
	}
	return icons
}

func alphaAt(m *image.NRGBA, x, y int) uint8 { return m.NRGBAAt(x, y).A }

func setAlpha(m *image.NRGBA, x, y int, a uint8) {
	if image.Pt(x, y).In(m.Bounds()) {
		m.SetNRGBA(x, y, color.NRGBA{A: a})
	}
}

func fade(m *image.NRGBA, f float64) {
	for y := range m.Bounds().Dy() {
		for x := range m.Bounds().Dx() {
			setAlpha(m, x, y, uint8(float64(alphaAt(m, x, y))*f))
		}
	}
}

// drawClockBadge cuts a ring of clear space at the bottom-right corner and draws a small clock in it, so the
// badge reads against the shield behind it.
func drawClockBadge(m *image.NRGBA) {
	const cx, cy, r = 24.0, 24.0, 7.0
	for y := 14; y < 32; y++ {
		for x := 14; x < 32; x++ {
			px, py := float64(x)+0.5, float64(y)+0.5
			d := math.Hypot(px-cx, py-cy)
			hand := (math.Abs(px-cx) < 0.9 && py <= cy && py > cy-4.5) || (math.Abs(py-cy) < 0.9 && px >= cx && px < cx+3.5)
			switch {
			case d <= r-1.8 && !hand:
				setAlpha(m, x, y, 0)
			case d <= r:
				setAlpha(m, x, y, 255)
			case d <= r+1.6:
				setAlpha(m, x, y, 0)
			}
		}
	}
}

// drawSlash strikes the shield from bottom-left to top-right, with a clear edge so it reads over the strokes.
func drawSlash(m *image.NRGBA) {
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			d := math.Abs(float64(x)+float64(y)+1-32) / math.Sqrt2
			switch {
			case d < 1.3 && x > 2 && x < 29:
				setAlpha(m, x, y, 255)
			case d < 2.8:
				setAlpha(m, x, y, 0)
			}
		}
	}
}

// drawDots clears a strip along the bottom-right and draws three dots in it.
func drawDots(m *image.NRGBA) {
	for y := 23; y < 32; y++ {
		for x := 12; x < 32; x++ {
			setAlpha(m, x, y, 0)
		}
	}
	for _, cx := range []float64{16.5, 22.5, 28.5} {
		for y := 24; y < 31; y++ {
			for x := 12; x < 32; x++ {
				if math.Hypot(float64(x)+0.5-cx, float64(y)+0.5-27.5) <= 2.1 {
					setAlpha(m, x, y, 255)
				}
			}
		}
	}
}

// toICO wraps a PNG in a one-image .ico, the only icon format the Windows notification area takes.
func toICO(p []byte) []byte {
	img, err := png.DecodeConfig(bytes.NewReader(p))
	if err != nil {
		panic(err)
	}
	side := func(n int) byte {
		if n >= 256 {
			return 0 // 0 means 256
		}
		return byte(n)
	}
	var b bytes.Buffer
	b.Write([]byte{0, 0, 1, 0, 1, 0})
	b.Write([]byte{side(img.Width), side(img.Height), 0, 0, 1, 0, 32, 0})
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(p)))
	_ = binary.Write(&b, binary.LittleEndian, uint32(22))
	b.Write(p)
	return b.Bytes()
}

// recolor paints a template icon's shape in c, keeping its alpha, for a tray that does not tint icons itself.
func recolor(p []byte, c color.NRGBA) []byte {
	src, err := png.Decode(bytes.NewReader(p))
	if err != nil {
		panic(err)
	}
	m := image.NewNRGBA(src.Bounds())
	for y := range m.Bounds().Dy() {
		for x := range m.Bounds().Dx() {
			_, _, _, a := src.At(x, y).RGBA()
			m.SetNRGBA(x, y, color.NRGBA{R: c.R, G: c.G, B: c.B, A: uint8(a >> 8)})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, m); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
