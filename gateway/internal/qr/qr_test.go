package qr

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// This file contains an independent QR decoder used to check the encoder. It shares no code with
// qr.go: function-pattern areas, the alignment table, masks, the codeword traversal, the format
// BCH check and the Reed–Solomon syndrome check are written out here from the standard. Only the
// block table (levelM) is shared; it is checked against the module count and against libqrencode.

// isoAlignment is ISO/IEC 18004 Annex E (row/column coordinates of alignment pattern centres).
var isoAlignment = map[int][]int{
	2: {6, 18}, 3: {6, 22}, 4: {6, 26}, 5: {6, 30}, 6: {6, 34}, 7: {6, 22, 38}, 8: {6, 24, 42}, 9: {6, 26, 46},
	10: {6, 28, 50}, 11: {6, 30, 54}, 12: {6, 32, 58}, 13: {6, 34, 62}, 14: {6, 26, 46, 66}, 15: {6, 26, 48, 70},
	16: {6, 26, 50, 74}, 17: {6, 30, 54, 78}, 18: {6, 30, 56, 82}, 19: {6, 30, 58, 86}, 20: {6, 34, 62, 90},
	21: {6, 28, 50, 72, 94}, 22: {6, 26, 50, 74, 98}, 23: {6, 30, 54, 78, 102}, 24: {6, 28, 54, 80, 106},
	25: {6, 32, 58, 84, 110}, 26: {6, 30, 58, 86, 114}, 27: {6, 34, 62, 90, 118}, 28: {6, 26, 50, 74, 98, 122},
	29: {6, 30, 54, 78, 102, 126}, 30: {6, 26, 52, 78, 104, 130}, 31: {6, 30, 56, 82, 108, 134},
	32: {6, 34, 60, 86, 112, 138}, 33: {6, 30, 58, 86, 114, 142}, 34: {6, 34, 62, 90, 118, 146},
	35: {6, 30, 54, 78, 102, 126, 150}, 36: {6, 24, 50, 76, 102, 128, 154}, 37: {6, 28, 54, 80, 106, 132, 158},
	38: {6, 32, 58, 84, 110, 136, 162}, 39: {6, 26, 54, 82, 110, 138, 166}, 40: {6, 30, 58, 86, 114, 142, 170},
}

// isoTotalCodewords is the total number of codewords per version (ISO/IEC 18004 table 1).
var isoTotalCodewords = []int{0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346, 404, 466, 532, 581, 655, 733, 815,
	901, 991, 1085, 1156, 1258, 1364, 1474, 1588, 1706, 1828, 1921, 2051, 2185, 2323, 2465, 2611, 2761, 2876,
	3034, 3196, 3362, 3532, 3706}

// Format words for level M, masks 0–7, as printed in the standard's annex C table (MSB first).
var isoFormatM = []string{"101010000010010", "101000100100101", "101111001111100", "101101101001011",
	"100010111111001", "100000011001110", "100111110010111", "100101010100000"}

type decoded struct {
	version int
	mask    int
	data    []byte
}

func functionMap(size, version int) [][]bool {
	f := make([][]bool, size)
	for r := range f {
		f[r] = make([]bool, size)
	}
	mark := func(r0, r1, c0, c1 int) {
		for r := r0; r <= r1; r++ {
			for c := c0; c <= c1; c++ {
				f[r][c] = true
			}
		}
	}
	mark(0, 8, 0, 8)           // top-left finder, separator, format
	mark(0, 8, size-8, size-1) // top-right finder, separator, format
	mark(size-8, size-1, 0, 8) // bottom-left finder, separator, format, dark module
	mark(6, 6, 0, size-1)      // timing row
	mark(0, size-1, 6, 6)      // timing column
	pos := isoAlignment[version]
	for _, r := range pos {
		for _, c := range pos {
			if (r < 9 && c < 9) || (r < 9 && c > size-9) || (r > size-9 && c < 9) {
				continue
			}
			mark(r-2, r+2, c-2, c+2)
		}
	}
	if version >= 7 {
		mark(0, 5, size-11, size-9)
		mark(size-11, size-9, 0, 5)
	}
	return f
}

func maskAt(mask, r, c int) bool {
	switch mask {
	case 0:
		return (r+c)%2 == 0
	case 1:
		return r%2 == 0
	case 2:
		return c%3 == 0
	case 3:
		return (r+c)%3 == 0
	case 4:
		return (r/2+c/3)%2 == 0
	case 5:
		return (r*c)%2+(r*c)%3 == 0
	case 6:
		return ((r*c)%2+(r*c)%3)%2 == 0
	case 7:
		return ((r+c)%2+(r*c)%3)%2 == 0
	}
	panic("mask")
}

func readFormat(m [][]bool) (int, error) {
	size := len(m)
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	var copy1, copy2 int
	// Copy 1: bits 14..9 on row 8, columns 0..5; bit 8 at (8,7); bit 7 at (8,8); bit 6 at (7,8);
	// bits 5..0 on column 8, rows 5..0.
	for i := 0; i <= 5; i++ {
		copy1 |= b(m[8][i]) << uint(14-i)
	}
	copy1 |= b(m[8][7])<<8 | b(m[8][8])<<7 | b(m[7][8])<<6
	for r := 0; r <= 5; r++ {
		copy1 |= b(m[r][8]) << uint(r)
	}
	// Copy 2: bits 0..7 on row 8, columns size-1..size-8; bits 8..14 on column 8, rows size-7..size-1.
	for i := 0; i < 8; i++ {
		copy2 |= b(m[8][size-1-i]) << uint(i)
	}
	for i := 8; i < 15; i++ {
		copy2 |= b(m[size-15+i][8]) << uint(i)
	}
	if copy1 != copy2 {
		return 0, fmt.Errorf("format copies differ: %015b vs %015b", copy1, copy2)
	}
	for mask, s := range isoFormatM {
		v, _ := strconv.ParseInt(s, 2, 32)
		if int(v) == copy1 {
			return mask, nil
		}
	}
	return 0, fmt.Errorf("format %015b is not a level-M word", copy1)
}

// Independent GF(256) for the syndrome check.
func gfTables() (exp [256]int, log [256]int) {
	x := 1
	for i := 0; i < 255; i++ {
		exp[i] = x
		log[x] = i
		x *= 2
		if x >= 256 {
			x ^= 0x11D
		}
	}
	return
}

func syndromesZero(codeword []byte, ec int) bool {
	exp, log := gfTables()
	n := len(codeword)
	for j := 0; j < ec; j++ {
		s := 0
		for k, c := range codeword {
			if c == 0 {
				continue
			}
			power := (j * (n - 1 - k)) % 255
			s ^= exp[(log[c]+power)%255]
		}
		if s != 0 {
			return false
		}
	}
	return true
}

func decode(m [][]bool) (decoded, error) {
	size := len(m)
	if size < 21 || (size-17)%4 != 0 {
		return decoded{}, errors.New("bad size")
	}
	version := (size - 17) / 4
	if !m[size-8][8] {
		return decoded{}, errors.New("dark module missing")
	}
	mask, err := readFormat(m)
	if err != nil {
		return decoded{}, err
	}
	fn := functionMap(size, version)
	var bits []bool
	upward := true
	for col := size - 1; col > 0; col -= 2 {
		if col == 6 {
			col--
		}
		for i := 0; i < size; i++ {
			r := i
			if upward {
				r = size - 1 - i
			}
			for _, c := range []int{col, col - 1} {
				if !fn[r][c] {
					bits = append(bits, m[r][c] != maskAt(mask, r, c))
				}
			}
		}
		upward = !upward
	}
	if len(bits)/8 != isoTotalCodewords[version] {
		return decoded{}, fmt.Errorf("version %d: %d codewords in the matrix, standard says %d", version, len(bits)/8, isoTotalCodewords[version])
	}
	raw := make([]byte, len(bits)/8)
	for i := range raw {
		for k := 0; k < 8; k++ {
			if bits[i*8+k] {
				raw[i] |= 0x80 >> uint(k)
			}
		}
	}
	t := levelM[version]
	ecPer, nBlocks := t[0], t[1]+t[3]
	lengths := make([]int, nBlocks)
	for i := range lengths {
		lengths[i] = t[2]
		if i >= t[1] {
			lengths[i] = t[4]
		}
	}
	blocks := make([][]byte, nBlocks)
	idx := 0
	for i := 0; ; i++ {
		any := false
		for b := range blocks {
			if i < lengths[b] {
				blocks[b] = append(blocks[b], raw[idx])
				idx++
				any = true
			}
		}
		if !any {
			break
		}
	}
	var data []byte
	for b := range blocks {
		data = append(data, blocks[b]...)
	}
	for i := 0; i < ecPer; i++ {
		for b := range blocks {
			blocks[b] = append(blocks[b], raw[idx])
			idx++
		}
	}
	for b := range blocks {
		if !syndromesZero(blocks[b], ecPer) {
			return decoded{}, fmt.Errorf("block %d fails the Reed-Solomon check", b)
		}
	}
	// Parse a single byte-mode segment.
	pos := 0
	read := func(n int) int {
		v := 0
		for i := 0; i < n; i++ {
			v = v<<1 | int(data[pos/8]>>uint(7-pos%8)&1)
			pos++
		}
		return v
	}
	if read(4) != 0b0100 {
		return decoded{}, errors.New("not byte mode")
	}
	countBits := 8
	if version >= 10 {
		countBits = 16
	}
	count := read(countBits)
	out := make([]byte, count)
	for i := range out {
		out[i] = byte(read(8))
	}
	return decoded{version: version, mask: mask, data: out}, nil
}

func TestTablesAgainstStandard(t *testing.T) {
	for v := 1; v <= 40; v++ {
		s := spec(v)
		total := s.totalDataCodewords + (s.g1Blocks+s.g2Blocks)*s.ecPerBlock
		if total != isoTotalCodewords[v] || rawDataModules(v)/8 != total {
			t.Errorf("version %d: table %d, standard %d, modules/8 %d", v, total, isoTotalCodewords[v], rawDataModules(v)/8)
		}
		got := AlignmentPositions(v)
		want := isoAlignment[v]
		if fmt.Sprint(got) != fmt.Sprint(want) && !(v == 1 && len(got) == 0) {
			t.Errorf("version %d alignment %v, want %v", v, got, want)
		}
		// Every module not marked as a function module by the independent map carries data.
		b := newBuilder(v)
		b.drawFunctionPatterns()
		free := 0
		fn := functionMap(Size(v), v)
		for r := 0; r < Size(v); r++ {
			for c := 0; c < Size(v); c++ {
				if b.function[r][c] != fn[r][c] {
					t.Fatalf("version %d: function map differs at row %d col %d", v, r, c)
				}
				if !fn[r][c] {
					free++
				}
			}
		}
		if free != rawDataModules(v) {
			t.Errorf("version %d: %d free modules, formula %d", v, free, rawDataModules(v))
		}
	}
	for mask, want := range isoFormatM {
		if got := fmt.Sprintf("%015b", formatBits(mask)); got != want {
			t.Errorf("format word mask %d = %s, want %s", mask, got, want)
		}
	}
	// Version information words from the standard's annex D.
	for v, want := range map[int]int{7: 0x07C94, 8: 0x085BC, 21: 0x15683, 40: 0x28C69} {
		if got := versionBits(v); got != want {
			t.Errorf("version word %d = %05X, want %05X", v, got, want)
		}
	}
}

func loadFixture(t *testing.T, path string) ([]byte, [][]bool) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	sc.Scan()
	data, err := hex.DecodeString(sc.Text())
	if err != nil {
		t.Fatal(err)
	}
	sc.Scan()
	size, _ := strconv.Atoi(sc.Text())
	var m [][]bool
	for sc.Scan() {
		row, err := hex.DecodeString(sc.Text())
		if err != nil {
			t.Fatal(err)
		}
		bits := make([]bool, size)
		for c := 0; c < size; c++ {
			bits[c] = row[c/8]>>uint(7-c%8)&1 == 1
		}
		m = append(m, bits)
	}
	if len(m) != size {
		t.Fatalf("%s: %d rows, want %d", path, len(m), size)
	}
	return data, m
}

// TestMatchesLibqrencode compares with symbols generated by libqrencode 4.1.1
// (`qrencode -l M -8 -m 0 -t ASCII`) for every version 1–40. libqrencode may pick a different
// mask (penalty implementations differ in details), so the reference's mask is read from its
// format information and the encoder is run with that mask: the matrices must then be identical.
func TestMatchesLibqrencode(t *testing.T) {
	files, _ := filepath.Glob("testdata/*.txt")
	if len(files) < 40 {
		t.Fatalf("expected reference fixtures, found %d", len(files))
	}
	versions := map[int]bool{}
	for _, path := range files {
		data, ref := loadFixture(t, path)
		d, err := decode(ref)
		if err != nil {
			t.Fatalf("%s: reference does not decode: %v", path, err)
		}
		if !bytes.Equal(d.data, data) {
			t.Fatalf("%s: independent decoder misreads the reference", path)
		}
		auto, err := Encode(data)
		if err != nil {
			t.Fatal(err)
		}
		if auto.Version != d.version {
			t.Errorf("%s: version %d, libqrencode %d", path, auto.Version, d.version)
		}
		code, err := EncodeWithMask(data, d.mask)
		if err != nil {
			t.Fatal(err)
		}
		for r := range ref {
			for c := range ref[r] {
				if ref[r][c] != code.Modules[r][c] {
					t.Fatalf("%s (version %d, mask %d): module row %d col %d differs", path, d.version, d.mask, r, c)
				}
			}
		}
		versions[d.version] = true
	}
	for v := 1; v <= 40; v++ {
		if !versions[v] {
			t.Errorf("no reference for version %d", v)
		}
	}
}

func TestRoundTripRandomPayloads(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 300; i++ {
		n := rng.Intn(2332)
		if i < 60 {
			n = rng.Intn(600) // the pairing payload range gets extra coverage
		}
		data := make([]byte, n)
		rng.Read(data)
		code, err := Encode(data)
		if err != nil {
			t.Fatal(err)
		}
		d, err := decode(code.Modules)
		if err != nil {
			t.Fatalf("length %d: %v", n, err)
		}
		if !bytes.Equal(d.data, data) || d.mask != code.Mask || d.version != code.Version {
			t.Fatalf("length %d: round trip mismatch", n)
		}
	}
	if _, err := Encode(make([]byte, 2332)); err != ErrTooLong {
		t.Fatal("over-long data accepted")
	}
}

func TestRender(t *testing.T) {
	code, _ := Encode([]byte("zetru"))
	plain := code.Render(false)
	lines := strings.Split(strings.TrimSuffix(plain, "\n"), "\n")
	if len(lines) != (code.Size+8+1)/2 {
		t.Fatalf("%d lines for size %d", len(lines), code.Size)
	}
	for _, l := range lines {
		if n := len([]rune(l)); n != code.Size+8 {
			t.Fatalf("line width %d", n)
		}
	}
	if !strings.Contains(code.Render(true), "\x1b[30;107m") {
		t.Fatal("ansi colours missing")
	}
}

// TestRenderRoundTrip parses the terminal rendering back into modules and decodes it, for both
// modes: what the operator scans is exactly the encoded symbol, with a light quiet zone.
func TestRenderRoundTrip(t *testing.T) {
	payload := []byte("zetru://pair?v=1&d=" + strings.Repeat("eyJ2IjoxfQ", 50))
	code, err := Encode(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, ansi := range []bool{true, false} {
		text := code.Render(ansi)
		text = strings.ReplaceAll(strings.ReplaceAll(text, "\x1b[30;107m", ""), "\x1b[0m", "")
		lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
		n := code.Size + 8
		grid := make([][]bool, len(lines)*2)
		for i := range grid {
			grid[i] = make([]bool, n)
		}
		for li, line := range lines {
			for x, ch := range []rune(line) {
				var top, bottom bool // ink
				switch ch {
				case '█':
					top, bottom = true, true
				case '▀':
					top = true
				case '▄':
					bottom = true
				}
				dark := func(ink bool) bool { return ink == ansi } // plain mode draws light modules
				grid[2*li][x], grid[2*li+1][x] = dark(top), dark(bottom)
			}
		}
		m := make([][]bool, code.Size)
		for y := 0; y < n; y++ {
			for x := 0; x < n; x++ {
				inside := y >= 4 && x >= 4 && y < 4+code.Size && x < 4+code.Size
				if !inside && grid[y][x] {
					t.Fatalf("ansi=%v: quiet zone not light at %d,%d", ansi, x, y)
				}
				if inside {
					if m[y-4] == nil {
						m[y-4] = make([]bool, code.Size)
					}
					m[y-4][x-4] = grid[y][x]
				}
			}
		}
		d, err := decode(m)
		if err != nil || !bytes.Equal(d.data, payload) {
			t.Fatalf("ansi=%v: rendered symbol does not decode: %v", ansi, err)
		}
	}
}

// TestWritePNG writes PNGs for an external decode check when ZETRU_QR_PNG_DIR is set
// (see DECISIONS.md: checked with Apple's Vision barcode detector).
func TestWritePNG(t *testing.T) {
	dir := os.Getenv("ZETRU_QR_PNG_DIR")
	if dir == "" {
		t.Skip("ZETRU_QR_PNG_DIR not set")
	}
	payloads := map[string]string{
		"short":   "zetru",
		"pairing": "zetru://pair?v=1&d=" + strings.Repeat("eyJ2IjoxLCJ1cmxzIjpbImh0dHBzOi8vMTkyLjE2OC4xLjI6ODQ0MyJdfQ", 8),
		"v40":     strings.Repeat("0123456789abcdef", 145),
	}
	for name, p := range payloads {
		code, err := Encode([]byte(p))
		if err != nil {
			t.Fatal(err)
		}
		const scale, quiet = 6, 4
		n := (code.Size + 2*quiet) * scale
		img := image.NewGray(image.Rect(0, 0, n, n))
		for y := 0; y < n; y++ {
			for x := 0; x < n; x++ {
				mx, my := x/scale-quiet, y/scale-quiet
				c := color.Gray{Y: 255}
				if mx >= 0 && my >= 0 && mx < code.Size && my < code.Size && code.Modules[my][mx] {
					c = color.Gray{Y: 0}
				}
				img.SetGray(x, y, c)
			}
		}
		f, _ := os.Create(filepath.Join(dir, name+".png"))
		_ = png.Encode(f, img)
		_ = f.Close()
		_ = os.WriteFile(filepath.Join(dir, name+".txt"), []byte(p), 0o600)
	}
}
