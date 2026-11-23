// Package qr is a small QR Code encoder (ISO/IEC 18004): byte mode, error-correction level M,
// versions 1–40, Reed–Solomon over GF(256) with the primitive polynomial 0x11D, all eight masks
// with the standard penalty rules, and BCH-coded format and version information.
//
// It exists so that the gateway can print the pairing code in the terminal without a third-party
// dependency. The tests check it against reference symbols produced by libqrencode and with an
// independent decoder.
package qr

import (
	"errors"
	"strings"
)

// blockSpec describes the error-correction blocks of one version at level M.
type blockSpec struct {
	ecPerBlock         int
	g1Blocks, g1Data   int
	g2Blocks, g2Data   int
	totalDataCodewords int
}

// levelM holds, for versions 1–40 at error-correction level M, the number of EC codewords per
// block and the two block groups (count, data codewords per block). Source: ISO/IEC 18004 table 9.
var levelM = [41][5]int{
	{},
	{10, 1, 16, 0, 0}, {16, 1, 28, 0, 0}, {26, 1, 44, 0, 0}, {18, 2, 32, 0, 0}, {24, 2, 43, 0, 0},
	{16, 4, 27, 0, 0}, {18, 4, 31, 0, 0}, {22, 2, 38, 2, 39}, {22, 3, 36, 2, 37}, {26, 4, 43, 1, 44},
	{30, 1, 50, 4, 51}, {22, 6, 36, 2, 37}, {22, 8, 37, 1, 38}, {24, 4, 40, 5, 41}, {24, 5, 41, 5, 42},
	{28, 7, 45, 3, 46}, {28, 10, 46, 1, 47}, {26, 9, 43, 4, 44}, {26, 3, 44, 11, 45}, {26, 3, 41, 13, 42},
	{26, 17, 42, 0, 0}, {28, 17, 46, 0, 0}, {28, 4, 47, 14, 48}, {28, 6, 45, 14, 46}, {28, 8, 47, 13, 48},
	{28, 19, 46, 4, 47}, {28, 22, 45, 3, 46}, {28, 3, 45, 23, 46}, {28, 21, 45, 7, 46}, {28, 19, 47, 10, 48},
	{28, 2, 46, 29, 47}, {28, 10, 46, 23, 47}, {28, 14, 46, 21, 47}, {28, 14, 46, 23, 47}, {28, 12, 47, 26, 48},
	{28, 6, 47, 34, 48}, {28, 29, 46, 14, 47}, {28, 13, 46, 32, 47}, {28, 40, 47, 7, 48}, {28, 18, 47, 31, 48},
}

func spec(version int) blockSpec {
	t := levelM[version]
	return blockSpec{ecPerBlock: t[0], g1Blocks: t[1], g1Data: t[2], g2Blocks: t[3], g2Data: t[4],
		totalDataCodewords: t[1]*t[2] + t[3]*t[4]}
}

// Size returns the number of modules per side of a version.
func Size(version int) int { return version*4 + 17 }

// rawDataModules is the number of modules available for codewords and remainder bits.
func rawDataModules(version int) int {
	n := (16*version+128)*version + 64
	if version >= 2 {
		align := version/7 + 2
		n -= (25*align-10)*align - 55
		if version >= 7 {
			n -= 36
		}
	}
	return n
}

// AlignmentPositions returns the row/column centres of the alignment patterns.
func AlignmentPositions(version int) []int {
	if version == 1 {
		return nil
	}
	count := version/7 + 2
	var step int
	if version == 32 {
		step = 26
	} else {
		step = (version*4 + count*2 + 1) / (count*2 - 2) * 2
	}
	out := make([]int, count)
	out[0] = 6
	for i, pos := count-1, Size(version)-7; i >= 1; i, pos = i-1, pos-step {
		out[i] = pos
	}
	return out
}

// Code is an encoded symbol. Modules[y][x] is true for a dark module.
type Code struct {
	Version int
	Mask    int
	Size    int
	Modules [][]bool
}

// ErrTooLong is returned when the data does not fit version 40 at level M.
var ErrTooLong = errors.New("qr: data too long")

// Encode encodes data in byte mode at level M using the smallest version and the mask with the
// lowest penalty.
func Encode(data []byte) (*Code, error) { return encode(data, -1) }

// EncodeWithMask encodes with a fixed mask (0–7); used by the tests to compare with references.
func EncodeWithMask(data []byte, mask int) (*Code, error) {
	if mask < 0 || mask > 7 {
		return nil, errors.New("qr: mask out of range")
	}
	return encode(data, mask)
}

func encode(data []byte, forcedMask int) (*Code, error) {
	version := 0
	for v := 1; v <= 40; v++ {
		countBits := 8
		if v >= 10 {
			countBits = 16
		}
		if 4+countBits+8*len(data) <= spec(v).totalDataCodewords*8 {
			version = v
			break
		}
	}
	if version == 0 {
		return nil, ErrTooLong
	}
	codewords := addErrorCorrection(dataCodewords(data, version), version)
	base := newBuilder(version)
	base.drawFunctionPatterns()
	base.drawCodewords(codewords)

	best, bestPenalty := -1, 0
	var bestModules [][]bool
	for mask := 0; mask < 8; mask++ {
		if forcedMask >= 0 && mask != forcedMask {
			continue
		}
		b := base.clone()
		b.applyMask(mask)
		b.drawFormatBits(mask)
		p := b.penalty()
		if best < 0 || p < bestPenalty {
			best, bestPenalty, bestModules = mask, p, b.modules
		}
	}
	return &Code{Version: version, Mask: best, Size: Size(version), Modules: bestModules}, nil
}

// dataCodewords builds the data bit stream: mode 0100, character count, bytes, terminator, bit
// padding and the alternating pad codewords 0xEC 0x11.
func dataCodewords(data []byte, version int) []byte {
	capacity := spec(version).totalDataCodewords
	var bits bitBuffer
	bits.append(0b0100, 4)
	if version < 10 {
		bits.append(uint32(len(data)), 8)
	} else {
		bits.append(uint32(len(data)), 16)
	}
	for _, b := range data {
		bits.append(uint32(b), 8)
	}
	terminator := capacity*8 - bits.n
	if terminator > 4 {
		terminator = 4
	}
	bits.append(0, terminator)
	if rem := bits.n % 8; rem != 0 {
		bits.append(0, 8-rem)
	}
	out := bits.bytes()
	for pad := byte(0xEC); len(out) < capacity; pad ^= 0xEC ^ 0x11 {
		out = append(out, pad)
	}
	return out
}

type bitBuffer struct {
	data []byte
	n    int
}

func (b *bitBuffer) append(value uint32, count int) {
	for i := count - 1; i >= 0; i-- {
		if b.n%8 == 0 {
			b.data = append(b.data, 0)
		}
		if (value>>uint(i))&1 == 1 {
			b.data[b.n/8] |= 0x80 >> uint(b.n%8)
		}
		b.n++
	}
}

func (b *bitBuffer) bytes() []byte { return append([]byte(nil), b.data...) }

// addErrorCorrection splits the data into blocks, appends Reed–Solomon codewords per block and
// interleaves data and EC codewords.
func addErrorCorrection(data []byte, version int) []byte {
	s := spec(version)
	generator := rsGenerator(s.ecPerBlock)
	var blocks, ecs [][]byte
	offset := 0
	for i := 0; i < s.g1Blocks+s.g2Blocks; i++ {
		n := s.g1Data
		if i >= s.g1Blocks {
			n = s.g2Data
		}
		block := data[offset : offset+n]
		offset += n
		blocks = append(blocks, block)
		ecs = append(ecs, rsRemainder(block, generator))
	}
	out := make([]byte, 0, len(data)+len(blocks)*s.ecPerBlock)
	maxData := s.g1Data
	if s.g2Blocks > 0 {
		maxData = s.g2Data
	}
	for i := 0; i < maxData; i++ {
		for _, block := range blocks {
			if i < len(block) {
				out = append(out, block[i])
			}
		}
	}
	for i := 0; i < s.ecPerBlock; i++ {
		for _, ec := range ecs {
			out = append(out, ec[i])
		}
	}
	return out
}

// GF(256) arithmetic with the QR primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
var gfExp, gfLog = func() ([512]byte, [256]byte) {
	var exp [512]byte
	var log [256]byte
	x := 1
	for i := 0; i < 255; i++ {
		exp[i] = byte(x)
		log[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		exp[i] = exp[i-255]
	}
	return exp, log
}()

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// rsGenerator returns the coefficients (highest degree first, leading 1 omitted) of
// g(x) = (x - α^0)(x - α^1)…(x - α^(degree-1)).
func rsGenerator(degree int) []byte {
	g := []byte{1}
	for i := 0; i < degree; i++ {
		next := make([]byte, len(g)+1)
		for j, c := range g {
			next[j] ^= c
			next[j+1] ^= gfMul(c, gfExp[i])
		}
		g = next
	}
	return g[1:]
}

// rsRemainder returns data(x)·x^n mod g(x).
func rsRemainder(data, generator []byte) []byte {
	rem := make([]byte, len(generator))
	for _, b := range data {
		factor := b ^ rem[0]
		copy(rem, rem[1:])
		rem[len(rem)-1] = 0
		for i, c := range generator {
			rem[i] ^= gfMul(c, factor)
		}
	}
	return rem
}

// builder holds a symbol under construction.
type builder struct {
	version  int
	size     int
	modules  [][]bool
	function [][]bool
}

func newBuilder(version int) *builder {
	size := Size(version)
	b := &builder{version: version, size: size}
	b.modules = make([][]bool, size)
	b.function = make([][]bool, size)
	for i := range b.modules {
		b.modules[i] = make([]bool, size)
		b.function[i] = make([]bool, size)
	}
	return b
}

func (b *builder) clone() *builder {
	c := &builder{version: b.version, size: b.size, function: b.function}
	c.modules = make([][]bool, b.size)
	for i := range b.modules {
		c.modules[i] = append([]bool(nil), b.modules[i]...)
	}
	return c
}

func (b *builder) set(x, y int, dark bool) {
	b.modules[y][x] = dark
	b.function[y][x] = true
}

func (b *builder) drawFunctionPatterns() {
	for i := 0; i < b.size; i++ { // timing patterns
		b.set(6, i, i%2 == 0)
		b.set(i, 6, i%2 == 0)
	}
	b.drawFinder(3, 3)
	b.drawFinder(b.size-4, 3)
	b.drawFinder(3, b.size-4)
	align := AlignmentPositions(b.version)
	for i, ay := range align {
		for j, ax := range align {
			if (i == 0 && j == 0) || (i == 0 && j == len(align)-1) || (i == len(align)-1 && j == 0) {
				continue // overlaps a finder pattern
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					b.set(ax+dx, ay+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	b.drawFormatBits(0) // reserve the format areas; real bits are drawn per mask
	b.drawVersion()
}

// drawFinder draws a finder pattern with its separator centred at (cx, cy).
func (b *builder) drawFinder(cx, cy int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			x, y := cx+dx, cy+dy
			if x < 0 || x >= b.size || y < 0 || y >= b.size {
				continue
			}
			d := max(abs(dx), abs(dy))
			b.set(x, y, d != 2 && d != 4)
		}
	}
}

// formatBits returns the 15-bit format word for level M (indicator 00) and a mask.
func formatBits(mask int) int {
	data := 0b00<<3 | mask
	rem := data
	for i := 0; i < 10; i++ {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	return (data<<10 | rem) ^ 0x5412
}

func (b *builder) drawFormatBits(mask int) {
	bits := formatBits(mask)
	bit := func(i int) bool { return (bits>>uint(i))&1 == 1 }
	for i := 0; i <= 5; i++ {
		b.set(8, i, bit(i))
	}
	b.set(8, 7, bit(6))
	b.set(8, 8, bit(7))
	b.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		b.set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		b.set(b.size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		b.set(8, b.size-15+i, bit(i))
	}
	b.set(8, b.size-8, true) // dark module
}

// versionBits returns the 18-bit version word (versions ≥ 7).
func versionBits(version int) int {
	rem := version
	for i := 0; i < 12; i++ {
		rem = rem<<1 ^ (rem>>11)*0x1F25
	}
	return version<<12 | rem
}

func (b *builder) drawVersion() {
	if b.version < 7 {
		return
	}
	bits := versionBits(b.version)
	for i := 0; i < 18; i++ {
		dark := (bits>>uint(i))&1 == 1
		a, c := b.size-11+i%3, i/3
		b.set(a, c, dark)
		b.set(c, a, dark)
	}
}

// drawCodewords places the codewords in the zigzag order; remainder bits stay light.
func (b *builder) drawCodewords(codewords []byte) {
	i := 0
	total := len(codewords) * 8
	for right := b.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		upward := (right+1)&2 == 0
		for vert := 0; vert < b.size; vert++ {
			y := vert
			if upward {
				y = b.size - 1 - vert
			}
			for j := 0; j < 2; j++ {
				x := right - j
				if b.function[y][x] {
					continue
				}
				if i < total {
					b.modules[y][x] = (codewords[i/8]>>uint(7-i%8))&1 == 1
					i++
				}
			}
		}
	}
}

func maskBit(mask, x, y int) bool {
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	default:
		return ((x+y)%2+x*y%3)%2 == 0
	}
}

func (b *builder) applyMask(mask int) {
	for y := 0; y < b.size; y++ {
		for x := 0; x < b.size; x++ {
			if !b.function[y][x] && maskBit(mask, x, y) {
				b.modules[y][x] = !b.modules[y][x]
			}
		}
	}
}

// penalty evaluates the four penalty rules of ISO/IEC 18004 §7.8.3.
func (b *builder) penalty() int {
	n := b.size
	at := func(x, y int, vertical bool) bool {
		if vertical {
			return b.modules[x][y]
		}
		return b.modules[y][x]
	}
	score := 0
	for _, vertical := range []bool{false, true} {
		for y := 0; y < n; y++ {
			run := 1
			for x := 1; x <= n; x++ {
				if x < n && at(x, y, vertical) == at(x-1, y, vertical) {
					run++
					continue
				}
				if run >= 5 {
					score += 3 + run - 5 // N1
				}
				run = 1
			}
			for x := 0; x+11 <= n; x++ { // N3: 1011101 with four light modules on one side
				var pattern [11]bool
				for k := 0; k < 11; k++ {
					pattern[k] = at(x+k, y, vertical)
				}
				if matches(pattern, finderLeft) || matches(pattern, finderRight) {
					score += 40
				}
			}
		}
	}
	for y := 0; y+1 < n; y++ { // N2
		for x := 0; x+1 < n; x++ {
			c := b.modules[y][x]
			if c == b.modules[y][x+1] && c == b.modules[y+1][x] && c == b.modules[y+1][x+1] {
				score += 3
			}
		}
	}
	dark := 0
	for _, row := range b.modules {
		for _, m := range row {
			if m {
				dark++
			}
		}
	}
	total := n * n
	k := (abs(dark*20-total*10)+total-1)/total - 1 // N4: 10 per 5 % deviation from 50 %
	return score + k*10
}

var (
	finderLeft  = [11]bool{true, false, true, true, true, false, true, false, false, false, false}
	finderRight = [11]bool{false, false, false, false, true, false, true, true, true, false, true}
)

func matches(a, b [11]bool) bool { return a == b }

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// Render draws the symbol with a 4-module quiet zone using Unicode half blocks: each character is
// one module wide and two modules tall. With ansi set, the output forces black on white with
// escape codes, so it scans on dark and light terminals alike; without it, light modules are
// printed as blocks, which suits terminals with a dark background.
func (c *Code) Render(ansi bool) string {
	const quiet = 4
	n := c.Size + 2*quiet
	dark := func(x, y int) bool {
		x, y = x-quiet, y-quiet
		return x >= 0 && y >= 0 && x < c.Size && y < c.Size && c.Modules[y][x]
	}
	var sb strings.Builder
	for y := 0; y < n; y += 2 {
		if ansi {
			sb.WriteString("\x1b[30;107m")
		}
		for x := 0; x < n; x++ {
			// "ink" is what the block characters draw: dark modules in black on the forced white
			// background (ansi), or light modules on a dark terminal background (plain).
			hasBottom := y+1 < n
			top, bottom := dark(x, y), hasBottom && dark(x, y+1)
			if !ansi {
				top, bottom = !top, hasBottom && !bottom
			}
			switch {
			case top && bottom:
				sb.WriteString("█")
			case top:
				sb.WriteString("▀")
			case bottom:
				sb.WriteString("▄")
			default:
				sb.WriteString(" ")
			}
		}
		if ansi {
			sb.WriteString("\x1b[0m")
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
