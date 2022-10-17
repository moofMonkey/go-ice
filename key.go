package ice

import "encoding/binary"

const BlockSize = 8

var iceSMod = [4][4]int{
	{333, 313, 505, 369},
	{379, 375, 319, 391},
	{361, 445, 451, 397},
	{397, 425, 395, 505},
}

var iceSXor = [4][4]int{
	{0x83, 0x85, 0x9b, 0xcd},
	{0xcc, 0xa7, 0xad, 0x41},
	{0x4b, 0x2e, 0xd4, 0x33},
	{0xea, 0xcb, 0x2e, 0x04},
}

var icePBox = [32]uint32{
	0x00000001, 0x00000080, 0x00000400, 0x00002000,
	0x00080000, 0x00200000, 0x01000000, 0x40000000,
	0x00000008, 0x00000020, 0x00000100, 0x00004000,
	0x00010000, 0x00800000, 0x04000000, 0x20000000,
	0x00000004, 0x00000010, 0x00000200, 0x00008000,
	0x00020000, 0x00400000, 0x08000000, 0x10000000,
	0x00000002, 0x00000040, 0x00000800, 0x00001000,
	0x00040000, 0x00100000, 0x02000000, 0x80000000,
}

var iceKeyRot = [16]int{
	0, 1, 2, 3, 2, 1, 3, 0,
	1, 3, 2, 0, 3, 1, 0, 2,
}

func gfMult(a uint32, b uint32, m uint32) uint32 {
	var res uint32
	for b != 0 {
		if (b & 1) == 1 {
			res ^= a
		}
		a <<= 1
		b >>= 1

		if a >= 256 {
			a ^= m
		}
	}
	return res
}

func gfExp7(b uint32, m uint32) uint32 {
	if b == 0 {
		return 0
	}
	var x uint32
	x = gfMult(b, b, m)
	x = gfMult(b, x, m)
	x = gfMult(x, x, m)
	return gfMult(b, x, m)
}

func icePerm32(x uint32) uint32 {
	var res uint32
	i := 0

	for x != 0 {
		if (x & 1) == 1 {
			res |= icePBox[i]
		}
		i++
		x >>= 1
	}
	return res
}

func iceSBoxesInit() (res [4][1024]uint32) {
	for i := 0; i < 1024; i++ {
		col := (i >> 1) & 0xFF
		row := (i & 1) | ((i & 0x200) >> 8)

		for j := 0; j < 4; j++ {
			res[j][i] = icePerm32(gfExp7(
				uint32(col^iceSXor[j][row]),
				uint32(iceSMod[j][row]),
			) << (24 - j*8))
		}
	}
	return
}

var iceSBox = iceSBoxesInit()

func iceF(p uint32, sk [3]uint32) uint32 {
	tl := ((p >> 16) & 0x3ff) | (((p >> 14) | (p << 18)) & 0xffc00)
	tr := (p & 0x3ff) | ((p << 2) & 0xffc00)
	al := sk[2] & (tl ^ tr)
	ar := al ^ tr

	al ^= tl
	al ^= sk[0]
	ar ^= sk[1]

	return iceSBox[0][al>>10] |
		iceSBox[1][al&0x3ff] |
		iceSBox[2][ar>>10] |
		iceSBox[3][ar&0x3ff]
}

type Key struct {
	keysched [16][3]uint32
}

func (key *Key) Encrypt(data []byte) {
	l := binary.BigEndian.Uint32(data[:])
	r := binary.BigEndian.Uint32(data[4:])

	for i := 0; i < 16; i += 2 {
		l ^= iceF(r, key.keysched[i])
		r ^= iceF(l, key.keysched[i+1])
	}

	binary.BigEndian.PutUint32(data[:], r)
	binary.BigEndian.PutUint32(data[4:], l)
}

func (key *Key) Decrypt(data []byte) {
	l := binary.BigEndian.Uint32(data[:])
	r := binary.BigEndian.Uint32(data[4:])

	for i := 15; i > 0; i -= 2 {
		l ^= iceF(r, key.keysched[i])
		r ^= iceF(l, key.keysched[i-1])
	}

	binary.BigEndian.PutUint32(data[:], r)
	binary.BigEndian.PutUint32(data[4:], l)
}

func (key *Key) scheduleBuild(kb *[4]uint16, n int, keyRot []int) {
	for i := 0; i < 8; i++ {
		kr := keyRot[i]
		isk := &key.keysched[n+i]

		for j := 0; j < 3; j++ {
			isk[j] = 0
		}

		for j := 0; j < 15; j++ {
			currSk := &isk[j%3]

			for k := 0; k < 4; k++ {
				currKb := &kb[(kr+k)&3]
				bit := uint32(*currKb & 1)

				*currSk = (*currSk << 1) | bit
				*currKb = uint16(uint32(*currKb>>1) | ((bit ^ 1) << 15))
			}
		}
	}
}

func (key *Key) SetSeed(seed [8]byte) {
	var kb [4]uint16
	for j := 0; j < 4; j++ {
		kb[3-j] = (uint16(seed[j*2]) << 8) | uint16(seed[j*2+1])
	}
	key.scheduleBuild(&kb, 0, iceKeyRot[:])
	key.scheduleBuild(&kb, 8, iceKeyRot[8:])
}
