package ltsm

import "fmt"

const (
	// wasm linear memory offsets (from `LINE-wasm.txt`)
	sbox2458096Off = 2458096
	const365824Off = 365824
)

// Mix66 is a direct port of wasm `func156`.
//
// It mixes two 66-byte base-8 digit arrays (values 0..7) into a new 66-byte
// base-8 digit array, using a large substitution table and a 66-byte constant
// block selected by constOff (an offset from const365824Off).
//
// This function is an internal building block for re-implementing:
// - SecureKey.deriveKey (signing key derivation)
// - Hmac.digest (request signing)
func Mix66(dst, x, y []byte, constOff int) {
	if len(dst) < 66 || len(x) < 66 || len(y) < 66 {
		panic(fmt.Sprintf("ltsm: Mix66 requires 66-byte slices (dst=%d x=%d y=%d)", len(dst), len(x), len(y)))
	}
	base := const365824Off + constOff
	var prev byte // wasm locals default to 0
	for i := 0; i < 66; i++ {
		// idx = (x[i] ^ (prev & 0xF8)) | (y[i] << 8) ^ (C[i] << 11)
		idx := uint32(x[i] ^ (prev & 0xF8))
		idx |= uint32(y[i]) << 8
		idx ^= uint32(memByte(base+i)) << 11

		prev = memByte(sbox2458096Off + int(idx))
		dst[i] = prev & 0x07
	}
}

