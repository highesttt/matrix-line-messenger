package ltsm

import (
	_ "embed"
	"fmt"
)

// memInit is a snapshot of the wasm linear memory right after instantiation.
//
// We embed it so the Go port can reference the same constant lookup tables by
// offset (as the wasm code does), without shipping wasm at runtime.
//
//go:embed data/mem_init_0_4m.bin
var memInit []byte

const memInitLen = 4 * 1024 * 1024

func init() {
	if len(memInit) != memInitLen {
		panic(fmt.Sprintf("ltsm: embedded memInit length=%d, want %d", len(memInit), memInitLen))
	}
}

func memByte(off int) byte {
	return memInit[off]
}

