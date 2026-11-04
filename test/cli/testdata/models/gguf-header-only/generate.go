// generate writes header.gguf: the header of a GGUF model shaped like Qwen2.5-0.5B-Instruct at Q2_K (290
// tensors declaring about 175 MB of data), padded to the tensor data alignment. Tests extend a copy to a
// model's size as a sparse file, which stands in for the full model without storing its data.
//
// This file lives under testdata/ so the Go build system ignores it. Run it when changing the fixture:
//
//	go run ./testdata/models/gguf-header-only/generate.go ./testdata/models/gguf-header-only/header.gguf
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

const (
	typeUint32 = 4
	typeString = 8
	typeArray  = 9

	ggmlF32 = 0
	ggmlQ2K = 10
	ggmlQ3K = 11
	ggmlQ4K = 12
	fileQ2K = 10
)

type tensor struct {
	name string
	typ  uint32
	dims []uint64
}

type writer struct{ bytes.Buffer }

func (w *writer) le(v any) { _ = binary.Write(w, binary.LittleEndian, v) }

func (w *writer) str(s string) {
	w.le(uint64(len(s)))
	w.WriteString(s)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: generate <output path>")
		os.Exit(1)
	}

	const (
		hidden = 896
		kvDim  = 128
		ffn    = 4864
		vocab  = 151936
		layers = 24
	)
	tensors := []tensor{{"token_embd.weight", ggmlQ4K, []uint64{hidden, vocab}}}
	for i := range layers {
		blk := func(n string) string { return fmt.Sprintf("blk.%d.%s", i, n) }
		tensors = append(tensors,
			tensor{blk("attn_norm.weight"), ggmlF32, []uint64{hidden}},
			tensor{blk("attn_q.weight"), ggmlQ2K, []uint64{hidden, hidden}},
			tensor{blk("attn_q.bias"), ggmlF32, []uint64{hidden}},
			tensor{blk("attn_k.weight"), ggmlQ2K, []uint64{hidden, kvDim}},
			tensor{blk("attn_k.bias"), ggmlF32, []uint64{kvDim}},
			tensor{blk("attn_v.weight"), ggmlQ3K, []uint64{hidden, kvDim}},
			tensor{blk("attn_v.bias"), ggmlF32, []uint64{kvDim}},
			tensor{blk("attn_output.weight"), ggmlQ3K, []uint64{hidden, hidden}},
			tensor{blk("ffn_norm.weight"), ggmlF32, []uint64{hidden}},
			tensor{blk("ffn_gate.weight"), ggmlQ2K, []uint64{hidden, ffn}},
			tensor{blk("ffn_up.weight"), ggmlQ2K, []uint64{hidden, ffn}},
			tensor{blk("ffn_down.weight"), ggmlQ3K, []uint64{ffn, hidden}},
		)
	}
	tensors = append(tensors, tensor{"output_norm.weight", ggmlF32, []uint64{hidden}})

	var w writer
	w.le(uint32(0x46554747)) // "GGUF"
	w.le(uint32(3))
	w.le(uint64(len(tensors)))
	w.le(uint64(6)) // metadata KV count

	w.str("general.architecture")
	w.le(uint32(typeString))
	w.str("qwen2")
	w.str("general.name")
	w.le(uint32(typeString))
	w.str("qwen2.5-0.5b-instruct")
	w.str("general.license")
	w.le(uint32(typeString))
	w.str("apache-2.0")
	w.str("general.file_type")
	w.le(uint32(typeUint32))
	w.le(uint32(fileQ2K))
	w.str("qwen2.block_count")
	w.le(uint32(typeUint32))
	w.le(uint32(layers))
	// a vocabulary the parser skips over
	w.str("tokenizer.ggml.tokens")
	w.le(uint32(typeArray))
	w.le(uint32(typeString))
	w.le(uint64(3))
	for _, tok := range []string{"!", "\"", "#"} {
		w.str(tok)
	}

	var offset uint64
	for _, t := range tensors {
		w.str(t.name)
		w.le(uint32(len(t.dims)))
		for _, d := range t.dims {
			w.le(d)
		}
		w.le(t.typ)
		w.le(offset)
		offset += 1 << 20 // not used by syft; real offsets depend on each type's block size
	}

	// pad to the default 32-byte alignment, where the tensor data starts
	w.Write(make([]byte, (32-w.Len()%32)%32))

	if err := os.WriteFile(os.Args[1], w.Bytes(), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
