package ai

import (
	"bytes"
	"encoding/binary"
)

// GGUF type constants for test builder
// https://github.com/ggml-org/ggml/blob/master/docs/gguf.md
const (
	ggufMagic       = 0x46554747 // "GGUF" in little-endian
	ggufTypeUint8   = 0
	ggufTypeInt8    = 1
	ggufTypeUint16  = 2
	ggufTypeInt16   = 3
	ggufTypeUint32  = 4
	ggufTypeInt32   = 5
	ggufTypeFloat32 = 6
	ggufTypeBool    = 7
	ggufTypeString  = 8
	ggufTypeArray   = 9
	ggufTypeUint64  = 10
	ggufTypeInt64   = 11
	ggufTypeFloat64 = 12
)

// testGGUFBuilder helps build GGUF files for testing
type testGGUFBuilder struct {
	buf         *bytes.Buffer
	version     uint32
	tensorCount uint64
	kvPairs     []testKVPair
}

type testKVPair struct {
	key       string
	valueType uint32
	value     interface{}
}

func newTestGGUFBuilder() *testGGUFBuilder {
	return &testGGUFBuilder{
		buf:         new(bytes.Buffer),
		version:     3,
		tensorCount: 0,
		kvPairs:     []testKVPair{},
	}
}

func (b *testGGUFBuilder) withVersion(v uint32) *testGGUFBuilder {
	b.version = v
	return b
}

func (b *testGGUFBuilder) withTensorCount(count uint64) *testGGUFBuilder {
	b.tensorCount = count
	return b
}

func (b *testGGUFBuilder) withStringKV(key, value string) *testGGUFBuilder {
	b.kvPairs = append(b.kvPairs, testKVPair{key: key, valueType: ggufTypeString, value: value})
	return b
}

func (b *testGGUFBuilder) withUint64KV(key string, value uint64) *testGGUFBuilder {
	b.kvPairs = append(b.kvPairs, testKVPair{key: key, valueType: ggufTypeUint64, value: value})
	return b
}

func (b *testGGUFBuilder) withUint32KV(key string, value uint32) *testGGUFBuilder {
	b.kvPairs = append(b.kvPairs, testKVPair{key: key, valueType: ggufTypeUint32, value: value})
	return b
}

func (b *testGGUFBuilder) writeString(s string) {
	binary.Write(b.buf, binary.LittleEndian, uint64(len(s)))
	b.buf.WriteString(s)
}

func (b *testGGUFBuilder) build() []byte {
	// Write magic number "GGUF"
	binary.Write(b.buf, binary.LittleEndian, uint32(ggufMagic))

	// Write version
	binary.Write(b.buf, binary.LittleEndian, b.version)

	// Write tensor count
	binary.Write(b.buf, binary.LittleEndian, b.tensorCount)

	// Write KV count
	binary.Write(b.buf, binary.LittleEndian, uint64(len(b.kvPairs)))

	// Write KV pairs
	for _, kv := range b.kvPairs {
		// Write key
		b.writeString(kv.key)
		// Write value type
		binary.Write(b.buf, binary.LittleEndian, kv.valueType)
		// Write value based on type
		switch kv.valueType {
		case ggufTypeString:
			b.writeString(kv.value.(string))
		case ggufTypeUint32:
			binary.Write(b.buf, binary.LittleEndian, kv.value.(uint32))
		case ggufTypeUint64:
			binary.Write(b.buf, binary.LittleEndian, kv.value.(uint64))
		case ggufTypeUint8:
			binary.Write(b.buf, binary.LittleEndian, kv.value.(uint8))
		case ggufTypeInt32:
			binary.Write(b.buf, binary.LittleEndian, kv.value.(int32))
		case ggufTypeBool:
			var v uint8
			if kv.value.(bool) {
				v = 1
			}
			binary.Write(b.buf, binary.LittleEndian, v)
		}
	}

	return b.buf.Bytes()
}

// buildInvalidMagic creates a file with invalid magic number
func (b *testGGUFBuilder) buildInvalidMagic() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(0x12345678))
	return buf.Bytes()
}
