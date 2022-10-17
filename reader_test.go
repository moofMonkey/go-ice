package ice

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/require"
	"io"
	"math/rand"
	"testing"
)

func TestReader(t *testing.T) {
	var seed [8]byte
	seedParsed, _ := hex.DecodeString("52fdfc072182654f")
	copy(seed[:], seedParsed)
	data, _ := hex.DecodeString("0f796dc0533d642816c3a5c70b96c5a6")
	decryptedExpect, _ := hex.DecodeString("645f74db317619439f2e5f373b2342fd")
	var key Key
	key.SetSeed(seed)
	t.Run("FullRead", func(t *testing.T) {
		tmp := make([]byte, len(data))
		for i := 1; i <= len(data); i++ {
			t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
				rand.Read(tmp) // ensure no partial reads/etc
				n, err := io.ReadFull(NewReader(bytes.NewReader(data), &key), tmp[:i])
				require.NoError(t, err)
				require.Equal(t, i, n)
				require.Equal(t, decryptedExpect[:i], tmp[:i])
			})
		}
	})
	t.Run("PartialRead", func(t *testing.T) {
		tmp := make([]byte, len(data))
		rand.Read(tmp) // ensure no partial reads/etc
		remaining := len(data)
		r := NewReader(bytes.NewReader(data), &key)
		for step := 1; step <= len(data); step++ {
			readSize := step
			if readSize > remaining {
				readSize = remaining
			}
			if readSize == 0 {
				break
			}
			n, err := io.ReadFull(
				r,
				tmp[:readSize],
			)
			require.NoError(t, err)
			require.Equal(t, readSize, n)
			require.Equal(t, decryptedExpect[len(data)-remaining:len(data)-remaining+readSize], tmp[:readSize])
			remaining -= n
		}
	})
	t.Run("ExpectedOEF", func(t *testing.T) {
		tmp := make([]byte, len(data))
		r := NewReader(bytes.NewReader(data), &key)
		n, err := io.ReadFull(r, tmp)
		require.NoError(t, err)
		require.Equal(t, len(tmp), n)
		n, err = io.ReadFull(r, tmp)
		require.Equal(t, io.EOF, err)
		require.Equal(t, 0, n)
	})
	t.Run("UnexpectedEOFRead", func(t *testing.T) {
		tmp := make([]byte, len(data)+1)
		r := NewReader(bytes.NewReader(data), &key)
		n, err := io.ReadFull(r, tmp)
		require.Equal(t, io.ErrUnexpectedEOF, err)
		require.Equal(t, len(data), n)
	})
	t.Run("UnexpectedEOFData", func(t *testing.T) {
		tmp := make([]byte, len(data))
		r := NewReader(bytes.NewReader(data[:len(data)-1]), &key)
		n, err := io.ReadFull(r, tmp)
		require.Equal(t, io.ErrUnexpectedEOF, err)
		require.Equal(t, len(data)-BlockSize, n)
	})
}

func BenchmarkReader(b *testing.B) {
	var seed [8]byte
	rand.Read(seed[:])
	data := make([]byte, BlockSize*1024)
	rand.Read(data)
	tmp := make([]byte, len(data))
	var key Key
	key.SetSeed(seed)
	dataReader := bytes.NewReader(data)
	r := NewReader(dataReader, &key)
	b.Run("Read", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(data)))
		for i := 0; i < b.N; i++ {
			_, _ = dataReader.Seek(0, 0)
			_, _ = r.Read(tmp)
		}
	})
}
