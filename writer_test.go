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

type limitWriter struct {
	dst   io.Writer
	limit int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.limit == 0 {
		return 0, io.ErrShortWrite
	}
	var err error
	lp := len(p)
	if lp > l.limit {
		lp = l.limit
		p = p[:l.limit]
		err = io.ErrShortWrite
	}
	l.limit -= lp
	_, errWrite := l.dst.Write(p)
	if errWrite != nil {
		err = errWrite
	}
	return lp, err
}

func TestWriter(t *testing.T) {
	var seed [8]byte
	seedParsed, _ := hex.DecodeString("52fdfc072182654f")
	copy(seed[:], seedParsed)
	data, _ := hex.DecodeString("645f74db317619439f2e5f373b2342fd")
	encryptedExpect, _ := hex.DecodeString("0f796dc0533d642816c3a5c70b96c5a6")
	var key Key
	key.SetSeed(seed)
	t.Run("FullWrite", func(t *testing.T) {
		for i := 1; i <= len(data); i++ {
			t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
				b := bytes.NewBuffer(nil)
				b.Grow(i)
				n, err := NewWriter(b, &key).Write(data[:i])
				require.NoError(t, err)
				require.Equal(t, i, n)
				expectedOutput := n - (n % BlockSize)
				require.Equal(t, encryptedExpect[:expectedOutput], b.Bytes())
			})
		}
	})
	t.Run("PartialWrite", func(t *testing.T) {
		remaining := len(data)
		b := bytes.NewBuffer(nil)
		b.Grow(len(data))
		w := NewWriter(b, &key)
		for step := 1; step <= len(data); step++ {
			writeSize := step
			if writeSize > remaining {
				writeSize = remaining
			}
			if writeSize == 0 {
				break
			}
			n, err := w.Write(data[len(data)-remaining : len(data)-remaining+writeSize])
			require.NoError(t, err)
			require.Equal(t, writeSize, n)
			expectedOutput := len(data) - remaining + writeSize
			expectedOutput -= expectedOutput % BlockSize
			require.Equal(t, encryptedExpect[:expectedOutput], b.Bytes()[:])
			remaining -= n
		}
	})
	t.Run("PartialWriteFlush", func(t *testing.T) {
		b := bytes.NewBuffer(nil)
		b.Grow(len(data))
		w := NewWriter(b, &key)
		n, err := w.Write(data[:len(data)-1])
		require.NoError(t, err)
		require.Equal(t, len(data)-1, n)
		require.NoError(t, w.Flush())
		require.Equal(t, len(data), b.Len())

		decrypted, err := io.ReadAll(NewReader(bytes.NewReader(b.Bytes()), &key))
		require.NoError(t, err)
		require.Equal(t, len(data), len(decrypted))
		require.Equal(t, data[:len(data)-1], decrypted[:len(data)-1])
		require.Equal(t, byte(0), decrypted[len(data)-1])
	})
	t.Run("FullWriteFlush", func(t *testing.T) {
		b := bytes.NewBuffer(nil)
		b.Grow(len(data))
		w := NewWriter(b, &key)
		n, err := w.Write(data)
		require.NoError(t, err)
		require.Equal(t, len(data), n)
		require.NoError(t, w.Flush())
		require.Equal(t, len(data), b.Len())

		decrypted, err := io.ReadAll(NewReader(bytes.NewReader(b.Bytes()), &key))
		require.NoError(t, err)
		require.Equal(t, len(data), len(decrypted))
		require.Equal(t, data, decrypted)
	})
	t.Run("WriteOverCache", func(t *testing.T) {
		dataBig := make([]byte, len(data)*256)
		for i := 0; i < 256; i++ {
			copy(dataBig[len(data)*i:], data)
		}
		b := bytes.NewBuffer(nil)
		b.Grow(len(dataBig))
		w := NewWriter(b, &key)
		require.True(t, len(dataBig) > len(w.cache))
		n, err := w.Write(dataBig)
		require.NoError(t, err)
		require.Equal(t, len(dataBig), n)
		require.Equal(t, len(dataBig), b.Len())

		decrypted, err := io.ReadAll(NewReader(bytes.NewReader(b.Bytes()), &key))
		require.NoError(t, err)
		require.Equal(t, len(dataBig), len(decrypted))
		require.Equal(t, dataBig, decrypted)
	})
	t.Run("FullFailWrite", func(t *testing.T) {
		b := bytes.NewBuffer(nil)
		b.Grow(len(data))
		w := NewWriter(&limitWriter{
			dst:   b,
			limit: len(data) - 1,
		}, &key)
		n, err := w.Write(data)
		require.Error(t, err)
		require.Equal(t, len(data)-BlockSize, n)
	})
	t.Run("PartialFailWrite", func(t *testing.T) {
		b := bytes.NewBuffer(nil)
		b.Grow(len(data) + 1)
		w := NewWriter(&limitWriter{
			dst:   b,
			limit: len(data),
		}, &key)
		n, err := w.Write(make([]byte, BlockSize-1))
		require.NoError(t, err)
		require.Equal(t, BlockSize-1, n)

		n, err = w.Write(data)
		require.NoError(t, err)
		require.Equal(t, len(data), n)

		n, err = w.Write([]byte{0})
		require.Error(t, err)
		require.Equal(t, 0, n)
	})
}

func BenchmarkWriter(b *testing.B) {
	var seed [8]byte
	rand.Read(seed[:])
	data := make([]byte, BlockSize*1024)
	rand.Read(data)
	var key Key
	key.SetSeed(seed)
	w := NewWriter(io.Discard, &key)
	b.Run("Write", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(data)))
		for i := 0; i < b.N; i++ {
			_, _ = w.Write(data)
		}
	})
}
