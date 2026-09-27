package logical

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// pglogrepl allocates declared tuple lengths while decoding. Check the entire
// frame before calling it, so a corrupt length cannot cause an oversized alloc.
func validateFrame(raw []byte) error {
	bad := errors.New("unsupported or malformed pgoutput frame")
	if len(raw) == 0 || len(raw) > 2<<20 {
		return bad
	}
	c := wire{data: raw[1:]}
	switch raw[0] {
	case 'B':
		c.take(20)
	case 'C':
		if c.byte() != 0 {
			return bad
		}
		c.take(24)
	case 'R':
		c.take(4)
		c.name()
		c.name()
		c.take(1)
		count := c.u16()
		if count > 1600 {
			return bad
		}
		for i := 0; i < int(count); i++ {
			if c.byte() > 1 {
				return bad
			}
			c.name()
			c.take(8)
		}
	case 'I':
		c.take(4)
		if c.byte() != 'N' {
			return bad
		}
		c.tuple()
	case 'D':
		c.take(4)
		tag := c.byte()
		if tag != 'K' && tag != 'O' {
			return bad
		}
		c.tuple()
	case 'U':
		c.take(4)
		tag := c.byte()
		if tag == 'K' || tag == 'O' {
			c.tuple()
			tag = c.byte()
		}
		if tag != 'N' {
			return bad
		}
		c.tuple()
	default:
		return bad
	}
	if c.failed || len(c.data) != 0 {
		return bad
	}
	return nil
}

type wire struct {
	data   []byte
	failed bool
}

func (c *wire) take(n int) []byte {
	if n < 0 || n > len(c.data) {
		c.failed = true
		c.data = nil
		return nil
	}
	b := c.data[:n]
	c.data = c.data[n:]
	return b
}
func (c *wire) byte() byte {
	b := c.take(1)
	if len(b) != 1 {
		return 0
	}
	return b[0]
}
func (c *wire) u16() uint16 {
	b := c.take(2)
	if len(b) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (c *wire) name() {
	n := bytes.IndexByte(c.data, 0)
	if n < 0 || n > 63 {
		c.failed = true
		return
	}
	c.take(n + 1)
}
func (c *wire) tuple() {
	n := c.u16()
	if n > 1600 {
		c.failed = true
		return
	}
	for i := 0; i < int(n) && !c.failed; i++ {
		switch c.byte() {
		case 'n', 'u':
		case 't':
			b := c.take(4)
			if len(b) != 4 {
				return
			}
			length := binary.BigEndian.Uint32(b)
			if length > 1<<20 {
				c.failed = true
				return
			}
			c.take(int(length))
		default:
			c.failed = true
		}
	}
}
