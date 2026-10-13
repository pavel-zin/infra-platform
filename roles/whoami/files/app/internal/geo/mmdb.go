// Package geo answers "where is this IP and who runs it" from DB-IP Lite
// databases (MaxMind DB format) and the Tor Project's exit list.
package geo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/netip"
	"os"
	"syscall"
)

// Reader reads a MaxMind DB file (https://maxmind.github.io/MaxMind-DB/).
// The file is memory-mapped, so a 130 MB city database costs page cache that
// the kernel can evict, not heap.
type Reader struct {
	data       []byte
	unmap      func() error
	nodeCount  uint32
	recordSize uint
	ipVersion  uint
	treeSize   int
	dataStart  int
	ipv4Start  uint32
	Metadata   Metadata
}

// Metadata is the subset of the database metadata this service uses.
type Metadata struct {
	DatabaseType string
	BuildEpoch   uint64
	NodeCount    uint32
	RecordSize   uint
	IPVersion    uint
}

var metadataMarker = []byte("\xab\xcd\xefMaxMind.com")

// Open memory-maps path and validates its metadata.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if size <= 0 || size > math.MaxInt32 {
		return nil, fmt.Errorf("mmdb %s: unexpected size %d", path, size)
	}
	data, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		// Fall back to reading the file into memory.
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, rerr
		}
		return FromBytes(b)
	}
	r, err := FromBytes(data)
	if err != nil {
		_ = syscall.Munmap(data)
		return nil, err
	}
	r.unmap = func() error { return syscall.Munmap(data) }
	return r, nil
}

// FromBytes parses an in-memory database.
func FromBytes(data []byte) (*Reader, error) {
	start := max(len(data)-128*1024, 0)
	i := bytes.LastIndex(data[start:], metadataMarker)
	if i < 0 {
		return nil, errors.New("mmdb: metadata marker not found")
	}
	metaStart := start + i + len(metadataMarker)
	meta := decoder{buf: data[metaStart:]}
	raw, _, err := meta.decode(0, 0)
	if err != nil {
		return nil, fmt.Errorf("mmdb metadata: %w", err)
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("mmdb metadata: not a map")
	}
	r := &Reader{data: data}
	r.Metadata.DatabaseType, _ = m["database_type"].(string)
	r.Metadata.BuildEpoch = asUint(m["build_epoch"])
	r.nodeCount = uint32(asUint(m["node_count"]))
	r.recordSize = uint(asUint(m["record_size"]))
	r.ipVersion = uint(asUint(m["ip_version"]))
	r.Metadata.NodeCount, r.Metadata.RecordSize, r.Metadata.IPVersion = r.nodeCount, r.recordSize, r.ipVersion
	if r.recordSize != 24 && r.recordSize != 28 && r.recordSize != 32 {
		return nil, fmt.Errorf("mmdb: unsupported record size %d", r.recordSize)
	}
	if r.ipVersion != 4 && r.ipVersion != 6 {
		return nil, fmt.Errorf("mmdb: unsupported ip_version %d", r.ipVersion)
	}
	r.treeSize = int(r.nodeCount) * int(r.recordSize) / 4
	r.dataStart = r.treeSize + 16
	if r.dataStart > metaStart-len(metadataMarker) {
		return nil, errors.New("mmdb: search tree larger than file")
	}
	if r.ipVersion == 6 {
		node := uint32(0)
		for i := 0; i < 96 && node < r.nodeCount; i++ {
			node = r.readNode(node, 0)
		}
		r.ipv4Start = node
	}
	return r, nil
}

func asUint(v any) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	case int32:
		return uint64(x)
	}
	return 0
}

// Close releases the mapping. The Reader must not be used afterwards.
func (r *Reader) Close() error {
	if r.unmap != nil {
		return r.unmap()
	}
	return nil
}

func (r *Reader) readNode(node uint32, bit uint32) uint32 {
	b := r.data
	switch r.recordSize {
	case 24:
		o := int(node)*6 + int(bit)*3
		return uint32(b[o])<<16 | uint32(b[o+1])<<8 | uint32(b[o+2])
	case 28:
		o := int(node) * 7
		if bit == 0 {
			return (uint32(b[o+3])&0xf0)<<20 | uint32(b[o])<<16 | uint32(b[o+1])<<8 | uint32(b[o+2])
		}
		return (uint32(b[o+3])&0x0f)<<24 | uint32(b[o+4])<<16 | uint32(b[o+5])<<8 | uint32(b[o+6])
	default:
		o := int(node)*8 + int(bit)*4
		return binary.BigEndian.Uint32(b[o:])
	}
}

// Lookup returns the decoded record for ip, or ok=false if the database has
// no data for it.
func (r *Reader) Lookup(ip netip.Addr) (record any, ok bool, err error) {
	ip = ip.Unmap()
	var bits []byte
	node := uint32(0)
	switch {
	case ip.Is4():
		a := ip.As4()
		bits = a[:]
		if r.ipVersion == 6 {
			node = r.ipv4Start
		}
	case r.ipVersion == 6:
		a := ip.As16()
		bits = a[:]
	default:
		return nil, false, nil
	}
	for i := 0; i < len(bits)*8 && node < r.nodeCount; i++ {
		bit := uint32(bits[i>>3]>>(7-uint(i&7))) & 1
		node = r.readNode(node, bit)
	}
	switch {
	case node == r.nodeCount:
		return nil, false, nil
	case node < r.nodeCount:
		return nil, false, errors.New("mmdb: search tree did not terminate")
	}
	off := int(node-r.nodeCount) - 16
	d := decoder{buf: r.data[r.dataStart:]}
	v, _, err := d.decode(off, 0)
	if err != nil {
		return nil, false, err
	}
	return v, true, nil
}

// decoder decodes the MaxMind DB data section format.
type decoder struct{ buf []byte }

var errBadData = errors.New("mmdb: corrupt data section")

func (d *decoder) need(off, n int) error {
	if off < 0 || n < 0 || off+n > len(d.buf) {
		return errBadData
	}
	return nil
}

func (d *decoder) uintN(off, n int) uint64 {
	var v uint64
	for _, b := range d.buf[off : off+n] {
		v = v<<8 | uint64(b)
	}
	return v
}

// decode returns the value at off and the offset just past it.
func (d *decoder) decode(off, depth int) (any, int, error) {
	if depth > 32 {
		return nil, 0, errors.New("mmdb: data nested too deeply")
	}
	if err := d.need(off, 1); err != nil {
		return nil, 0, err
	}
	ctrl := d.buf[off]
	off++
	typ := int(ctrl >> 5)
	if typ == 1 { // pointer
		ss := int(ctrl>>3) & 0x3
		vvv := uint64(ctrl & 0x7)
		n := ss + 1
		if err := d.need(off, n); err != nil {
			return nil, 0, err
		}
		var ptr uint64
		switch ss {
		case 0:
			ptr = vvv<<8 | d.uintN(off, 1)
		case 1:
			ptr = (vvv<<16 | d.uintN(off, 2)) + 2048
		case 2:
			ptr = (vvv<<24 | d.uintN(off, 3)) + 526336
		case 3:
			ptr = d.uintN(off, 4)
		}
		v, _, err := d.decode(int(ptr), depth+1)
		return v, off + n, err
	}
	if typ == 0 { // extended type
		if err := d.need(off, 1); err != nil {
			return nil, 0, err
		}
		typ = 7 + int(d.buf[off])
		off++
	}
	size := int(ctrl & 0x1f)
	if size >= 29 {
		n := size - 28
		if err := d.need(off, n); err != nil {
			return nil, 0, err
		}
		switch n {
		case 1:
			size = 29 + int(d.uintN(off, 1))
		case 2:
			size = 285 + int(d.uintN(off, 2))
		case 3:
			size = 65821 + int(d.uintN(off, 3))
		}
		off += n
	}
	switch typ {
	case 2: // UTF-8 string
		if err := d.need(off, size); err != nil {
			return nil, 0, err
		}
		return string(d.buf[off : off+size]), off + size, nil
	case 3: // double
		if size != 8 || d.need(off, 8) != nil {
			return nil, 0, errBadData
		}
		return math.Float64frombits(d.uintN(off, 8)), off + 8, nil
	case 4: // bytes
		if err := d.need(off, size); err != nil {
			return nil, 0, err
		}
		return append([]byte(nil), d.buf[off:off+size]...), off + size, nil
	case 5, 6, 9: // uint16, uint32, uint64
		if size > 8 || d.need(off, size) != nil {
			return nil, 0, errBadData
		}
		return d.uintN(off, size), off + size, nil
	case 10: // uint128
		if size > 16 || d.need(off, size) != nil {
			return nil, 0, errBadData
		}
		return new(big.Int).SetBytes(d.buf[off : off+size]), off + size, nil
	case 8: // int32
		if size > 4 || d.need(off, size) != nil {
			return nil, 0, errBadData
		}
		return int32(uint32(d.uintN(off, size))), off + size, nil
	case 7: // map
		m := make(map[string]any, size)
		for range size {
			k, next, err := d.decode(off, depth+1)
			if err != nil {
				return nil, 0, err
			}
			key, ok := k.(string)
			if !ok {
				return nil, 0, errBadData
			}
			v, next2, err := d.decode(next, depth+1)
			if err != nil {
				return nil, 0, err
			}
			m[key] = v
			off = next2
		}
		return m, off, nil
	case 11: // array
		a := make([]any, 0, size)
		for range size {
			v, next, err := d.decode(off, depth+1)
			if err != nil {
				return nil, 0, err
			}
			a = append(a, v)
			off = next
		}
		return a, off, nil
	case 14: // boolean, value stored in the size field
		return size != 0, off, nil
	case 15: // float
		if size != 4 || d.need(off, 4) != nil {
			return nil, 0, errBadData
		}
		return math.Float32frombits(uint32(d.uintN(off, 4))), off + 4, nil
	}
	return nil, 0, fmt.Errorf("mmdb: unsupported data type %d", typ)
}
