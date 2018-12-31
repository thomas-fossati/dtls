package dtls

import (
	"encoding/binary"
	"fmt"
)

type recordLayerHeader struct {
	contentType     contentType
	contentLen      uint16
	protocolVersion protocolVersion
	epoch           uint16
	sequenceNumber  uint64 // uint48 in spec
	cid             []byte
	cidLen          int // set by the caller for unmarshal
}

const (
	recordLayerHeaderSize = 13
	maxSequenceNumber     = 0x0000FFFFFFFFFFFF

	dtls1_2Major = 0xfe
	dtls1_2Minor = 0xfd
)

var protocolVersion1_2 = protocolVersion{dtls1_2Major, dtls1_2Minor}

// https://tools.ietf.org/html/rfc4346#section-6.2.1
type protocolVersion struct {
	major, minor uint8
}

func (r *recordLayerHeader) Marshal() ([]byte, error) {
	if r.sequenceNumber > maxSequenceNumber {
		return nil, errSequenceNumberOverflow
	}

	hlen := recordLayerHeaderSize
	// expand record header to include CID (if we have been asked to send
	// one)
	if r.contentType == contentTypeTLS12CID {
		hlen += r.cidLen
	}

	out := make([]byte, hlen)

	out[0] = byte(r.contentType)
	out[1] = r.protocolVersion.major
	out[2] = r.protocolVersion.minor
	binary.BigEndian.PutUint16(out[3:], r.epoch)
	putBigEndianUint48(out[5:], r.sequenceNumber)

	if r.contentType == contentTypeTLS12CID {
		fmt.Printf("[recordLayerHeader::Marshal] adding CID: % x\n", r.cid)
		copy(out[11:], r.cid)
	}

	binary.BigEndian.PutUint16(out[hlen-2:], r.contentLen)
	fmt.Printf("[recordLayerHeader::Marshal] out: % x\n", out)
	return out, nil
}

func (r *recordLayerHeader) Unmarshal(data []byte) error {
	fmt.Printf("[recordLayerHeader::Unmarshal] in: % x\n", data)

	r.contentType = contentType(data[0])
	r.protocolVersion.major = data[1]
	r.protocolVersion.minor = data[2]
	r.epoch = binary.BigEndian.Uint16(data[3:])

	// SequenceNumber is stored as uint48, make into uint64
	seqCopy := make([]byte, 8)
	copy(seqCopy[2:], data[5:11])
	r.sequenceNumber = binary.BigEndian.Uint64(seqCopy)

	if r.contentType == contentTypeTLS12CID {
		// there must be enough bytes for cid + 2 bytes for clen
		if len(data[11:]) < r.cidLen+2 {
			return errNotEnoughDataForCID
		}
		copy(r.cid, data[11:11+r.cidLen])
		fmt.Printf("[recordLayerHeader::UnMarshal] consuming CID: % x\n", r.cid)
	}

	return nil
}
