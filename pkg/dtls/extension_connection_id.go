package dtls

import (
	"encoding/binary"
)

const (
	extensionConnectionIdHeaderSize = 5
)

// https://tools.ietf.org/html/draft-ietf-tls-dtls-connection-id-02#section-3
type extensionConnectionId struct {
	connectionId []byte
}

func (e extensionConnectionId) extensionValue() extensionValue {
	return extensionConnectionIdValue
}

func (e *extensionConnectionId) Marshal() ([]byte, error) {
	l := len(e.connectionId)
	if l > 255 {
		return nil, errConnectionIdTooBig
	}

	out := make([]byte, extensionConnectionIdHeaderSize)

	binary.BigEndian.PutUint16(out, uint16(e.extensionValue()))
	binary.BigEndian.PutUint16(out[2:], uint16(l+1))
	// CID is encoded as a variable-length array of at least 255 bytes
	out[4] = byte(l)
	out = append(out, e.connectionId[:l]...)

	return out, nil
}

func (e *extensionConnectionId) Unmarshal(data []byte) error {
	if len(data) < extensionConnectionIdHeaderSize {
		return errBufferTooSmall
	} else if extensionValue(binary.BigEndian.Uint16(data)) != e.extensionValue() {
		return errInvalidExtensionType
	}

	e.connectionId = append(e.connectionId, data[extensionConnectionIdHeaderSize:]...)

	return nil
}
