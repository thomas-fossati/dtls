package dtls

import (
	"encoding/binary"
)

const (
	extensionConnectionIdHeaderSize = 2
)

// https://tools.ietf.org/html/draft-ietf-tls-dtls-connection-id-02#section-3
type extensionConnectionId struct {
	connectionId []byte
}

func (e extensionConnectionId) extensionValue() extensionValue {
	return extensionConnectionIdValue
}

func (e *extensionConnectionId) Marshal() ([]byte, error) {
	out := make([]byte, extensionConnectionIdHeaderSize)

	binary.BigEndian.PutUint16(out, uint16(e.extensionValue()))

	out = append(out, e.connectionId...)

	return out, nil
}

func (e *extensionConnectionId) Unmarshal(data []byte) error {
	e.connectionId = make([]byte, 0)

	if len(data) < extensionConnectionIdHeaderSize {
		return errBufferTooSmall
	} else if extensionValue(binary.BigEndian.Uint16(data)) != e.extensionValue() {
		return errInvalidExtensionType
	}

	e.connectionId = append(e.connectionId, data[2:]...)

	return nil
}
