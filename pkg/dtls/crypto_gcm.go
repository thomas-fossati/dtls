package dtls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

const cryptoGCMTagLength = 16

// State needed to handle encrypted input/output
type cryptoGCM struct {
	localGCM, remoteGCM         cipher.AEAD
	localWriteIV, remoteWriteIV []byte
}

func newCryptoGCM(localKey, localWriteIV, remoteKey, remoteWriteIV []byte) (*cryptoGCM, error) {
	localBlock, err := aes.NewCipher(localKey)
	if err != nil {
		return nil, err
	}
	localGCM, err := cipher.NewGCM(localBlock)
	if err != nil {
		return nil, err
	}

	remoteBlock, err := aes.NewCipher(remoteKey)
	if err != nil {
		return nil, err
	}
	remoteGCM, err := cipher.NewGCM(remoteBlock)
	if err != nil {
		return nil, err
	}

	return &cryptoGCM{
		localGCM:      localGCM,
		localWriteIV:  localWriteIV,
		remoteGCM:     remoteGCM,
		remoteWriteIV: remoteWriteIV,
	}, nil
}

func (c *cryptoGCM) encrypt(pkt *recordLayer, raw []byte) ([]byte, error) {
	hlen := recordLayerHeaderSize

	if pkt.recordLayerHeader.cid != nil {
		hlen += pkt.recordLayerHeader.cidLen
	}

	payload := raw[hlen:]
	raw = raw[:hlen]

	nonce := append(append([]byte{}, c.localWriteIV[:4]...), make([]byte, 8)...)
	if _, err := rand.Read(nonce[4:]); err != nil {
		return nil, err
	}

	var additionalData [13]byte
	// SequenceNumber MUST be set first
	// we only want uint48, clobbering an extra 2 (using uint64, Golang doesn't have uint48)
	binary.BigEndian.PutUint64(additionalData[:], pkt.recordLayerHeader.sequenceNumber)
	binary.BigEndian.PutUint16(additionalData[:], pkt.recordLayerHeader.epoch)
	additionalData[8] = byte(pkt.content.contentType())
	additionalData[9] = pkt.recordLayerHeader.protocolVersion.major
	additionalData[10] = pkt.recordLayerHeader.protocolVersion.minor
	binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(len(payload)))
	encryptedPayload := c.localGCM.Seal(nil, nonce, payload, additionalData[:])

	encryptedPayload = append(nonce[4:], encryptedPayload...)
	raw = append(raw, encryptedPayload...)

	// Update recordLayer size to include explicit nonce
	binary.BigEndian.PutUint16(raw[hlen-2:], uint16(len(raw)-hlen))
	return raw, nil

}

func (c *cryptoGCM) decrypt(in []byte) ([]byte, error) {
	hlen := recordLayerHeaderSize

	var h recordLayerHeader

	if contentType(in[0]) == contentTypeTLS12CID {
		h.cidLen = extensionConnectionIdSize
		hlen += extensionConnectionIdSize
	}

	err := h.Unmarshal(in)
	switch {
	case err != nil:
		return nil, err
	case h.contentType == contentTypeChangeCipherSpec:
		// Nothing to encrypt with ChangeCipherSpec
		return in, nil
	case len(in) <= (8 + hlen):
		return nil, errNotEnoughRoomForNonce
	}

	nonce := append(append([]byte{}, c.remoteWriteIV[:4]...), in[hlen:hlen+8]...)
	out := in[hlen+8:]

	var additionalData [13]byte
	// SequenceNumber MUST be set first
	// we only want uint48, clobbering an extra 2 (using uint64, Golang doesn't have uint48)
	binary.BigEndian.PutUint64(additionalData[:], h.sequenceNumber)
	binary.BigEndian.PutUint16(additionalData[:], h.epoch)
	additionalData[8] = byte(h.contentType)
	additionalData[9] = h.protocolVersion.major
	additionalData[10] = h.protocolVersion.minor
	binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(len(out)-cryptoGCMTagLength))
	out, err = c.remoteGCM.Open(out[:0], nonce, out, additionalData[:])
	if err != nil {
		return nil, fmt.Errorf("decryptPacket: %v", err)
	}
	return append(in[:hlen], out...), nil
}
