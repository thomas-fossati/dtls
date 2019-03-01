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
	cid := pkt.recordLayerHeader.cid
	cidLen := pkt.recordLayerHeader.cidLen
	hasValidCid := (cid != nil && len(cid) >= cidLen && cidLen > 0)

	hlen := recordLayerHeaderSize
	adLen := 13
	if hasValidCid {
		hlen += cidLen
		adLen += 1 + cidLen // cid's len + cid
	}

	payload := raw[hlen:]
	raw = raw[:hlen]

	nonce := append(append([]byte{}, c.localWriteIV[:4]...), make([]byte, 8)...)
	if _, err := rand.Read(nonce[4:]); err != nil {
		return nil, err
	}

	additionalData := make([]byte, adLen)

	// SequenceNumber MUST be set first
	// we only want uint48, clobbering an extra 2 (using uint64, Golang doesn't have uint48)
	binary.BigEndian.PutUint64(additionalData[:], pkt.recordLayerHeader.sequenceNumber)
	binary.BigEndian.PutUint16(additionalData[:], pkt.recordLayerHeader.epoch)
	additionalData[8] = byte(pkt.content.contentType())
	additionalData[9] = pkt.recordLayerHeader.protocolVersion.major
	additionalData[10] = pkt.recordLayerHeader.protocolVersion.minor

	if hasValidCid {
		copy(additionalData[11:11+cidLen], cid[:cidLen])
		additionalData[11+cidLen] = byte(cidLen)
	}

	binary.BigEndian.PutUint16(additionalData[adLen-2:], uint16(len(payload)))
	encryptedPayload := c.localGCM.Seal(nil, nonce, payload, additionalData[:])

	encryptedPayload = append(nonce[4:], encryptedPayload...)
	raw = append(raw, encryptedPayload...)

	// Update recordLayer size to include explicit nonce
	binary.BigEndian.PutUint16(raw[hlen-2:], uint16(len(raw)-hlen))
	return raw, nil

}

func (c *cryptoGCM) decrypt(in []byte) ([]byte, error) {
	hlen := recordLayerHeaderSize
	adLen := 13

	hasCid := (contentType(in[0]) == contentTypeTLS12Cid)

	var h recordLayerHeader

	if hasCid {
		h.cidLen = extensionConnectionIdSize
		hlen += extensionConnectionIdSize
		adLen += 1 + extensionConnectionIdSize // cid's len + cid
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

	additionalData := make([]byte, adLen)

	// SequenceNumber MUST be set first
	// we only want uint48, clobbering an extra 2 (using uint64, Golang doesn't have uint48)
	binary.BigEndian.PutUint64(additionalData[:], h.sequenceNumber)
	binary.BigEndian.PutUint16(additionalData[:], h.epoch)
	additionalData[8] = byte(h.contentType)
	additionalData[9] = h.protocolVersion.major
	additionalData[10] = h.protocolVersion.minor

	if hasCid {
		copy(additionalData[11:11+h.cidLen], h.cid[:h.cidLen])
		additionalData[11+h.cidLen] = byte(h.cidLen)
	}

	binary.BigEndian.PutUint16(additionalData[adLen-2:], uint16(len(out)-cryptoGCMTagLength))
	out, err = c.remoteGCM.Open(out[:0], nonce, out, additionalData[:])
	if err != nil {
		return nil, fmt.Errorf("decryptPacket: %v", err)
	}
	return append(in[:hlen], out...), nil
}
