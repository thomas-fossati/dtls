package dtls

type tls12cid struct {
	compressed []byte
	ct         byte
	zeroes     []byte
}

func (t tls12cid) contentType() contentType {
	return contentTypeTLS12Cid
}

func (t *tls12cid) Marshal() ([]byte, error) {
	out := append([]byte{}, t.compressed...)
	out = append(out, t.ct)
	// no pad (for now)

	return out, nil
}

func (t *tls12cid) Unmarshal(data []byte) error {
	t.compressed = append([]byte{}, data[:len(data)-1]...)
	t.ct = data[len(data)-1]
	return nil
}
