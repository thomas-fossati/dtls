package dtls

type tls12cid struct {
	encdata []byte
}

func (t tls12cid) contentType() contentType {
	return contentTypeTLS12Cid
}

func (t *tls12cid) Marshal() ([]byte, error) {
	return append([]byte{}, t.encdata...), nil
}

func (t *tls12cid) Unmarshal(data []byte) error {
	t.encdata = append([]byte{}, data...)
	return nil
}
