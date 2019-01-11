package dtls

import "fmt"

type tls12cid struct {
	innerContent content
	ct           byte
	zeroes       []byte
}

func (t tls12cid) contentType() contentType {
	return contentTypeTLS12Cid
}

func (t *tls12cid) Marshal() ([]byte, error) {
	// only handle application data
	// also, no pad (for now)
	switch ct := t.innerContent.(type) {
	case *applicationData:
		out, err := t.innerContent.Marshal()
		if err != nil {
			return nil, err
		}
		out = append(out, byte(ct.contentType()))
		out = append(out, 0x00) // 0-length pad

		return out, nil
	default:
		return nil, fmt.Errorf("unhandled wrapped content type: %v", ct)
	}
}

func (t *tls12cid) Unmarshal(data []byte) error {
	t.ct = data[len(data)-2]

	switch t.ct {
	case byte(contentTypeApplicationData):
		t.innerContent = &applicationData{}
		return t.innerContent.Unmarshal(data[:len(data)-2])
	default:
		return fmt.Errorf("unhandled wrapped content type: %v", t.ct)
	}
}
