package dtls

import "fmt"

type tls12cid struct {
	innerContent content
	ct           byte
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
		// add one byte of padding (only to exercise our peers)
		out = append(out, 0x00)

		return out, nil
	default:
		return nil, fmt.Errorf("marshal: unhandled wrapped content type: %v", ct)
	}
}

func (t *tls12cid) Unmarshal(paddedData []byte) error {
	data := removePadding(paddedData)

	t.ct = data[len(data)-1]

	switch t.ct {
	case byte(contentTypeApplicationData):
		t.innerContent = &applicationData{}
		return t.innerContent.Unmarshal(data[:len(data)-1])
	default:
		return fmt.Errorf("unmarshal: unhandled wrapped content type: %v", t.ct)
	}
}

func removePadding(buf []uint8) []uint8 {
	i := len(buf) - 1
	for i >= 0 && buf[i] == 0x00 {
		i--
	}

	return buf[:i+1]
}
