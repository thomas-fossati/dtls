package dtls

import (
	"reflect"
	"testing"
)

func TestConnectionIdMarshal(t *testing.T) {
	type testVector struct {
		in extensionConnectionId
		ex []byte
	}

	tvs := []testVector{
		testVector{
			in: extensionConnectionId{},
			ex: []byte{0x00, 0x34},
		},
		testVector{
			in: extensionConnectionId{
				connectionId: []byte{0x00, 0x01, 0x02},
			},
			ex: []byte{0x00, 0x34, 0x00, 0x01, 0x02},
		},
	}

	for _, tv := range tvs {
		out, err := tv.in.Marshal()
		if err != nil {
			t.Error(err)
		} else if !reflect.DeepEqual(out, tv.ex) {
			t.Errorf("marshal: got %#v, want %#v", out, tv.ex)
		}
	}
}

func TestConnectionIdUnmarshalOk(t *testing.T) {
	type testVector struct {
		in []byte
		ex []byte
		er error
	}

	tvs := []testVector{
		testVector{
			in: []byte{},
			ex: nil, // doesn't matter
			er: errBufferTooSmall,
		},
		testVector{
			in: []byte{0x00},
			ex: nil, // doesn't matter
			er: errBufferTooSmall,
		},
		testVector{
			// invalid codepoint
			in: []byte{0x00, 0x00},
			ex: nil, // doesn't matter
			er: errInvalidExtensionType,
		},
		testVector{
			// 0-length is valid
			in: []byte{0x00, 0x34},
			ex: []byte{},
			er: nil,
		},
		testVector{
			in: []byte{0x00, 0x34, 0x00, 0x01, 0x02},
			ex: []byte{0x00, 0x01, 0x02},
			er: nil,
		},
	}

	for _, tv := range tvs {
		var out extensionConnectionId

		err := out.Unmarshal(tv.in)

		if tv.er != nil {
			if err != tv.er {
				t.Errorf("marshal: got %#v, want %#v", err, tv.er)
			}
		} else {
			if err != nil {
				t.Error(err)
			} else if !reflect.DeepEqual(out.connectionId, tv.ex) {
				t.Errorf("marshal: got %#v, want %#v", out.connectionId, tv.ex)
			}
		}
	}
}
