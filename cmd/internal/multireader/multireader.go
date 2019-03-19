package multireader

import (
	"fmt"
	"io"
	"os"
)

type multiReader struct {
	file  *os.File
	files []string
}

func New(ps []string) (io.Reader, error) {
	if len(ps) == 0 {
		return nil, fmt.Errorf("no files given")
	}
	// sort.Strings(ps)
	f, err := os.Open(ps[0])
	if err != nil {
		return nil, err
	}
	m := multiReader{file: f}
	if len(ps) > 1 {
		m.files = ps[1:]
	} else {
		m.files = ps[:0]
	}
	return &m, nil
}

func (m *multiReader) Read(bs []byte) (int, error) {
	if len(m.files) == 0 && m.file == nil {
		return 0, io.EOF
	}
	n, err := m.file.Read(bs)
	if err == io.EOF {
		m.file.Close()
		if len(m.files) > 0 {
			if m.file, err = os.Open(m.files[0]); err != nil {
				return 0, err
			}
			if len(m.files) == 1 {
				m.files = m.files[:0]
			} else {
				m.files = m.files[1:]
			}
			return 0, nil
		} else {
			m.file = nil
		}
	}
	return n, err
}
