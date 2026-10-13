package helps

import (
	"bufio"
	"bytes"
	"encoding/json"
)

// SplitResponsesSSE emits one complete data event for the existing translator.
// Scanner owns buffering across CRLF and arbitrary UTF-8 transport boundaries.
// Incomplete events at EOF are discarded, never certified as terminal success.
func SplitResponsesSSE(data []byte, atEOF bool) (advance int, token []byte, err error) {
	var fields [][]byte
	for offset := 0; offset < len(data); {
		n, line, errLine := bufio.ScanLines(data[offset:], atEOF)
		if errLine != nil {
			return 0, nil, errLine
		}
		if n == 0 {
			return 0, nil, nil
		}
		offset += n
		if len(line) == 0 {
			if len(fields) == 0 {
				return offset, nil, nil
			}
			value := bytes.Join(fields, []byte{'\n'})
			var compact bytes.Buffer
			if string(value) != "[DONE]" {
				if err = json.Compact(&compact, value); err != nil {
					return 0, nil, err
				}
				value = compact.Bytes()
			}
			return offset, append([]byte("data: "), value...), nil
		}
		if bytes.Equal(line, []byte("data")) {
			fields = append(fields, nil)
		}
		if value, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			value, _ = bytes.CutPrefix(value, []byte{' '})
			fields = append(fields, value)
		}
	}
	if atEOF {
		return len(data), nil, nil
	}
	return 0, nil, nil
}
