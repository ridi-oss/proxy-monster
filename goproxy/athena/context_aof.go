package athena

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strconv"
)

func validateContextAOF(file *os.File, capacity int) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() == 0 || info.Size() > maxContextAOFBytes {
		return ErrContextCorrupt
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	reader := bufio.NewReader(file)
	formatSeen := false
	keys := make(map[string]bool)
	for {
		if _, err := reader.Peek(1); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		count, err := readRESPNumber(reader, '*', 3)
		if err != nil || count < 2 {
			return ErrContextCorrupt
		}
		parts := make([]string, count)
		for i := range parts {
			size, err := readRESPNumber(reader, '$', maxContextBytes+1024)
			if err != nil {
				return ErrContextCorrupt
			}
			data := make([]byte, size+2)
			if _, err = io.ReadFull(reader, data); err != nil || data[size] != '\r' || data[size+1] != '\n' {
				return ErrContextCorrupt
			}
			parts[i] = string(data[:size])
		}
		switch {
		case parts[0] == "set" && len(parts) == 3:
			if parts[1] == contextFormatKey {
				if parts[2] != contextFormat {
					return ErrContextCorrupt
				}
				formatSeen = true
			} else {
				if !formatSeen || !validContextKey(parts[1]) {
					return ErrContextCorrupt
				}
				if _, err := decodeContext([]byte(parts[2])); err != nil {
					return err
				}
				keys[parts[1]] = true
				if len(keys) > capacity {
					return ErrContextCapacity
				}
			}
		case parts[0] == "del" && len(parts) == 2:
			if !formatSeen || !validContextKey(parts[1]) {
				return ErrContextCorrupt
			}
			delete(keys, parts[1])
		default:
			return ErrContextCorrupt
		}
	}
	if !formatSeen {
		return ErrContextCorrupt
	}
	_, err = file.Seek(0, io.SeekStart)
	return err
}

func readRESPNumber(reader *bufio.Reader, prefix byte, max int) (int, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) < 4 || len(line) > 20 || line[0] != prefix || line[len(line)-2] != '\r' {
		return 0, ErrContextCorrupt
	}
	for _, digit := range line[1 : len(line)-2] {
		if digit < '0' || digit > '9' {
			return 0, ErrContextCorrupt
		}
	}
	value, err := strconv.Atoi(string(line[1 : len(line)-2]))
	if err != nil || value < 0 || value > max {
		return 0, ErrContextCorrupt
	}
	return value, nil
}
