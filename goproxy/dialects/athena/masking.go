package athena

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ridi-oss/proxy-monster/goproxy/engine"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

var ErrResultShape = errors.New("athena: result shape cannot be enforced")

// firstPage comes from the absence of the native request's NextToken, never from row contents.
func MaskResultPage(body []byte, masks []*pb.ColumnMask, expectedWidth *int32, metadataDigest []byte, firstPage bool) ([]byte, []byte, error) {
	page, err := DecodeEnvelope(body)
	if err != nil {
		return nil, nil, ErrResultShape
	}
	result, err := DecodeEnvelope(page.Field("ResultSet"))
	if err != nil {
		return nil, nil, ErrResultShape
	}
	metadata, err := DecodeEnvelope(result.Field("ResultSetMetadata"))
	if err != nil {
		return nil, nil, ErrResultShape
	}
	var columns []json.RawMessage
	if err := json.Unmarshal(metadata.Field("ColumnInfo"), &columns); err != nil || columns == nil {
		return nil, nil, ErrResultShape
	}
	if expectedWidth != nil && (int(*expectedWidth) != len(columns) || *expectedWidth < 0) {
		return nil, nil, ErrResultShape
	}
	for _, mask := range masks {
		if mask == nil {
			return nil, nil, engine.ErrMaskUnbound
		}
	}
	masker := engine.NewRowMasker(masks, len(columns))
	if masker == nil {
		return nil, nil, engine.ErrMaskUnbound
	}

	var shape any
	decoder := json.NewDecoder(bytes.NewReader(metadata.Field("ColumnInfo")))
	decoder.UseNumber()
	if err := decoder.Decode(&shape); err != nil {
		return nil, nil, ErrResultShape
	}
	canonical, err := json.Marshal(shape)
	if err != nil {
		return nil, nil, ErrResultShape
	}
	digest := sha256.Sum256(canonical)
	if len(metadataDigest) != 0 && !bytes.Equal(metadataDigest, digest[:]) {
		return nil, nil, ErrResultShape
	}

	names := make([]string, len(columns))
	for i, column := range columns {
		info, err := DecodeEnvelope(column)
		if err != nil {
			return nil, nil, ErrResultShape
		}
		name, err := requiredString(info, "Name")
		if err != nil {
			return nil, nil, ErrResultShape
		}
		if _, err := requiredString(info, "Type"); err != nil {
			return nil, nil, ErrResultShape
		}
		names[i] = name
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(result.Field("Rows"), &rows); err != nil || rows == nil {
		return nil, nil, ErrResultShape
	}
	for i, rawRow := range rows {
		row, err := DecodeEnvelope(rawRow)
		if err != nil {
			return nil, nil, ErrResultShape
		}
		var cells []json.RawMessage
		if err := json.Unmarshal(row.Field("Data"), &cells); err != nil || len(cells) != len(columns) {
			return nil, nil, ErrResultShape
		}
		values := make([]*string, len(cells))
		objects := make([]*Envelope, len(cells))
		for j, cell := range cells {
			objects[j], err = DecodeEnvelope(cell)
			if err != nil {
				return nil, nil, ErrResultShape
			}
			if value := objects[j].Field("VarCharValue"); value != nil {
				text, err := requiredString(objects[j], "VarCharValue")
				if err != nil {
					return nil, nil, ErrResultShape
				}
				values[j] = &text
			}
		}
		if firstPage && i == 0 {
			for j, value := range values {
				if value == nil || *value != names[j] {
					return nil, nil, ErrResultShape
				}
			}
			continue
		}
		masked := masker.Apply(values)
		for j, value := range masked {
			if value == values[j] {
				continue
			}
			if value == nil {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(cells[j], &fields); err != nil {
					return nil, nil, ErrResultShape
				}
				delete(fields, "VarCharValue")
				cells[j], err = json.Marshal(fields)
			} else {
				cells[j], err = replaceField(objects[j], "VarCharValue", *value)
			}
			if err != nil {
				return nil, nil, err
			}
		}
		rows[i], err = replaceField(row, "Data", cells)
		if err != nil {
			return nil, nil, err
		}
	}
	for index, kind := range engine.BindMasks(masks, len(columns)).ByIndex {
		if kind == "NULL" {
			continue
		}
		column, err := DecodeEnvelope(columns[index])
		if err != nil {
			return nil, nil, ErrResultShape
		}
		columns[index], err = replaceField(column, "Type", "varchar")
		if err != nil {
			return nil, nil, err
		}
	}
	metadataBytes, err := replaceField(metadata, "ColumnInfo", columns)
	if err != nil {
		return nil, nil, err
	}
	resultBytes, err := replaceField(result, "ResultSetMetadata", json.RawMessage(metadataBytes))
	if err != nil {
		return nil, nil, err
	}
	result, err = DecodeEnvelope(resultBytes)
	if err != nil {
		return nil, nil, err
	}
	resultBytes, err = replaceField(result, "Rows", rows)
	if err != nil {
		return nil, nil, err
	}
	output, err := replaceField(page, "ResultSet", json.RawMessage(resultBytes))
	return output, digest[:], err
}

func requiredString(envelope *Envelope, name string) (string, error) {
	raw := envelope.Field(name)
	if len(raw) == 0 || raw[0] != '"' {
		return "", fmt.Errorf("athena: %s must be a string", name)
	}
	var value string
	err := json.Unmarshal(raw, &value)
	return value, err
}

func replaceField(envelope *Envelope, name string, value any) ([]byte, error) {
	span, present := envelope.fields[name]
	if !present {
		return nil, fmt.Errorf("athena: missing field %s", name)
	}
	replacement, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, len(envelope.body)+len(replacement))
	result = append(result, envelope.body[:span.start]...)
	result = append(result, replacement...)
	result = append(result, envelope.body[span.end:]...)
	return result, nil
}
