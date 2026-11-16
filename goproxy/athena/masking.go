package athena

import (
	"encoding/json"
	"fmt"

	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
)

var ErrResultShape = httpdb.ErrResultShape

// MaskResultPage applies column masks to one GetQueryResults page in place, keeping every other byte. The
// page must match the shape the context was admitted under (column count, and the column metadata digest
// once one page has been read); anything else fails closed with ErrResultShape rather than masking the
// wrong ordinal. Masked columns report type varchar. firstPage comes from the absence of the native
// request's NextToken, never from row contents, because Athena's DML first row is a header of column names.
func MaskResultPage(body []byte, masks []*pb.ColumnMask, expectedWidth *int32, metadataDigest []byte, firstPage bool) ([]byte, []byte, error) {
	page, err := httpdb.DecodeEnvelope(body)
	if err != nil {
		return nil, nil, ErrResultShape
	}
	result, err := httpdb.DecodeEnvelope(page.Field("ResultSet"))
	if err != nil {
		return nil, nil, ErrResultShape
	}
	metadata, err := httpdb.DecodeEnvelope(result.Field("ResultSetMetadata"))
	if err != nil {
		return nil, nil, ErrResultShape
	}
	var columns []json.RawMessage
	if err := json.Unmarshal(metadata.Field("ColumnInfo"), &columns); err != nil || columns == nil {
		return nil, nil, ErrResultShape
	}
	if err := httpdb.CheckWidth(expectedWidth, len(columns)); err != nil {
		return nil, nil, err
	}
	for _, mask := range masks {
		if mask == nil {
			return nil, nil, relay.ErrMaskUnbound
		}
	}
	masker := relay.NewRowMasker(masks, len(columns))
	if masker == nil {
		return nil, nil, relay.ErrMaskUnbound
	}

	digest, err := httpdb.ColumnDigest(metadata.Field("ColumnInfo"), metadataDigest)
	if err != nil {
		return nil, nil, err
	}

	names := make([]string, len(columns))
	for i, column := range columns {
		info, err := httpdb.DecodeEnvelope(column)
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
		row, err := httpdb.DecodeEnvelope(rawRow)
		if err != nil {
			return nil, nil, ErrResultShape
		}
		var cells []json.RawMessage
		if err := json.Unmarshal(row.Field("Data"), &cells); err != nil || len(cells) != len(columns) {
			return nil, nil, ErrResultShape
		}
		values := make([]*string, len(cells))
		objects := make([]*httpdb.Envelope, len(cells))
		for j, cell := range cells {
			objects[j], err = httpdb.DecodeEnvelope(cell)
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
				cells[j], err = objects[j].Replace("VarCharValue", *value)
			}
			if err != nil {
				return nil, nil, err
			}
		}
		rows[i], err = row.Replace("Data", cells)
		if err != nil {
			return nil, nil, err
		}
	}
	for index, kind := range relay.BindMasks(masks, len(columns)).ByIndex {
		if kind == "NULL" {
			continue
		}
		column, err := httpdb.DecodeEnvelope(columns[index])
		if err != nil {
			return nil, nil, ErrResultShape
		}
		columns[index], err = column.Replace("Type", "varchar")
		if err != nil {
			return nil, nil, err
		}
	}
	metadataBytes, err := metadata.Replace("ColumnInfo", columns)
	if err != nil {
		return nil, nil, err
	}
	resultBytes, err := result.Replace("ResultSetMetadata", json.RawMessage(metadataBytes))
	if err != nil {
		return nil, nil, err
	}
	result, err = httpdb.DecodeEnvelope(resultBytes)
	if err != nil {
		return nil, nil, err
	}
	resultBytes, err = result.Replace("Rows", rows)
	if err != nil {
		return nil, nil, err
	}
	output, err := page.Replace("ResultSet", json.RawMessage(resultBytes))
	return output, digest, err
}

func requiredString(envelope *httpdb.Envelope, name string) (string, error) {
	raw := envelope.Field(name)
	if len(raw) == 0 || raw[0] != '"' {
		return "", fmt.Errorf("athena: %s must be a string", name)
	}
	var value string
	err := json.Unmarshal(raw, &value)
	return value, err
}
