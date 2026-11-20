package bigquery

import (
	"encoding/json"

	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
)

// diagnosticKeys are the free-text fields through which BigQuery echoes stored values: errors[] and
// errorResult carry message and debugInfo.
var diagnosticKeys = []string{"message", "debugInfo"}

// maskPage masks one jobs.query or getQueryResults page in place: schema.fields[i] describes rows[].f[i].v.
// A page with neither schema nor rows (jobComplete false) has nothing to mask. A masked column must be a
// scalar, and its type becomes STRING.
func maskPage(body []byte, verdict *pb.Verdict, expectedWidth *int32, metadataDigest []byte) ([]byte, []byte, error) {
	page, err := httpdb.DecodeEnvelope(body)
	if err != nil {
		return nil, nil, httpdb.ErrResultShape
	}
	if page.Field("schema") == nil && page.Field("rows") == nil {
		return redact(body, verdict, nil)
	}
	if verdict.Decision == pb.EnfAction_ALLOW {
		return redact(body, verdict, nil)
	}
	schema, err := httpdb.DecodeEnvelope(page.Field("schema"))
	if err != nil {
		return nil, nil, httpdb.ErrResultShape
	}
	var fields []json.RawMessage
	if err := json.Unmarshal(schema.Field("fields"), &fields); err != nil || fields == nil {
		return nil, nil, httpdb.ErrResultShape
	}
	if err := httpdb.CheckWidth(expectedWidth, len(fields)); err != nil {
		return nil, nil, err
	}
	masker := relay.NewRowMasker(verdict.Masks, len(fields))
	if masker == nil {
		return nil, nil, relay.ErrMaskUnbound
	}
	digest, err := httpdb.ColumnDigest(schema.Field("fields"), metadataDigest)
	if err != nil {
		return nil, nil, err
	}
	masked := relay.BindMasks(verdict.Masks, len(fields)).ByIndex
	for index, kind := range masked {
		var field struct{ Type, Mode string }
		if err := json.Unmarshal(fields[index], &field); err != nil || field.Type == "" ||
			field.Type == "RECORD" || field.Type == "STRUCT" || field.Mode == "REPEATED" {
			return nil, nil, httpdb.ErrResultShape
		}
		if kind == "NULL" {
			continue
		}
		column, err := httpdb.DecodeEnvelope(fields[index])
		if err != nil {
			return nil, nil, httpdb.ErrResultShape
		}
		if fields[index], err = column.Replace("type", "STRING"); err != nil {
			return nil, nil, httpdb.ErrResultShape
		}
	}
	var rows []json.RawMessage
	if raw := page.Field("rows"); raw != nil {
		if err := json.Unmarshal(raw, &rows); err != nil {
			return nil, nil, httpdb.ErrResultShape
		}
	}
	for i, rawRow := range rows {
		row, err := httpdb.DecodeEnvelope(rawRow)
		if err != nil {
			return nil, nil, httpdb.ErrResultShape
		}
		var cells []json.RawMessage
		if err := json.Unmarshal(row.Field("f"), &cells); err != nil || len(cells) != len(fields) {
			return nil, nil, httpdb.ErrResultShape
		}
		values := make([]*string, len(cells))
		for j := range masked {
			var cell struct{ V *string }
			if err := json.Unmarshal(cells[j], &cell); err != nil {
				return nil, nil, httpdb.ErrResultShape
			}
			values[j] = cell.V
		}
		for j, value := range masker.Apply(values) {
			if _, ok := masked[j]; !ok {
				continue
			}
			cell, err := httpdb.DecodeEnvelope(cells[j])
			if err != nil {
				return nil, nil, httpdb.ErrResultShape
			}
			if cells[j], err = cell.Replace("v", value); err != nil {
				return nil, nil, httpdb.ErrResultShape
			}
		}
		if rows[i], err = row.Replace("f", cells); err != nil {
			return nil, nil, err
		}
	}
	schemaBytes, err := schema.Replace("fields", fields)
	if err != nil {
		return nil, nil, err
	}
	output, err := page.Replace("schema", json.RawMessage(schemaBytes))
	if err != nil {
		return nil, nil, err
	}
	if rows != nil {
		if page, err = httpdb.DecodeEnvelope(output); err != nil {
			return nil, nil, err
		}
		if output, err = page.Replace("rows", rows); err != nil {
			return nil, nil, err
		}
	}
	return redact(output, verdict, digest)
}

func redact(body []byte, verdict *pb.Verdict, digest []byte) ([]byte, []byte, error) {
	if !verdict.SanitizeDiagnostics {
		return body, digest, nil
	}
	redacted, err := httpdb.RedactDiagnostics(body, diagnosticKeys)
	return redacted, digest, err
}
