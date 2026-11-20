package bigquery

import (
	"bytes"
	"errors"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"google.golang.org/protobuf/proto"
)

// arrowMasker masks the record batches of one Arrow read session: kinds holds the mask kind of each masked
// field by its index in the session schema. A masked field becomes a nullable string, as on the REST
// side; a NULL mask keeps the field's type.
type arrowMasker struct {
	upstream *arrow.Schema
	masked   *arrow.Schema
	// schema is the serialized schema the client is given.
	schema []byte
	kinds  map[int]string
	rows   *relay.RowMasker
}

// newArrowMasker reads the session's serialized Arrow schema and plans its masks. A masked field must be a
// scalar, and no field may be dictionary-encoded, since batches are decoded without dictionary messages.
func newArrowMasker(serializedSchema []byte, kinds map[int]string) (*arrowMasker, error) {
	reader, err := ipc.NewReader(bytes.NewReader(serializedSchema))
	if err != nil {
		return nil, httpdb.ErrResultShape
	}
	upstream := reader.Schema()
	reader.Release()
	fields := upstream.Fields()
	masks := make([]*pb.ColumnMask, 0, len(kinds))
	for index, kind := range kinds {
		if index < 0 || index >= len(fields) || !maskableArrowType(fields[index].Type) {
			return nil, httpdb.ErrResultShape
		}
		masks = append(masks, &pb.ColumnMask{Kind: kind, Ordinal: proto.Int32(int32(index))})
		field := arrow.Field{Name: fields[index].Name, Type: arrow.BinaryTypes.String, Nullable: true}
		if kind == "NULL" {
			field.Type = fields[index].Type
		}
		fields[index] = field
	}
	for _, field := range fields {
		if hasDictionary(field.Type) {
			return nil, httpdb.ErrResultShape
		}
	}
	rows := relay.NewRowMasker(masks, len(fields))
	if rows == nil {
		return nil, relay.ErrMaskUnbound
	}
	metadata := upstream.Metadata()
	masked := arrow.NewSchema(fields, &metadata)
	payload := ipc.GetSchemaPayload(masked, memory.DefaultAllocator)
	defer payload.Release()
	var schema bytes.Buffer
	if _, err := payload.WritePayload(&schema); err != nil {
		return nil, err
	}
	return &arrowMasker{upstream: upstream, masked: masked, schema: schema.Bytes(), kinds: kinds, rows: rows}, nil
}

func maskableArrowType(t arrow.DataType) bool {
	switch id := t.ID(); {
	case arrow.IsNested(id), id == arrow.DICTIONARY, id == arrow.EXTENSION, id == arrow.RUN_END_ENCODED, id == arrow.NULL:
		return false
	}
	return true
}

func hasDictionary(t arrow.DataType) bool {
	if t.ID() == arrow.DICTIONARY {
		return true
	}
	if nested, ok := t.(arrow.NestedType); ok {
		for _, child := range nested.Fields() {
			if hasDictionary(child.Type) {
				return true
			}
		}
	}
	return false
}

var errBatchShape = errors.New("bigquery: record batch does not match its session schema")

// maskBatch decodes one serialized record batch under the session's upstream schema, masks it, and
// serializes it again under the masked schema, uncompressed.
func (m *arrowMasker) maskBatch(serialized []byte) ([]byte, error) {
	if len(m.kinds) == 0 {
		return serialized, nil
	}
	upstream := ipc.GetSchemaPayload(m.upstream, memory.DefaultAllocator)
	defer upstream.Release()
	var stream bytes.Buffer
	if _, err := upstream.WritePayload(&stream); err != nil {
		return nil, err
	}
	stream.Write(serialized)
	reader, err := ipc.NewReader(&stream, ipc.WithSchema(m.upstream))
	if err != nil {
		return nil, errBatchShape
	}
	defer reader.Release()
	if !reader.Next() {
		return nil, errBatchShape
	}
	batch := reader.RecordBatch()
	batch.Retain()
	defer batch.Release()
	if reader.Next() || reader.Err() != nil || !batch.Schema().Equal(m.upstream) {
		return nil, errBatchShape
	}
	masked, err := m.maskRecord(batch)
	if err != nil {
		return nil, err
	}
	defer masked.Release()
	payload, err := ipc.GetRecordBatchPayload(masked)
	if err != nil {
		return nil, err
	}
	defer payload.Release()
	var out bytes.Buffer
	if _, err := payload.WritePayload(&out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (m *arrowMasker) maskRecord(batch arrow.RecordBatch) (arrow.RecordBatch, error) {
	rows := int(batch.NumRows())
	columns := make([]arrow.Array, batch.NumCols())
	for i := range columns {
		columns[i] = batch.Column(i)
		columns[i].Retain()
	}
	defer func() {
		for _, column := range columns {
			column.Release()
		}
	}()
	for index, kind := range m.kinds {
		if kind == "NULL" {
			columns[index].Release()
			columns[index] = array.MakeArrayOfNull(memory.DefaultAllocator, m.upstream.Field(index).Type, rows)
			continue
		}
		builder := array.NewStringBuilder(memory.DefaultAllocator)
		values := make([]*string, len(columns))
		source := columns[index]
		for row := range rows {
			values[index] = nil
			if source.IsValid(row) {
				text := source.ValueStr(row)
				values[index] = &text
			}
			if masked := m.rows.Apply(values)[index]; masked != nil {
				builder.Append(*masked)
			} else {
				builder.AppendNull()
			}
		}
		source.Release()
		columns[index] = builder.NewArray()
		builder.Release()
	}
	return array.NewRecordBatch(m.masked, columns, int64(rows)), nil
}
