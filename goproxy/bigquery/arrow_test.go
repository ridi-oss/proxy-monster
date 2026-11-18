package bigquery

import (
	"bytes"
	"errors"
	"testing"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
)

// usersSchema is a session schema like BigQuery's for SELECT email, n, tags, address.
var usersSchema = arrow.NewSchema([]arrow.Field{
	{Name: "email", Type: arrow.BinaryTypes.String, Nullable: true},
	{Name: "n", Type: arrow.PrimitiveTypes.Int64, Nullable: true},
	{Name: "tags", Type: arrow.ListOf(arrow.BinaryTypes.String), Nullable: true},
	{Name: "address", Type: arrow.StructOf(arrow.Field{Name: "city", Type: arrow.BinaryTypes.String, Nullable: true}), Nullable: true},
}, nil)

// serializedArrow is a schema and one batch of rows as the Storage API sends them: separate IPC messages,
// the batch compressed when lz4 is set.
func serializedArrow(t *testing.T, schema *arrow.Schema, lz4 bool, fill func(*array.RecordBuilder)) (schemaBytes, batchBytes []byte) {
	t.Helper()
	builder := array.NewRecordBuilder(memory.DefaultAllocator, schema)
	defer builder.Release()
	fill(builder)
	batch := builder.NewRecordBatch()
	defer batch.Release()
	schemaPayload := ipc.GetSchemaPayload(schema, memory.DefaultAllocator)
	defer schemaPayload.Release()
	var out bytes.Buffer
	if _, err := schemaPayload.WritePayload(&out); err != nil {
		t.Fatal(err)
	}
	schemaBytes = bytes.Clone(out.Bytes())
	var options []ipc.Option
	if lz4 {
		options = append(options, ipc.WithLZ4())
	}
	batchPayload, err := ipc.GetRecordBatchPayload(batch, options...)
	if err != nil {
		t.Fatal(err)
	}
	defer batchPayload.Release()
	out.Reset()
	if _, err := batchPayload.WritePayload(&out); err != nil {
		t.Fatal(err)
	}
	return schemaBytes, out.Bytes()
}

func fillUsers(b *array.RecordBuilder) {
	email := b.Field(0).(*array.StringBuilder)
	email.Append("a@example.test")
	email.AppendNull()
	email.Append("bob@example.test")
	b.Field(1).(*array.Int64Builder).AppendValues([]int64{1, 2, 3}, nil)
	tags := b.Field(2).(*array.ListBuilder)
	for range 3 {
		tags.Append(true)
		tags.ValueBuilder().(*array.StringBuilder).Append("vip")
	}
	address := b.Field(3).(*array.StructBuilder)
	for range 3 {
		address.Append(true)
		address.FieldBuilder(0).(*array.StringBuilder).Append("Seoul")
	}
}

// readBatch decodes a masked batch as a client does, under the schema the session gave it.
func readBatch(t *testing.T, schemaBytes, batchBytes []byte) arrow.RecordBatch {
	t.Helper()
	reader, err := ipc.NewReader(bytes.NewReader(append(bytes.Clone(schemaBytes), batchBytes...)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Release)
	if !reader.Next() {
		t.Fatalf("no batch: %v", reader.Err())
	}
	batch := reader.RecordBatch()
	batch.Retain()
	t.Cleanup(batch.Release)
	return batch
}

func TestArrowMaskerMasksOnlyTheMaskedColumns(t *testing.T) {
	for _, lz4 := range []bool{false, true} {
		schemaBytes, batchBytes := serializedArrow(t, usersSchema, lz4, fillUsers)
		masker, err := newArrowMasker(schemaBytes, map[int]string{0: "LAST_N", 1: "FIXED"})
		if err != nil {
			t.Fatal(err)
		}
		masked, err := masker.maskBatch(batchBytes)
		if err != nil {
			t.Fatal(err)
		}
		batch := readBatch(t, masker.schema, masked)
		if batch.NumRows() != 3 || !arrow.TypeEqual(batch.Schema().Field(1).Type, arrow.BinaryTypes.String) || !arrow.TypeEqual(batch.Schema().Field(2).Type, usersSchema.Field(2).Type) {
			t.Fatalf("masked schema: %v", batch.Schema())
		}
		email, n := batch.Column(0).(*array.String), batch.Column(1).(*array.String)
		if email.Value(0) != "**********test" || email.IsValid(1) || email.Value(2) != "************test" {
			t.Fatalf("email not masked: %v", email)
		}
		if n.Value(0) != "####" || n.Value(2) != "####" {
			t.Fatalf("n not masked: %v", n)
		}
		if tags := batch.Column(2).(*array.List); tags.ValueStr(0) != `["vip"]` {
			t.Fatalf("unmasked column changed: %v", tags)
		}
		if city := batch.Column(3).(*array.Struct).Field(0).(*array.String); city.Value(2) != "Seoul" {
			t.Fatalf("unmasked column changed: %v", city)
		}
	}
}

func TestArrowMaskerNullMaskKeepsTheType(t *testing.T) {
	schemaBytes, batchBytes := serializedArrow(t, usersSchema, false, fillUsers)
	masker, err := newArrowMasker(schemaBytes, map[int]string{1: "NULL"})
	if err != nil {
		t.Fatal(err)
	}
	masked, err := masker.maskBatch(batchBytes)
	if err != nil {
		t.Fatal(err)
	}
	batch := readBatch(t, masker.schema, masked)
	if n := batch.Column(1); !arrow.TypeEqual(n.DataType(), arrow.PrimitiveTypes.Int64) || n.NullN() != 3 {
		t.Fatalf("NULL mask: %v", n)
	}
	if email := batch.Column(0).(*array.String); email.Value(0) != "a@example.test" {
		t.Fatalf("unmasked column changed: %v", email)
	}
}

func TestArrowMaskerWithoutMasksPassesBatchesThrough(t *testing.T) {
	schemaBytes, batchBytes := serializedArrow(t, usersSchema, true, fillUsers)
	masker, err := newArrowMasker(schemaBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := masker.maskBatch(batchBytes); err != nil || !bytes.Equal(out, batchBytes) {
		t.Fatalf("unmasked batch altered: %v", err)
	}
}

func TestArrowMaskerRefusesNestedMaskedColumns(t *testing.T) {
	schemaBytes, _ := serializedArrow(t, usersSchema, false, fillUsers)
	for _, index := range []int{2, 3, 4} {
		for _, kind := range []string{"FIXED", "NULL"} {
			if _, err := newArrowMasker(schemaBytes, map[int]string{index: kind}); !errors.Is(err, httpdb.ErrResultShape) {
				t.Fatalf("mask %s on field %d: %v", kind, index, err)
			}
		}
	}
	dictionary := arrow.NewSchema([]arrow.Field{{Name: "email", Type: &arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Int32, ValueType: arrow.BinaryTypes.String}}}, nil)
	payload := ipc.GetSchemaPayload(dictionary, memory.DefaultAllocator)
	defer payload.Release()
	var out bytes.Buffer
	if _, err := payload.WritePayload(&out); err != nil {
		t.Fatal(err)
	}
	if _, err := newArrowMasker(out.Bytes(), nil); !errors.Is(err, httpdb.ErrResultShape) {
		t.Fatalf("dictionary schema: %v", err)
	}
}

func TestArrowMaskerRefusesABatchOfAnotherShape(t *testing.T) {
	schemaBytes, _ := serializedArrow(t, usersSchema, false, fillUsers)
	other := arrow.NewSchema([]arrow.Field{{Name: "email", Type: arrow.BinaryTypes.String, Nullable: true}}, nil)
	_, batchBytes := serializedArrow(t, other, false, func(b *array.RecordBuilder) { b.Field(0).(*array.StringBuilder).Append("a@example.test") })
	masker, err := newArrowMasker(schemaBytes, map[int]string{0: "FIXED"})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := masker.maskBatch(batchBytes); err == nil {
		t.Fatalf("batch of another shape masked: %x", out)
	}
	if _, err := masker.maskBatch([]byte("not arrow")); err == nil {
		t.Fatal("garbage masked")
	}
}
