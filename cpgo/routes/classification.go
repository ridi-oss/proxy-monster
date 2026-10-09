package routes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/engine"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

// shippedTags are the system: names the product defines; any other system: name is reserved.
var shippedTags = []string{
	"system:critical", "system:data-leak", "system:activity", "system:catalog",
	"system:development", "system:production",
}

// classification is the engine module's Classification, fields in declaration order.
type classification struct {
	Schema     string   `json:"schema"`
	Table      string   `json:"table"`
	Column     string   `json:"column"`
	Tags       []string `json:"tags"`
	MaskFnID   *int64   `json:"maskFnId,omitempty"`
	MaskFnName *string  `json:"maskFnName,omitempty"`
	Catalog    string   `json:"catalog"`
}

// defaultSchema is the first default schema that is not a system one, which an unqualified column means.
func (ds *datasource) defaultSchema() *string {
	def, _ := engine.ByWireName(ds.Engine)
	for _, s := range ds.DefaultSchemas {
		if !def.IsSystemSchema(s) {
			return &s
		}
	}
	return nil
}

// requireCatalog accepts only this datasource's catalog: the one it reported, else its engine's name for it.
func (ds *datasource) requireCatalog(catalog string) error {
	def, _ := engine.ByWireName(ds.Engine)
	effective := def.CatalogName(ds.DBName)
	if ds.CurrentCatalog != nil {
		effective = *ds.CurrentCatalog
	}
	if strings.TrimSpace(catalog) == "" || catalog != effective {
		return &managementError{code: "datasource.invalid_catalog"}
	}
	return nil
}

func columnEntity(ds, schema, table, column string) string {
	return audit.Entity("Datasource", ds) + " col " + schema + "." + table + "." + column
}

type classificationTarget struct {
	Schema  *string `json:"schema"`
	Table   *string `json:"table"`
	Column  *string `json:"column"`
	Catalog *string `json:"catalog"`
}

func (c classificationTarget) missing() bool {
	return c.Table == nil || c.Column == nil || c.Catalog == nil
}

// setClassification tags one column, replacing its tags and mask function.
func (d datasources) setClassification(w http.ResponseWriter, r *http.Request, id int64) {
	var in struct {
		classificationTarget
		RawTags  json.RawMessage `json:"tags"`
		MaskFnID *int64          `json:"maskFnId"`
		Tags     []string        `json:"-"`
	}
	err := decodeBody(r, &in)
	if err == nil && !in.missing() {
		in.Tags, err = decodeTags(in.RawTags)
	}
	if err != nil || in.missing() {
		writeMutationError(w, &managementError{code: "common.invalid_value", params: api.Params{{"field", "body"}}})
		return
	}
	mutate(d.pool, w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if err := required("table", *in.Table); err != nil {
			return nil, err
		}
		if err := required("column", *in.Column); err != nil {
			return nil, err
		}
		ds, err := getDatasource(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		def := ds.defaultSchema()
		if in.Schema == nil && def == nil {
			return nil, &managementError{code: "datasource.schema_required"}
		}
		for _, tag := range in.Tags {
			if strings.HasPrefix(tag, "system:") && !slices.Contains(shippedTags, tag) {
				return nil, &managementError{code: "datasource.reserved_tag", params: api.Params{{"tag", tag}}}
			}
		}
		schema := def
		if in.Schema != nil && strings.TrimSpace(*in.Schema) != "" {
			schema = in.Schema
		}
		if schema == nil {
			return nil, errors.New("schema is required until introspection captures a default schema")
		}
		if err := ds.requireCatalog(*in.Catalog); err != nil {
			return nil, err
		}
		q := db.New(tx)
		if err := q.SetClassification(ctx, db.SetClassificationParams{DatasourceID: id, SchemaName: *schema, TableName: *in.Table,
			ColumnName: *in.Column, Tags: tagsJSON(in.Tags), MaskFnID: in.MaskFnID, CatalogName: *in.Catalog}); err != nil {
			return nil, err
		}
		out := classification{Schema: *schema, Table: *in.Table, Column: *in.Column, Tags: in.Tags, MaskFnID: in.MaskFnID, Catalog: *in.Catalog}
		if in.MaskFnID != nil {
			name, err := q.LiveMaskFnName(ctx, *in.MaskFnID)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return nil, err
			}
			if err == nil {
				out.MaskFnName = &name
			}
		}
		path := out.Schema + "." + out.Table + "." + out.Column
		return out, audit.Admin(ctx, tx, actor, "admin.datasources", columnEntity(ds.Name, out.Schema, out.Table, out.Column),
			"tag "+ds.Name+"."+path+" ["+strings.Join(out.Tags, ", ")+"]")
	})
}

// clearClassification removes a column's tags; clearing an untagged column still answers 204.
func (d datasources) clearClassification(w http.ResponseWriter, r *http.Request, id int64) {
	var in classificationTarget
	if err := decodeBody(r, &in); err != nil || in.missing() {
		writeMutationError(w, &managementError{code: "common.invalid_value", params: api.Params{{"field", "body"}}})
		return
	}
	mutate(d.pool, w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if err := required("table", *in.Table); err != nil {
			return nil, err
		}
		if err := required("column", *in.Column); err != nil {
			return nil, err
		}
		ds, err := getDatasource(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		schema := in.Schema
		if schema == nil {
			schema = ds.defaultSchema()
		}
		if schema == nil {
			return nil, &managementError{code: "datasource.schema_required"}
		}
		if err := ds.requireCatalog(*in.Catalog); err != nil {
			return nil, err
		}
		n, err := db.New(tx).ClearClassification(ctx, db.ClearClassificationParams{DatasourceID: id, SchemaName: *schema,
			TableName: *in.Table, ColumnName: *in.Column, CatalogName: *in.Catalog})
		if err != nil || n == 0 {
			return nil, err
		}
		return nil, audit.Admin(ctx, tx, actor, "admin.datasources", columnEntity(ds.Name, *schema, *in.Table, *in.Column),
			"clear tags on "+ds.Name+"."+*schema+"."+*in.Table+"."+*in.Column)
	})
}

func tagsJSON(tags []string) []byte {
	b, _ := json.Marshal(tags)
	return b
}

// decodeTags reads an absent tags field as none, and refuses null or a null element rather than reading
// either as an empty tag set, which would clear a column's masking.
func decodeTags(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return []string{}, nil
	}
	var tags []*string
	if err := json.Unmarshal(raw, &tags); err != nil || tags == nil {
		return nil, errors.New("tags must be an array of strings")
	}
	out := make([]string, len(tags))
	for i, tag := range tags {
		if tag == nil {
			return nil, errors.New("tags must be an array of strings")
		}
		out[i] = *tag
	}
	return out, nil
}
