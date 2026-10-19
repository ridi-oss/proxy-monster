package datasources

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/analyzer/engines"
	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

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

// classificationTarget is the column a request names, as SQL identifier text.
type classificationTarget struct {
	Schema  *string `json:"schema"`
	Table   *string `json:"table"`
	Column  *string `json:"column"`
	Catalog *string `json:"catalog"`
}

// decode reads the body; Kotlin answers one that does not decode, or lacks table, column or catalog, with 500.
func (c *classificationTarget) decode(r *http.Request, v any) error {
	if api.DecodeBody(r, v) != nil || c.Table == nil || c.Column == nil || c.Catalog == nil {
		return errors.New("classification body does not decode")
	}
	return nil
}

func (c *classificationTarget) required() error {
	if err := api.Required("table", *c.Table); err != nil {
		return err
	}
	return api.Required("column", *c.Column)
}

// namer spells a datasource's names as its engine does. err is why it cannot (MySQL before introspection
// reports lower_case_table_names), answered only when a name actually has to be spelled.
type namer struct {
	ds     datasource
	engine *engines.Session
	err    error
}

func newNamer(ds datasource) namer {
	bound, err := bindEngine(ds)
	return namer{ds, bound, err}
}

func bindEngine(ds datasource) (*engines.Session, error) {
	engine, err := engines.Parse(ds.Engine)
	if err != nil {
		return nil, err
	}
	reported := &pb.TargetSettings{Properties: map[string]string{}}
	if ds.EngineVersion != nil {
		reported.EngineVersion = *ds.EngineVersion
	}
	if ds.MySQLLowerCaseTableNames != nil {
		n := int32(*ds.MySQLLowerCaseTableNames)
		reported.MysqlLowerCaseTableNames = &n
	}
	if ds.ConnectionInfo != nil {
		var info struct {
			Properties map[string]string `json:"properties"`
		}
		if err := json.Unmarshal(ds.ConnectionInfo, &info); err != nil {
			return nil, err
		}
		for k, v := range info.Properties {
			reported.Properties[k] = v
		}
	}
	bound, err := engine.NewSession(reported)
	if err != nil {
		return nil, api.CodeCaseModeUnknown.Err()
	}
	return bound, nil
}

// defaultSchema is the first stored default schema that is not a system one, quoted so it keeps the target's
// spelling, or "" when there is none.
func (n namer) defaultSchema() (string, error) {
	for _, stored := range n.ds.DefaultSchemas {
		if n.err != nil {
			return "", n.err
		}
		if !n.engine.Engine().IsSystemSchema(n.engine.CatalogSchemaName(&pb.Column{Schema: stored})) {
			return n.engine.Engine().QuoteIdentifier(stored), nil
		}
	}
	return "", nil
}

// column parses a column a person named; its catalog must be the datasource's.
func (n namer) column(catalog, schema, table, column string) (engines.ColumnName, error) {
	if n.err != nil {
		return engines.ColumnName{}, n.err
	}
	key, err := n.engine.ParseColumn(catalog, schema, table, column)
	if err != nil {
		return key, api.CodeInvalidValue.Err("field", "column")
	}
	effective := n.engine.Engine().CatalogName(n.ds.DBName).String()
	if n.ds.CurrentCatalog != nil {
		effective = *n.ds.CurrentCatalog
	}
	if c := key.Catalog().String(); strings.TrimSpace(c) == "" || c != effective {
		return key, api.CodeInvalidCatalog.Err()
	}
	return key, nil
}

// requireWritableTags refuses a system: name the product does not define.
func requireWritableTags(tags []string) error {
	for _, tag := range tags {
		switch tag {
		case "system:critical", "system:data-leak", "system:activity", "system:catalog", "system:development", "system:production":
		default:
			if strings.HasPrefix(tag, "system:") {
				return api.CodeReservedTag.Err("tag", tag)
			}
		}
	}
	return nil
}

// decodeTags reads an absent tags field as none; null or a null element fails like any other bad body, never
// reading as an empty set that would clear the column's masking.
func decodeTags(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return []string{}, nil
	}
	var tags []*string
	if err := json.Unmarshal(raw, &tags); err != nil || tags == nil || slices.Contains(tags, nil) {
		return nil, errors.New("classification tags do not decode")
	}
	out := make([]string, len(tags))
	for i, tag := range tags {
		out[i] = *tag
	}
	return out, nil
}

func tagsJSON(tags []string) []byte {
	b, _ := json.Marshal(tags)
	return b
}

func recordColumn(ctx context.Context, tx pgx.Tx, actor audit.Actor, ds string, key engines.ColumnName, summary string) error {
	path := key.Schema().String() + "." + key.Table() + "." + key.Column()
	return audit.Admin(ctx, tx, actor, "admin.datasources", audit.Entity("Datasource", ds)+" col "+path, summary)
}

func columnPath(ds string, key engines.ColumnName) string {
	return ds + "." + key.Schema().String() + "." + key.Table() + "." + key.Column()
}

// setClassification tags one column, replacing its tags and mask function.
func (d datasources) setClassification(w http.ResponseWriter, r *http.Request, id int64) error {
	var in struct {
		classificationTarget
		Tags     json.RawMessage `json:"tags"`
		MaskFnID *int64          `json:"maskFnId"`
	}
	if err := in.decode(r, &in); err != nil {
		return err
	}
	tags, err := decodeTags(in.Tags)
	if err != nil {
		return err
	}
	if err := in.required(); err != nil {
		return err
	}
	return api.Mutate(d.pool, w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		ds, err := getDatasource(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		n := newNamer(ds)
		if in.Schema == nil {
			def, err := n.defaultSchema()
			if err != nil {
				return nil, err
			}
			if def == "" {
				return nil, api.CodeSchemaRequired.Err()
			}
		}
		if err := requireWritableTags(tags); err != nil {
			return nil, err
		}
		schema := ""
		if in.Schema != nil && strings.TrimSpace(*in.Schema) != "" {
			schema = *in.Schema
		} else if schema, err = n.defaultSchema(); err != nil {
			return nil, err
		}
		if schema == "" {
			return nil, errors.New("schema is required until introspection captures a default schema")
		}
		key, err := n.column(*in.Catalog, schema, *in.Table, *in.Column)
		if err != nil {
			return nil, err
		}
		q := db.New(tx)
		if err := q.SetClassification(ctx, db.SetClassificationParams{DatasourceID: id, CatalogName: key.Catalog().String(),
			SchemaName: key.Schema().String(), TableName: key.Table(), ColumnName: key.Column(), Tags: tagsJSON(tags), MaskFnID: in.MaskFnID}); err != nil {
			return nil, err
		}
		out := classification{Schema: key.Schema().String(), Table: key.Table(), Column: key.Column(), Tags: tags, MaskFnID: in.MaskFnID, Catalog: key.Catalog().String()}
		if in.MaskFnID != nil {
			name, err := q.LiveMaskFnName(ctx, *in.MaskFnID)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return nil, err
			}
			if err == nil {
				out.MaskFnName = &name
			}
		}
		return out, recordColumn(ctx, tx, actor, ds.Name, key, "tag "+columnPath(ds.Name, key)+" ["+strings.Join(tags, ", ")+"]")
	})
}

// clearClassification removes a column's tags; clearing an untagged column still answers 204.
func (d datasources) clearClassification(w http.ResponseWriter, r *http.Request, id int64) error {
	var in classificationTarget
	if err := in.decode(r, &in); err != nil {
		return err
	}
	if err := in.required(); err != nil {
		return err
	}
	return api.Mutate(d.pool, w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		ds, err := getDatasource(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		n := newNamer(ds)
		var schema string
		if in.Schema != nil {
			schema = *in.Schema
		} else if schema, err = n.defaultSchema(); err != nil {
			return nil, err
		} else if schema == "" {
			return nil, api.CodeSchemaRequired.Err()
		}
		key, err := n.column(*in.Catalog, schema, *in.Table, *in.Column)
		if err != nil {
			return nil, err
		}
		deleted, err := db.New(tx).ClearClassification(ctx, db.ClearClassificationParams{DatasourceID: id, CatalogName: key.Catalog().String(),
			SchemaName: key.Schema().String(), TableName: key.Table(), ColumnName: key.Column()})
		if err != nil || deleted == 0 {
			return nil, err
		}
		return nil, recordColumn(ctx, tx, actor, ds.Name, key, "clear tags on "+columnPath(ds.Name, key))
	})
}
