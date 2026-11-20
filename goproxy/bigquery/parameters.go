package bigquery

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	sqlglot "github.com/ridi-oss/sqlglot-go"
	"github.com/ridi-oss/sqlglot-go/dialects"
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/generator"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// queryParameter is one entry of a request's queryParameters.
type queryParameter struct {
	Name          string `json:"name"`
	ParameterType *struct {
		Type             string          `json:"type"`
		ArrayType        json.RawMessage `json:"arrayType"`
		StructTypes      json.RawMessage `json:"structTypes"`
		RangeElementType json.RawMessage `json:"rangeElementType"`
	} `json:"parameterType"`
	ParameterValue *struct {
		Value        *string         `json:"value"`
		ArrayValues  json.RawMessage `json:"arrayValues"`
		StructValues json.RawMessage `json:"structValues"`
		RangeValue   json.RawMessage `json:"rangeValue"`
	} `json:"parameterValue"`
}

var scalarTypes = map[string]bool{
	"STRING": true, "BYTES": true, "INT64": true, "FLOAT64": true, "NUMERIC": true, "BIGNUMERIC": true, "BOOL": true,
	"DATE": true, "DATETIME": true, "TIME": true, "TIMESTAMP": true, "JSON": true, "GEOGRAPHY": true, "INTERVAL": true,
}

// sqlParameters turns typed query parameters into GoogleSQL literals the analyzer binds: NAMED keeps each
// name, POSITIONAL has none.
func sqlParameters(mode string, parameters []queryParameter) ([]*enginepb.HttpDbParameter, error) {
	if len(parameters) == 0 {
		return nil, nil
	}
	if mode != "NAMED" && mode != "POSITIONAL" {
		return nil, errors.New("bigquery: parameterMode must be NAMED or POSITIONAL")
	}
	out := make([]*enginepb.HttpDbParameter, 0, len(parameters))
	for _, parameter := range parameters {
		if (mode == "NAMED") != (parameter.Name != "") {
			return nil, errors.New("bigquery: a NAMED parameter needs a name and a POSITIONAL one has none")
		}
		kind := parameter.ParameterType
		if kind == nil || !scalarTypes[kind.Type] || kind.ArrayType != nil || kind.StructTypes != nil || kind.RangeElementType != nil {
			return nil, errors.New("bigquery: only scalar query parameters are supported")
		}
		var value *string
		if v := parameter.ParameterValue; v != nil {
			if v.ArrayValues != nil || v.StructValues != nil || v.RangeValue != nil {
				return nil, errors.New("bigquery: only scalar query parameters are supported")
			}
			value = v.Value
		}
		text, err := literal(kind.Type, value)
		if err != nil {
			return nil, err
		}
		out = append(out, &enginepb.HttpDbParameter{Name: parameter.Name, Value: text})
	}
	return out, nil
}

// literal is a typed value as GoogleSQL text the analyzer reads back: INT64 "7" is 7 (LIMIT takes only a
// literal), BYTES (base64 on the wire) FROM_BASE64, JSON PARSE_JSON, GEOGRAPHY ST_GEOGFROM, anything else a
// CAST; an absent value is a typed NULL.
func literal(kind string, value *string) (string, error) {
	dataType, err := exp.DataTypeFromStr(kind, bigqueryDialect, false, nil)
	if err != nil {
		return "", err
	}
	if value != nil && strings.ContainsFunc(*value, func(r rune) bool { return r < 0x20 && r != '\n' && r != '\r' && r != '\t' }) {
		return "", errors.New("bigquery: control character in a query parameter")
	}
	var node exp.Expression
	switch {
	case value == nil:
		node = exp.Cast(exp.Args{"this": exp.Null(), "to": dataType})
	case kind == "BYTES":
		if _, err := base64.StdEncoding.DecodeString(*value); err != nil {
			return "", fmt.Errorf("bigquery: BYTES parameter is not base64: %w", err)
		}
		node = exp.FromBase64(exp.Args{"this": exp.LiteralString(*value)})
	case kind == "JSON":
		node = exp.ParseJSON(exp.Args{"this": exp.LiteralString(*value)})
	case kind == "GEOGRAPHY":
		node = exp.Anonymous(exp.Args{"this": "ST_GEOGFROM", "expressions": []exp.Expression{exp.LiteralString(*value)}})
	default:
		if n, err := strconv.ParseInt(*value, 10, 64); kind == "INT64" && err == nil {
			node = exp.LiteralNumber(n)
		} else {
			node = exp.Cast(exp.Args{"this": exp.LiteralString(*value), "to": dataType})
		}
	}
	return sqlglot.Generate(node, bigqueryDialect, generator.Options{})
}

var bigqueryDialect = dialects.BigQuery()
