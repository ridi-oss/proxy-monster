package athena

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
)

// Athena keeps managed results for 24 hours; the enforcement context lives exactly that long.
const contextLifetime = 24 * time.Hour

// submissionScope is what a StartQueryExecution body says about where and how it runs; the query and
// parameters go to Decide, the workgroup and database are checked against the target scope, and the client
// token is namespaced per (datasource, principal) so a retry can never surface another principal's execution.
type submissionScope struct {
	query      string
	parameters []string
	workgroup  string
	database   string
	token      string
}

func readSubmission(envelope *httpdb.Envelope, defaults settings) (*submissionScope, error) {
	query, present, err := queryString(envelope)
	if err != nil || !present {
		return nil, errors.New("athena: QueryString is required")
	}
	parameters, _, err := executionParameters(envelope)
	if err != nil {
		return nil, err
	}
	if envelope.Field("ResultReuseConfiguration") != nil {
		return nil, ErrUnauthorized
	}
	scope := &submissionScope{query: query, parameters: parameters, workgroup: defaults.workgroup, database: defaults.database}
	if raw := envelope.Field("WorkGroup"); raw != nil {
		if err := json.Unmarshal(raw, &scope.workgroup); err != nil {
			return nil, errors.New("athena: WorkGroup must be a string")
		}
	}
	if raw := envelope.Field("ClientRequestToken"); raw != nil {
		if err := json.Unmarshal(raw, &scope.token); err != nil {
			return nil, errors.New("athena: ClientRequestToken must be a string")
		}
	}
	if raw := envelope.Field("QueryExecutionContext"); raw != nil {
		var context struct {
			Database *string `json:"Database"`
			Catalog  *string `json:"Catalog"`
		}
		if err := json.Unmarshal(raw, &context); err != nil {
			return nil, errors.New("athena: QueryExecutionContext must be an object")
		}
		if context.Database != nil && *context.Database != "" {
			scope.database = *context.Database
		}
	}
	return scope, nil
}

// applySubmission replaces the query string and execution parameters with the admitted ones.
func applySubmission(envelope *httpdb.Envelope, query string, parameters []string) (*httpdb.Envelope, error) {
	replaced, err := withQueryString(envelope, query)
	if err != nil {
		return nil, err
	}
	if len(parameters) == 0 {
		return replaced.WithoutField("ExecutionParameters")
	}
	return replaced.WithField("ExecutionParameters", parameters)
}

// pinScope forwards the submission in exactly the scope it was admitted for; AWS would otherwise fill an
// omitted workgroup or database with its own defaults.
func pinScope(envelope *httpdb.Envelope, cfg settings) (*httpdb.Envelope, error) {
	pinned, err := envelope.WithField("WorkGroup", cfg.workgroup)
	if err != nil {
		return nil, err
	}
	return pinned.WithField("QueryExecutionContext", map[string]string{"Catalog": cfg.catalog, "Database": cfg.database})
}

// executionID reads the QueryExecutionId AWS returned; a client-supplied id never reaches here.
func executionID(body []byte) (string, error) {
	envelope, err := httpdb.DecodeEnvelope(body)
	if err != nil {
		return "", err
	}
	raw := envelope.Field("QueryExecutionId")
	if raw == nil {
		return "", errors.New("athena: response carries no QueryExecutionId")
	}
	var id string
	if err := json.Unmarshal(raw, &id); err != nil || strings.TrimSpace(id) == "" || len(id) > 256 {
		return "", errors.New("athena: QueryExecutionId is malformed")
	}
	return id, nil
}

func queryString(e *httpdb.Envelope) (string, bool, error) {
	value := e.Field("QueryString")
	if value == nil {
		return "", false, nil
	}
	if len(value) == 0 || value[0] != '"' {
		return "", true, errors.New("athena: QueryString must be a string")
	}
	var query string
	err := json.Unmarshal(value, &query)
	return query, true, err
}

func executionParameters(e *httpdb.Envelope) ([]string, bool, error) {
	value := e.Field("ExecutionParameters")
	if value == nil {
		return nil, false, nil
	}
	if len(value) == 0 || value[0] != '[' {
		return nil, true, errors.New("athena: ExecutionParameters must be a string array")
	}
	var values []json.RawMessage
	if err := json.Unmarshal(value, &values); err != nil {
		return nil, true, err
	}
	parameters := make([]string, len(values))
	for i, value := range values {
		if len(value) == 0 || value[0] != '"' {
			return nil, true, errors.New("athena: ExecutionParameters must be a string array")
		}
		if err := json.Unmarshal(value, &parameters[i]); err != nil {
			return nil, true, err
		}
	}
	return parameters, true, nil
}

func withQueryString(e *httpdb.Envelope, query string) (*httpdb.Envelope, error) {
	original, present, err := queryString(e)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, errors.New("athena: QueryString is missing")
	}
	if query == original {
		return e, nil
	}
	body, err := e.Replace("QueryString", query)
	if err != nil {
		return nil, err
	}
	return httpdb.DecodeEnvelope(body)
}
