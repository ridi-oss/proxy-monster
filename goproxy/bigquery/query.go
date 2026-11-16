package bigquery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
)

// resultWait is how long one jobs.query or getQueryResults call waits for the job before it answers.
const resultWait = 10_000

// queryRequest is a jobs.query body the proxy sends with its own credentials; startQuery pins the rest.
type queryRequest struct {
	Query           string            `json:"query"`
	UseLegacySQL    bool              `json:"useLegacySql"`
	Location        string            `json:"location"`
	JobCreationMode string            `json:"jobCreationMode"`
	TimeoutMs       int               `json:"timeoutMs"`
	MaxResults      int               `json:"maxResults,omitempty"`
	DefaultDataset  *datasetReference `json:"defaultDataset,omitempty"`
	ParameterMode   string            `json:"parameterMode,omitempty"`
	QueryParameters []stringParameter `json:"queryParameters,omitempty"`
}

type datasetReference struct {
	ProjectID string `json:"projectId"`
	DatasetID string `json:"datasetId"`
}

// stringParameter is a named STRING query parameter.
type stringParameter struct {
	Name           string            `json:"name"`
	ParameterType  map[string]string `json:"parameterType"`
	ParameterValue map[string]string `json:"parameterValue"`
}

func namedString(name, value string) stringParameter {
	return stringParameter{Name: name, ParameterType: map[string]string{"type": "STRING"}, ParameterValue: map[string]string{"value": value}}
}

// tableField is one column of a result or table schema; a RECORD carries its own fields.
type tableField struct {
	Name        string       `json:"name"`
	Type        string       `json:"type"`
	Mode        string       `json:"mode"`
	Description *string      `json:"description"`
	Fields      []tableField `json:"fields"`
}

// queryPage is the part of a jobs.query or getQueryResults response the proxy reads.
type queryPage struct {
	JobComplete        bool          `json:"jobComplete"`
	JobReference       *jobReference `json:"jobReference"`
	PageToken          string        `json:"pageToken"`
	NumDMLAffectedRows string        `json:"numDmlAffectedRows"`
	Schema             *struct {
		Fields []tableField `json:"fields"`
	} `json:"schema"`
	Rows []struct {
		F []struct {
			V json.RawMessage `json:"v"`
		} `json:"f"`
	} `json:"rows"`
}

// values reads each cell as text: a scalar is its string, NULL is nil, and a RECORD or REPEATED cell is its JSON.
func (p *queryPage) values() ([][]*string, error) {
	width := 0
	if p.Schema != nil {
		width = len(p.Schema.Fields)
	}
	rows := make([][]*string, 0, len(p.Rows))
	for _, row := range p.Rows {
		if len(row.F) != width {
			return nil, httpdb.ErrResultShape
		}
		values := make([]*string, width)
		for i, cell := range row.F {
			if len(cell.V) == 0 || string(cell.V) == "null" {
				continue
			}
			text := string(cell.V)
			if cell.V[0] == '"' && json.Unmarshal(cell.V, &text) != nil {
				return nil, httpdb.ErrResultShape
			}
			values[i] = &text
		}
		rows = append(rows, values)
	}
	return rows, nil
}

// startQuery submits SQL as a jobs.query that must create a job, in the target's location.
func (t *target) startQuery(ctx context.Context, request queryRequest) (*queryPage, []byte, error) {
	request.Location, request.JobCreationMode, request.UseLegacySQL = t.location, "JOB_CREATION_REQUIRED", false
	if request.TimeoutMs == 0 {
		request.TimeoutMs = resultWait
	}
	var raw json.RawMessage
	if err := t.call(ctx, http.MethodPost, projectPath(t.project)+"/queries", nil, request, &raw); err != nil {
		return nil, nil, err
	}
	return decodePage(raw)
}

// resultPage reads job's page at pageToken, the first when empty, waiting for the job to complete.
func (t *target) resultPage(ctx context.Context, job *jobReference, pageToken string, maxResults int) (*queryPage, []byte, error) {
	if _, err := job.id(); err != nil {
		return nil, nil, err
	}
	query := url.Values{"location": {job.Location}, "timeoutMs": {strconv.Itoa(resultWait)}}
	if pageToken != "" {
		query.Set("pageToken", pageToken)
	}
	if maxResults > 0 {
		query.Set("maxResults", strconv.Itoa(maxResults))
	}
	var raw json.RawMessage
	if err := t.call(ctx, http.MethodGet, projectPath(job.ProjectID)+"/queries/"+url.PathEscape(job.JobID), query, nil, &raw); err != nil {
		return nil, nil, err
	}
	return decodePage(raw)
}

func decodePage(raw []byte) (*queryPage, []byte, error) {
	var page queryPage
	if err := json.Unmarshal(raw, &page); err != nil {
		return nil, nil, httpdb.ErrResultShape
	}
	if _, err := page.JobReference.id(); err != nil {
		return nil, nil, err
	}
	return &page, raw, nil
}

// queryRows runs a metadata query and reads every row of its result.
func (t *target) queryRows(ctx context.Context, request queryRequest) ([][]*string, error) {
	page, _, err := t.startQuery(ctx, request)
	var rows [][]*string
	token, seen := "", map[string]bool{}
	for err == nil {
		if page.JobComplete {
			values, err := page.values()
			if err != nil {
				return nil, err
			}
			rows = append(rows, values...)
			if page.PageToken == "" {
				return rows, nil
			}
			if seen[page.PageToken] {
				return nil, errors.New("bigquery: repeated result page token")
			}
			seen[page.PageToken], token = true, page.PageToken
		}
		page, _, err = t.resultPage(ctx, page.JobReference, token, 0)
	}
	return nil, err
}
