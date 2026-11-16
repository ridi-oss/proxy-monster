package bigquery

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/ridi-oss/proxy-monster/goproxy/httpdb"
)

const apiPrefix = "/bigquery/v2/"

// route is one REST method the proxy forwards; its pattern is the path under /bigquery/v2/, and params are
// the query parameters it may carry besides alt and prettyPrint.
type route struct {
	name, method, pattern string
	kind                  httpdb.Kind
	params                []string
}

var (
	pageParams = []string{"maxResults", "pageToken"}
	location   = []string{"location"}
)

const (
	datasetPath = "projects/{p}/datasets/{d}"
	tablePath   = datasetPath + "/tables/{t}"
	routinePath = datasetPath + "/routines/{t}"
)

// routes is every method the proxy forwards; an unlisted one, such as tabledata.list, is refused.
var routes = []route{
	{"jobs.query", "POST", "projects/{p}/queries", httpdb.KindSubmission, nil},
	{"jobs.insert", "POST", "projects/{p}/jobs", httpdb.KindSubmission, nil},
	{"jobs.get", "GET", "projects/{p}/jobs/{j}", httpdb.KindMetadata, location},
	{"jobs.getQueryResults", "GET", "projects/{p}/queries/{j}", httpdb.KindResultPage,
		[]string{"location", "maxResults", "pageToken", "startIndex", "timeoutMs", "formatOptions.useInt64Timestamp"}},
	{"jobs.cancel", "POST", "projects/{p}/jobs/{j}/cancel", httpdb.KindMetadata, location},
	{"jobs.list", "GET", "projects/{p}/jobs", httpdb.KindListing,
		[]string{"allUsers", "maxResults", "pageToken", "projection", "stateFilter", "minCreationTime", "maxCreationTime", "parentJobId"}},

	{"projects.list", "GET", "projects", httpdb.KindMetadata, pageParams},
	{"datasets.list", "GET", "projects/{p}/datasets", httpdb.KindMetadata, []string{"all", "filter", "maxResults", "pageToken"}},
	{"datasets.get", "GET", datasetPath, httpdb.KindMetadata, nil},
	{"datasets.insert", "POST", "projects/{p}/datasets", httpdb.KindMetadata, nil},
	{"datasets.patch", "PATCH", datasetPath, httpdb.KindMetadata, nil},
	{"datasets.update", "PUT", datasetPath, httpdb.KindMetadata, nil},
	{"datasets.delete", "DELETE", datasetPath, httpdb.KindMetadata, nil},
	{"tables.list", "GET", datasetPath + "/tables", httpdb.KindMetadata, pageParams},
	{"tables.get", "GET", tablePath, httpdb.KindMetadata, nil},
	{"tables.insert", "POST", datasetPath + "/tables", httpdb.KindMetadata, nil},
	{"tables.patch", "PATCH", tablePath, httpdb.KindMetadata, nil},
	{"tables.update", "PUT", tablePath, httpdb.KindMetadata, nil},
	{"tables.delete", "DELETE", tablePath, httpdb.KindMetadata, nil},
	{"routines.list", "GET", datasetPath + "/routines", httpdb.KindMetadata, []string{"filter", "maxResults", "pageToken"}},
	{"routines.get", "GET", routinePath, httpdb.KindMetadata, nil},
	{"routines.delete", "DELETE", routinePath, httpdb.KindMetadata, nil},
}

// call is a request matched to its route, with the path variables decoded: {p: proj-a, j: job_1}.
type call struct {
	route route
	vars  map[string]string
	query url.Values
}

// match finds the request's route. A path outside /bigquery/v2/ is ErrUnsupportedTransport; a malformed
// segment, an unlisted query parameter, or a header that changes the method or billing project is an error;
// an unlisted method matches no route.
func match(r *http.Request) (*call, error) {
	rest, ok := strings.CutPrefix(r.URL.EscapedPath(), apiPrefix)
	if !ok {
		return nil, httpdb.ErrUnsupportedTransport
	}
	for name := range r.Header {
		if strings.EqualFold(name, "X-HTTP-Method-Override") || strings.EqualFold(name, "X-Goog-User-Project") {
			return nil, errors.New("bigquery: refused header " + name)
		}
	}
	segments := strings.Split(rest, "/")
	for i, segment := range segments {
		lower := strings.ToLower(segment)
		if segment == "" || segment == "." || segment == ".." || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(segment, `\`) {
			return nil, errors.New("bigquery: malformed path")
		}
		decoded, err := url.PathUnescape(segment)
		// Only a domain-scoped project id has a colon; elsewhere it would name a custom method (":undelete").
		if err != nil || decoded == "." || decoded == ".." || i > 1 && strings.Contains(decoded, ":") {
			return nil, errors.New("bigquery: malformed path")
		}
		segments[i] = decoded
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, errors.New("bigquery: malformed query")
	}
	for _, candidate := range routes {
		if vars, ok := candidate.matches(r.Method, segments); ok {
			if err := candidate.checkParams(query); err != nil {
				return nil, err
			}
			return &call{route: candidate, vars: vars, query: query}, nil
		}
	}
	return &call{vars: map[string]string{}, query: query}, nil
}

// dropFieldMask removes a partial-response mask (fields, X-Goog-FieldMask) so BigQuery returns the whole
// response, which masking can read.
func dropFieldMask(r *http.Request) {
	r.Header.Del("X-Goog-FieldMask")
	if query, err := url.ParseQuery(r.URL.RawQuery); err == nil && query.Has("fields") {
		query.Del("fields")
		r.URL.RawQuery = query.Encode()
	}
}

func (r route) matches(method string, segments []string) (map[string]string, bool) {
	pattern := strings.Split(r.pattern, "/")
	if method != r.method || len(pattern) != len(segments) {
		return nil, false
	}
	vars := map[string]string{}
	for i, part := range pattern {
		if name, isVar := strings.CutPrefix(part, "{"); isVar {
			vars[strings.TrimSuffix(name, "}")] = segments[i]
		} else if part != segments[i] {
			return nil, false
		}
	}
	return vars, true
}

// checkParams refuses credentials in the query and anything the route does not list.
func (r route) checkParams(query url.Values) error {
	for name, values := range query {
		switch {
		case name == "alt" && len(values) == 1 && values[0] == "json":
		case name == "prettyPrint" && len(values) == 1:
		case slices.Contains(r.params, name) && (len(values) == 1 || name == "stateFilter"):
		default:
			return errors.New("bigquery: refused query parameter " + name)
		}
	}
	return nil
}

// jobID is the resource id of the job a call names, "<project>/<location>/<jobId>" with the location
// lowercased; the control plane builds the same id.
func (c *call) jobID(defaultLocation string) string {
	location := defaultLocation
	if l := c.query.Get("location"); l != "" {
		location = l
	}
	return c.vars["p"] + "/" + strings.ToLower(location) + "/" + c.vars["j"]
}
