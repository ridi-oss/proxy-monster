package athena

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// Glue reports some table parameters as JSON null, which the SDK's map<string,string> decoder rejects
// outright. The provider never reads those values, so drop them before the SDK sees the response.
type metadataTransport struct{ next http.RoundTripper }

func (t metadataTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(request)
	if err != nil || response.StatusCode != http.StatusOK {
		return response, err
	}
	switch request.Header.Get("X-Amz-Target") {
	case "AmazonAthena.ListTableMetadata", "AmazonAthena.GetTableMetadata", "AmazonAthena.ListDatabases", "AmazonAthena.GetDatabase":
	default:
		return response, nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, defaultResponseLimit+1))
	_ = response.Body.Close()
	if err != nil || len(body) > defaultResponseLimit {
		return nil, ErrResultShape
	}
	var document any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, ErrResultShape
	}
	if dropNullParameters(document) {
		if body, err = json.Marshal(document); err != nil {
			return nil, ErrResultShape
		}
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.Header.Del("Content-Length")
	return response, nil
}

func dropNullParameters(node any) bool {
	changed := false
	switch value := node.(type) {
	case map[string]any:
		if parameters, ok := value["Parameters"].(map[string]any); ok {
			for key, entry := range parameters {
				if entry == nil {
					delete(parameters, key)
					changed = true
				}
			}
		}
		for _, child := range value {
			if dropNullParameters(child) {
				changed = true
			}
		}
	case []any:
		for _, child := range value {
			if dropNullParameters(child) {
				changed = true
			}
		}
	}
	return changed
}
