package athena

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsa "github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/ridi-oss/proxy-monster/goproxy/engine"
)

// replayTolerance bounds how far before the admission an execution may have been submitted and still count
// as the one this request created (analysis time plus clock skew).
const replayTolerance = 2 * time.Minute

// afterStatementTimeout bounds how long a catalog-changing execution is awaited before its refetches are given up.
const afterStatementTimeout = 15 * time.Minute

// redactDiagnostics replaces every free-text diagnostic in a status or error body: Athena echoes stored
// values through StateChangeReason and error messages, which masking never sees.
func redactDiagnostics(body []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, ErrResultShape
	}
	redactValue(document)
	redacted, err := json.Marshal(document)
	if err != nil {
		return nil, ErrResultShape
	}
	return redacted, nil
}

func redactValue(value any) {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			switch key {
			case "Message", "StateChangeReason", "ErrorMessage":
				if _, text := child.(string); text {
					node[key] = engine.RedactedDiagnosticMessage
				}
			default:
				redactValue(child)
			}
		}
	case []any:
		for _, child := range node {
			redactValue(child)
		}
	}
}

// submittedAfter reports whether AWS records the execution as submitted at or after the given instant.
func (t *target) submittedAfter(ctx context.Context, id string, instant time.Time) (bool, error) {
	output, err := t.api.GetQueryExecution(ctx, &awsa.GetQueryExecutionInput{QueryExecutionId: aws.String(id)})
	if err != nil {
		return false, err
	}
	if output.QueryExecution == nil || output.QueryExecution.Status == nil || output.QueryExecution.Status.SubmissionDateTime == nil {
		return false, nil
	}
	return !output.QueryExecution.Status.SubmissionDateTime.Before(instant), nil
}
