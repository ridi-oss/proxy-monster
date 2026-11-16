package athena

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsa "github.com/aws/aws-sdk-go-v2/service/athena"
)

// diagnosticKeys are the free-text fields through which Athena echoes stored values.
var diagnosticKeys = []string{"Message", "StateChangeReason", "ErrorMessage"}

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
