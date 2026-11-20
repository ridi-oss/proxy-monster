package httpdb

import (
	"context"
	"errors"
	"sync"
	"testing"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// fakeExecutor admits every statement with decision and answers two result rows. A non-nil gate channel
// holds that step: its entered channel signals arrival, and the step waits on release.
type fakeExecutor struct {
	decision             *spi.Decision
	deciding, decide     chan struct{}
	submitting, submit   chan struct{}
	awaiting             chan struct{}
	mu                   sync.Mutex
	submitted            []string
	submitRows, sessions []int
	job                  *fakeJob
}

type fakeJob struct {
	executor *fakeExecutor
	canceled int
	awaited  bool
}

func (f *fakeExecutor) Authorize(_ *spi.Authorizer, _ *relay.ProxyCommandRunner, submission Submission) spi.Verdict {
	if f.deciding != nil {
		f.deciding <- struct{}{}
		<-f.decide
	}
	if submission.Session == nil {
		return spi.Fail{Message: "no session"}
	}
	return spi.Proceed{Decision: f.decision}
}

func (f *fakeExecutor) NewProxyCommandRunner(*spi.Authorizer) (*relay.ProxyCommandRunner, error) {
	return &relay.ProxyCommandRunner{}, nil
}

func (f *fakeExecutor) Namespace() (string, string) { return "cat", "db" }

func (f *fakeExecutor) Session(maxRows int) *enginepb.SessionObservation {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions = append(f.sessions, maxRows)
	return &enginepb.SessionObservation{}
}

func (f *fakeExecutor) Submit(ctx context.Context, query string, _ []string, maxRows int) (Job, error) {
	if f.submitting != nil {
		f.submitting <- struct{}{}
		<-f.submit
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.submitted = append(f.submitted, query)
	f.submitRows = append(f.submitRows, maxRows)
	f.job = &fakeJob{executor: f}
	return f.job, nil
}

func (j *fakeJob) Await(ctx context.Context) error {
	j.executor.mu.Lock()
	j.awaited = true
	j.executor.mu.Unlock()
	if j.executor.awaiting != nil {
		j.executor.awaiting <- struct{}{}
		<-ctx.Done()
		return errors.New("target: await aborted")
	}
	return nil
}

func (j *fakeJob) Read(_ context.Context, budget *relay.RowBudget, _ []*pb.ColumnMask) ([]string, [][]*string, int, error) {
	rows := [][]*string{}
	for _, value := range []string{"a", "b"} {
		if !budget.Admit(len(rows), 1) {
			break
		}
		rows = append(rows, []*string{&value})
	}
	return []string{"c"}, rows, 0, nil
}

func (j *fakeJob) Cancel(context.Context) error {
	j.executor.mu.Lock()
	defer j.executor.mu.Unlock()
	j.canceled++
	return nil
}

func openFake(t *testing.T, executor *fakeExecutor) spi.Connection {
	t.Helper()
	if executor.decision == nil {
		executor.decision = &spi.Decision{Action: "ALLOW"}
	}
	connection, err := OpenConnection("fake", executor, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func serve(connection spi.Connection, maxRows int) chan error {
	done := make(chan error, 1)
	go func() {
		_, err := connection.ServeStatement("SELECT 1", maxRows)
		done <- err
	}()
	return done
}

func TestConnectionOpensOnlyInTheConfiguredSchema(t *testing.T) {
	if _, err := OpenConnection("fake", &fakeExecutor{}, nil, nil, "other"); err == nil {
		t.Fatal("opened in a schema other than the configured one")
	}
	connection := openFake(t, &fakeExecutor{})
	if catalog, namespace, _ := connection.Namespace(); catalog != "cat" || len(namespace) != 1 || namespace[0] != "db" {
		t.Fatalf("namespace = %q %v", catalog, namespace)
	}
}

func TestConnectionAppliesTheRowBudget(t *testing.T) {
	executor := &fakeExecutor{decision: &spi.Decision{Action: "ALLOW", MaxRows: 1}}
	result, err := openFake(t, executor).ServeStatement("SELECT 1", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || !result.TruncatedByCap {
		t.Fatalf("cap of 1 over two rows: rows=%d truncatedByCap=%v", len(result.Rows), result.TruncatedByCap)
	}
	if len(executor.submitRows) != 1 || executor.submitRows[0] != 1 || executor.sessions[0] != 100 {
		t.Fatalf("submit rows %v, session rows %v", executor.submitRows, executor.sessions)
	}
}

func TestConnectionIdleCancelDoesNothing(t *testing.T) {
	executor := &fakeExecutor{}
	connection := openFake(t, executor)
	if err := connection.Cancel(); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.ServeStatement("SELECT 1", 100); err != nil {
		t.Fatalf("a cancel while idle carried into the next statement: %v", err)
	}
}

func TestConnectionCancelDuringDecideNeverSubmits(t *testing.T) {
	executor := &fakeExecutor{deciding: make(chan struct{}, 1), decide: make(chan struct{})}
	connection := openFake(t, executor)
	done := serve(connection, 100)
	<-executor.deciding
	if err := connection.Cancel(); err != nil {
		t.Fatal(err)
	}
	close(executor.decide)
	if err := <-done; !errors.Is(err, ErrCanceled) {
		t.Fatalf("statement err = %v", err)
	}
	if len(executor.submitted) != 0 {
		t.Fatalf("canceled statement submitted %v", executor.submitted)
	}
}

func TestConnectionCancelBeforeTheJobIsKnownCancelsItOnce(t *testing.T) {
	executor := &fakeExecutor{submitting: make(chan struct{}, 1), submit: make(chan struct{})}
	connection := openFake(t, executor)
	done := serve(connection, 100)
	<-executor.submitting
	if err := connection.Cancel(); err != nil {
		t.Fatal(err)
	}
	close(executor.submit)
	if err := <-done; !errors.Is(err, ErrCanceled) {
		t.Fatalf("statement err = %v", err)
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.job == nil || executor.job.canceled != 1 || executor.job.awaited {
		t.Fatalf("job canceled %d times, awaited %v", executor.job.canceled, executor.job.awaited)
	}
}

func TestConnectionCancelWhileRunningCancelsTheJob(t *testing.T) {
	executor := &fakeExecutor{awaiting: make(chan struct{}, 1)}
	connection := openFake(t, executor)
	done := serve(connection, 100)
	<-executor.awaiting
	if err := connection.Cancel(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrCanceled) {
		t.Fatalf("statement err = %v", err)
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.job == nil || executor.job.canceled != 1 {
		t.Fatalf("job canceled %d times", executor.job.canceled)
	}
}
