// Package child runs the Kotlin control plane as a child process bound to loopback.
package child

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// Child is a running Kotlin control plane.
type Child struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

// Start launches command with the caller's environment, overriding the ports and bind host so the
// child listens only on loopback and trusts only cp-go's forwarded headers.
func Start(command string, httpPort, grpcPort int) (*Child, error) {
	cmd := exec.Command(command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"PM_HTTP_PORT="+strconv.Itoa(httpPort),
		"PM_GRPC_PORT="+strconv.Itoa(grpcPort),
		"PM_BIND_HOST=127.0.0.1",
		"PM_TRUSTED_PROXIES=127.0.0.1",
	)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("child: starting %s: %w", command, err)
	}
	c := &Child{cmd: cmd, done: make(chan struct{})}
	go func() {
		c.err = cmd.Wait()
		close(c.done)
	}()
	return c, nil
}

// Done closes when the child exits.
func (c *Child) Done() <-chan struct{} { return c.done }

// ExitCode is the child's exit status, valid after Done.
func (c *Child) ExitCode() int {
	if c.cmd.ProcessState == nil {
		return 1
	}
	if code := c.cmd.ProcessState.ExitCode(); code >= 0 {
		return code
	}
	return 1
}

// Err is the child's wait error, valid after Done.
func (c *Child) Err() error { return c.err }

// Stop asks the child to drain and exit, kills it if it is still running after grace, and returns
// once it has been reaped.
func (c *Child) Stop(grace time.Duration) {
	select {
	case <-c.done:
		return
	default:
	}
	_ = c.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-c.done:
	case <-time.After(grace):
		_ = c.cmd.Process.Kill()
		<-c.done
	}
}

// WaitHealthy polls url until it answers 200, the child exits, or ctx ends. exited may be nil when no
// child is supervised.
func WaitHealthy(ctx context.Context, url string, exited <-chan struct{}) error {
	client := &http.Client{Timeout: 2 * time.Second}
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		if resp, err := client.Get(url); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("child: %s not healthy: %w", url, ctx.Err())
		case <-exited:
			return fmt.Errorf("child: exited before %s was healthy", url)
		case <-tick.C:
		}
	}
}
