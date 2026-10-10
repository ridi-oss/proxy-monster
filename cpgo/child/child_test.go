package child

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// The test binary doubles as a child that ignores SIGTERM.
func TestMain(m *testing.M) {
	if os.Getenv("CPGO_STUBBORN_CHILD") == "1" {
		signal.Ignore(syscall.SIGTERM)
		time.Sleep(time.Minute)
		return
	}
	os.Exit(m.Run())
}

func TestStopKillsAChildThatIgnoresSIGTERM(t *testing.T) {
	t.Setenv("CPGO_STUBBORN_CHILD", "1")
	c, err := Start(os.Args[0], 0, 0, "t")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	c.Stop(300 * time.Millisecond)
	select {
	case <-c.Done():
	default:
		t.Fatal("Stop returned before the child was reaped")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Stop took %v", elapsed)
	}
}
