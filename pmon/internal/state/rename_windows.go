package state

import (
	"errors"
	"math/rand/v2"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// rename retries os.Rename while another handle on the target briefly blocks it: a reader that opened the config
// without FILE_SHARE_DELETE, or a virus scanner. The same approach as Go's cmd/go/internal/robustio.
func rename(from, to string) error {
	const window = 2 * time.Second
	start := time.Now()
	for delay := time.Millisecond; ; delay *= 2 {
		err := os.Rename(from, to)
		if err == nil || !(errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)) ||
			time.Since(start) > window {
			return err
		}
		time.Sleep(min(delay, 100*time.Millisecond) + rand.N(time.Millisecond))
	}
}
