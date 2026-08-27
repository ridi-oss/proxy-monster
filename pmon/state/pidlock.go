package state

import (
	"time"

	"github.com/ridi-oss/proxy-monster/pmon/singleinstance"
)

const pidLockOperationTimeout = 2 * time.Second

func DaemonInstance() (*singleinstance.Instance, error) {
	path, err := PidPath()
	if err != nil {
		return nil, err
	}
	return singleinstance.New(path, pidLockOperationTimeout), nil
}
