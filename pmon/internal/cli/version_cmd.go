package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"text/tabwriter"

	"github.com/ridi-oss/proxy-monster/pmon/control"
	"github.com/ridi-oss/proxy-monster/pmon/internal/instance"
	"github.com/ridi-oss/proxy-monster/pmon/internal/state"
)

// versionCmd is `pmon version`: this binary, the running daemon, and what each server reports now.
type versionCmd struct{}

func (versionCmd) Run() error {
	ctx := context.Background()
	fmt.Printf("pmon     %s\n", version)
	servers := map[string]string{}
	client, err := control.Connect(ctx)
	if err == nil {
		s, err := client.Status(ctx)
		if err != nil {
			return fmt.Errorf("could not read the daemon's status: %w", err)
		}
		fmt.Printf("daemon   %s\n", orUnknown(s.Version))
		for _, srv := range s.Servers {
			servers[srv.Name] = srv.ControlPlane
		}
	} else {
		fmt.Println("daemon   not running")
		cfg, err := state.Load()
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("could not read the config: %w", err)
		}
		if cfg != nil {
			for name, srv := range cfg.Servers {
				servers[name] = srv.ControlPlane
			}
		}
	}
	if len(servers) == 0 {
		return nil
	}
	versions := make(map[string]string, len(servers))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for name, url := range servers {
		wg.Go(func() {
			v := serverVersion(ctx, url)
			mu.Lock()
			versions[name] = v
			mu.Unlock()
		})
	}
	wg.Wait()
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Println()
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVER\tURL\tVERSION")
	for _, name := range names {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", name, servers[name], versions[name])
	}
	return tw.Flush()
}

// serverVersion is what controlPlane's /api/instance reports, or why it says nothing.
func serverVersion(ctx context.Context, controlPlane string) string {
	info, err := instance.Fetch(ctx, controlPlane)
	switch {
	case errors.Is(err, instance.ErrUnsupported):
		return "unknown (the server predates /api/instance)"
	case err != nil:
		return "unreachable"
	}
	return orUnknown(info.Version)
}

func orUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}
