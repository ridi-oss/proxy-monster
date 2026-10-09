package cli

import (
	"fmt"
	"os"

	"github.com/ridi-oss/proxy-monster/pmon/internal/aiapps"
)

// moveAIEntries points the AI apps' `pmon mcp <from>` entries at a server renamed to to: an entry for the
// old name would reach no server. The new entry is added before the old one is removed. def is the default
// server after the rename, which a bare `pmon mcp` entry follows on its own.
func moveAIEntries(from, to, def string) error {
	pmon, err := pmonPath()
	if err != nil {
		return err
	}
	setup := aiapps.Setup{Pmon: pmon, Confirm: confirmClaudeRestart, Default: def}
	// No MCP URL: moving pmon's entry is not an install, so it replaces none of the app's https entries.
	target := aiapps.Server{Name: to}
	failed := 0
	for _, app := range aiapps.Apps() {
		if !app.Installed() || !app.Connected(setup, from) {
			continue
		}
		err := app.Batch(setup, func(setup aiapps.Setup) error {
			entry, _, err := app.Add(setup, target)
			if err != nil {
				return err
			}
			if _, err := app.Remove(setup, from); err != nil {
				return err
			}
			fmt.Printf("%s: now runs pmon mcp %s as %s\n", app.Name, to, entry)
			return nil
		})
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "%s: could not move its entry for %s: %v — run `pmon mcp --install %s` and `pmon mcp --uninstall %s`\n", app.Name, from, err, to, from)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d AI app(s) still run pmon mcp %s", failed, from)
	}
	return nil
}
