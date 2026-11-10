// pm-ci files a pull request's new SQL files as proxy-monster change requests from GitHub Actions; see README.md.
package main

import "github.com/alecthomas/kong"

type root struct {
	File    sqlFileCmd       `cmd:"" help:"File each SQL file a pull request adds under --dir as a change request."`
	Token   tokenCmd         `cmd:"" help:"Exchange the job's GitHub OIDC token for a wire token a workload binding allows, written masked to the step outputs token, expires-at, and binding."`
	Version kong.VersionFlag `help:"Print the version and exit." short:"V"`
}

func main() {
	var r root
	ctx := kong.Parse(&r,
		kong.Name("pm-ci"),
		kong.Description("File a pull request's new SQL files as proxy-monster change requests, from GitHub Actions."),
		kong.UsageOnError(),
		kong.Vars{"version": fullVersion()},
	)
	ctx.FatalIfErrorf(ctx.Run())
}
