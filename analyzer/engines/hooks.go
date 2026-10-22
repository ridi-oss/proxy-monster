package engines

import (
	exp "github.com/ridi-oss/sqlglot-go/expressions"
	"github.com/ridi-oss/sqlglot-go/optimizer"
	"github.com/ridi-oss/sqlglot-go/schema"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// engineHooks are the engine's steps in a statement's analysis; sharedHooks holds what most engines share.
type engineHooks interface {
	// prepareStatement runs before classification on the single parsed statement: an engine that binds
	// request parameters into the tree, or resolves a server-side prepared statement into its body, does it
	// here. It returns the statement to analyze, whether the proxy must submit regenerated text, and either
	// an error (fail closed) or facts that end the analysis (a request for more input).
	prepareStatement(settings *sessionSettings, root exp.Expression) (exp.Expression, bool, *pb.StatementFacts, error)
	// finishSubmission runs after a resolved analysis on the tree the proxy will submit (the lineage rewrite
	// re-parsed, or the prepared original) and may edit it (a row cap); true means the text must be
	// regenerated.
	finishSubmission(settings *sessionSettings, submission exp.Expression) bool
	// stampSubmission records on facts what the proxy needs beside the regenerated text (Athena: the
	// execution-parameter list that goes with it). Called only when the text was regenerated.
	stampSubmission(facts *pb.StatementFacts)
	// configureNamespace maps the session's namespace onto the qualifier's resolution options: a search
	// path for engines that have one, a fixed catalog and default schema for engines that do not.
	configureNamespace(opts *optimizer.QualifyOpts, namespace NamespaceConfig)
	// rewriteStatement optionally rewrites a parsed statement into the SQL the proxy should relay to the
	// target DB, returning "" to leave it unchanged.
	rewriteStatement(root exp.Expression) string
}

type sharedHooks struct{}

func (sharedHooks) prepareStatement(_ *sessionSettings, root exp.Expression) (exp.Expression, bool, *pb.StatementFacts, error) {
	return root, false, nil, nil
}

func (sharedHooks) finishSubmission(*sessionSettings, exp.Expression) bool { return false }

func (sharedHooks) stampSubmission(*pb.StatementFacts) {}

func (sharedHooks) configureNamespace(opts *optimizer.QualifyOpts, namespace NamespaceConfig) {
	opts.SearchPath = namespace.SearchPath
}

func (sharedHooks) rewriteStatement(exp.Expression) string { return "" }

// The trait answers most engines share.

func noBuiltinBareCall(*sessionSettings, string) bool { return false }

func noSafeTypeReference(*sessionSettings, exp.Expression, exp.Expression, NamespaceConfig) bool {
	return false
}

func referencedColumnLeakKeys(_ *sessionSettings, report ProbeResult, _ schema.Schema) map[string]bool {
	return referencedColumnKeys(report)
}
