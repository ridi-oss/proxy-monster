// The Layer-1 analyzer: proxy-monster owns the column-lineage probe (probe/) and its C-shared entry
// point (cmd/libsqlglot/), depending on sqlglot-go purely as a parser/optimizer/scope library
// (expressions, generator, optimizer, schema). Owning the probe here keeps the security-critical
// enforcement analysis versioned and evolved in this repo, while sqlglot-go stays a general-purpose
// SQL library and a version-pinned Go module dependency — a fresh clone builds with `go build`. See
// analyzer/README.md for how the pin is bumped.
module github.com/ridi-oss/proxy-monster/analyzer

go 1.26.0

require github.com/ridi-oss/sqlglot-go v0.37.4

require (
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)
