// The Layer-1 analyzer: proxy-monster owns the column-lineage probe (probe/) and its C-shared entry
// point (cmd/libsqlglot/), depending on sqlglot-go purely as a parser/optimizer/scope library
// (expressions, generator, optimizer, schema). Owning the probe here keeps the security-critical
// enforcement analysis versioned and evolved in this repo, while sqlglot-go stays a general-purpose
// SQL library and a version-pinned Go module dependency — a fresh clone builds with `go build`. See
// analyzer/README.md for how the pin is bumped.
module github.com/ridi-oss/proxy-monster/analyzer

go 1.26.0

require github.com/ridi-oss/sqlglot-go v0.22.0

require google.golang.org/protobuf v1.35.2

require github.com/google/go-cmp v0.6.0 // indirect
