module github.com/ridi-oss/proxy-monster/pmon

go 1.23

require github.com/ridi-oss/proxy-monster/mysqlwire v0.0.0

require github.com/alecthomas/kong v1.16.0

// In-repo module: resolve locally (no go.work needed for CI / fresh clones).
replace github.com/ridi-oss/proxy-monster/mysqlwire => ../mysqlwire
