// Command libsqlglot is the C-shared entry point for the JVM binding (jvm/): it exports the probe
// as a C ABI function so a JVM process can call it in-process via the Foreign Function & Memory API
// (java.lang.foreign). It is a separate `main` package, so cgo is confined here — pure-Go consumers
// of the library never pull in cgo.
//
// Build:  go build -buildmode=c-shared -o libsqlglot.<dylib|so> ./cmd/libsqlglot
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"

	"github.com/ridi-oss/proxy-monster/analyzer/probe"
)

// AnalyzeStatement analyzes one SQL statement. reqBytes/reqLen is a marshaled analyzerv1.AnalyzeRequest
// (proto/src/main/proto/analyzer.proto); the return is a marshaled analyzerv1.StatementFacts, its length
// written to outLen. Proto binary can contain embedded zero bytes, so this is a length-prefixed byte
// buffer on both sides, not a NUL-terminated C string — mirroring SqlNormalize's existing byte-exact
// argument convention, just applied to the return value too. The returned pointer is malloc'd by Go
// and MUST be released by the caller via FreeCString (it frees by address, not by NUL scan, so it
// works equally for a char* or a raw byte buffer). probe.AnalyzeStatementSafe is total (never panics,
// always a validly-encoded StatementFacts), so this boundary can never crash the host JVM.
//
//export AnalyzeStatement
func AnalyzeStatement(reqBytes *C.char, reqLen C.size_t, outLen *C.size_t) unsafe.Pointer {
	req := analyzeRequestBytesFromC(reqBytes, reqLen)
	out := probe.AnalyzeStatementSafe(req)
	*outLen = C.size_t(len(out))
	if len(out) == 0 {
		return nil // CBytes on an empty slice would still need freeing; nil is a valid zero-length result
	}
	return C.CBytes(out) // malloc'd; caller frees via FreeCString.
}

// SplitStatements cuts a multi-statement batch into its statements. Same byte-buffer convention and
// FreeCString ownership as AnalyzeStatement. A panic becomes ok=false, but a Go stack overflow is a
// fatal error no recover() catches: ~40k nested parens still aborts the process.
//
//export SplitStatements
func SplitStatements(reqBytes *C.char, reqLen C.size_t, outLen *C.size_t) unsafe.Pointer {
	req := analyzeRequestBytesFromC(reqBytes, reqLen)
	out := probe.SplitStatementsSafe(req)
	*outLen = C.size_t(len(out))
	if len(out) == 0 {
		return nil
	}
	return C.CBytes(out) // malloc'd; caller frees via FreeCString.
}

func analyzeRequestBytesFromC(p *C.char, n C.size_t) []byte {
	// C.GoBytes takes a C.int length. Reject anything that cannot be represented exactly rather than
	// narrowing it and reading a different byte sequence.
	const maxCInt = uint64(^uint32(0) >> 1)
	if p == nil || n == 0 || uint64(n) > maxCInt {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(p), C.int(n))
}

// SqlNormalize canonicalizes one SQL statement for byte-exact query-grant matching. SQL is passed as
// a pointer plus its UTF-8 byte length so an embedded NUL reaches probe.SqlNormalize and is denied there
// instead of being truncated at this boundary. The returned char* is malloc'd by Go and MUST be released
// by the caller via FreeCString; an allocated empty string means deny.
//
//export SqlNormalize
func SqlNormalize(sql *C.char, sqlLen C.size_t, dialect *C.char) *C.char {
	out, ok := sqlNormalizeFromC(sql, sqlLen, dialect)
	if !ok || out == "" {
		return C.CString("")
	}
	return C.CString(out)
}

func sqlNormalizeFromC(sql *C.char, sqlLen C.size_t, dialect *C.char) (out string, ok bool) {
	defer func() {
		if recover() != nil {
			out, ok = "", false
		}
	}()

	// C.GoBytes takes a C.int length. Reject anything that cannot be represented exactly rather than
	// narrowing it and reading a different byte sequence.
	const maxCInt = uint64(^uint32(0) >> 1)
	if sql == nil || dialect == nil || sqlLen == 0 || uint64(sqlLen) > maxCInt {
		return "", false
	}
	bytes := C.GoBytes(unsafe.Pointer(sql), C.int(sqlLen))
	return probe.SqlNormalize(string(bytes), C.GoString(dialect))
}

// FreeCString releases a char*/byte buffer previously returned by AnalyzeStatement or SqlNormalize.
//
//export FreeCString
func FreeCString(p *C.char) {
	C.free(unsafe.Pointer(p))
}

func main() {}
