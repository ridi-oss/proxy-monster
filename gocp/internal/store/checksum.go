package store

import "hash/crc32"

// utf8BOM is the UTF-8 encoding of U+FEFF. Flyway reads a migration through a decoding Reader, so
// the BOM arrives as a single leading char and is stripped from the first line only.
const utf8BOM = "\xef\xbb\xbf"

// FlywayChecksum reproduces Flyway's ChecksumCalculator for a SQL migration: a CRC32 (IEEE, the same
// polynomial as java.util.zip.CRC32) over the file's LINES, with the line terminators excluded and a
// leading byte-order mark stripped from the first line.
//
// 99-library-decisions.md §5 calls this "the one open technical risk" of D4 and marks the algorithm
// ⚠️ Unverified: there is no Flyway jar and no populated flyway_schema_history on this machine, so
// this is a reimplementation from the described shape, not a measured match. The consequence is
// fail-closed in both directions — too strict refuses to start a healthy control plane, too lax lets
// an edited migration through silently.
//
// 🔴 The gate 99-library-decisions.md:361-366 makes mandatory before this runner is pointed at any
// real deployment: stand up the Kotlin stack from docker-compose.yml, let Flyway migrate a clean
// database, dump flyway_schema_history, and assert this function reproduces the stored checksum for
// all ten shipped migrations. build.gradle.kts:12 pins flywayVersion 13.0.0 (docs/migrations.md:11
// says 11.1.0 and is stale), so 13.0.0 is the version to compare against.
//
// TODO(A1): run that parity gate and record the result here.
//
// The return type is int32 because Flyway's checksum is a Java int and the history column is
// INTEGER — a CRC32 above 2^31 is stored NEGATIVE, and widening it to int64 here would produce a
// value that never matches the stored row.
func FlywayChecksum(content []byte) int32 {
	h := crc32.NewIEEE()
	for i, line := range flywayLines(content) {
		if i == 0 {
			line = stripBOM(line)
		}
		_, _ = h.Write(line)
	}
	return int32(h.Sum32())
}

func stripBOM(line []byte) []byte {
	if len(line) >= len(utf8BOM) && string(line[:len(utf8BOM)]) == utf8BOM {
		return line[len(utf8BOM):]
	}
	return line
}

// flywayLines splits content the way java.io.BufferedReader.readLine does: a line ends at "\n",
// "\r", or "\r\n", the terminator is not part of the line, and a terminator at end-of-input does NOT
// produce a trailing empty line. Empty input yields no lines at all, so its checksum is CRC32 of
// nothing — 0, which is also what Flyway records for an empty migration.
func flywayLines(content []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(content); {
		switch content[i] {
		case '\n':
			lines = append(lines, content[start:i])
			i++
			start = i
		case '\r':
			lines = append(lines, content[start:i])
			i++
			if i < len(content) && content[i] == '\n' {
				i++
			}
			start = i
		default:
			i++
		}
	}
	if start < len(content) {
		lines = append(lines, content[start:])
	}
	return lines
}
