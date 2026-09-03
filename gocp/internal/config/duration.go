package config

import (
	"fmt"
	"math"
)

// ParseDuration parses a duration to whole seconds, per 01-bootstrap.md §2 (`parseDuration`,
// Config.kt:283-307). It is written BY HAND on purpose (D19): it must REJECT what Go's
// time.ParseDuration accepts (`1.5h`, `300ms`, `-5m`, unit-less) and ACCEPT the bare-integer-seconds
// form Go rejects. Do not delegate to the stdlib.
//
// Behaviour, in the Kotlin's order:
//
//  1. Empty ⇒ error.
//  2. All-digits ⇒ parse as an integer, and require > 0.
//  3. Otherwise match `(\d+)([hms])` repeatedly from offset 0. Each match must start EXACTLY where the
//     previous one ended — no gaps, no leading junk — so `1h30m` is valid and `1h 30m` is not.
//  4. Multipliers h=3600, m=60, s=1, accumulated with exact (overflow-checked) arithmetic.
//  5. After the loop, `offset == len(raw) && total > 0`, else error.
//  6. An arithmetic overflow surfaces as "duration is too large: …", not as a wrapped arithmetic error
//     (the Kotlin catches ArithmeticException and rethrows IllegalArgumentException).
//
// The Kotlin scans with Regex.findAll and asserts `match.range.first == offset`. A hand-rolled scan is
// equivalent: findAll's next match either starts at offset (accept and continue) or starts later
// (which the range check rejects) or does not exist (the loop ends). In both of the latter cases the
// `offset == raw.length` check afterwards is what decides, so "no match exactly at offset" ⇒ error
// unless we have already consumed the whole string.
func ParseDuration(raw string) (int64, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("duration must not be empty")
	}
	if allASCIIDigits(raw) {
		v, err := parseInt64(raw)
		if err != nil {
			// Kotlin: raw.toLong() throws NumberFormatException, itself an IllegalArgumentException,
			// so it escapes fromEnv as one. Reproduced as a plain error here.
			return 0, fmt.Errorf("invalid duration: %s", raw)
		}
		if v <= 0 {
			return 0, fmt.Errorf("duration must be positive")
		}
		return v, nil
	}

	offset := 0
	var total int64
	for offset < len(raw) {
		// A match must begin at `offset`: digits, then exactly one of h/m/s.
		i := offset
		for i < len(raw) && raw[i] >= '0' && raw[i] <= '9' {
			i++
		}
		if i == offset || i >= len(raw) {
			break // no match starting here; the offset == len(raw) check below rejects it
		}
		var multiplier int64
		switch raw[i] {
		case 'h':
			multiplier = 3600
		case 'm':
			multiplier = 60
		case 's':
			multiplier = 1
		}
		if multiplier == 0 {
			break // digits not followed by h/m/s: no match at this offset
		}
		value, err := parseInt64(raw[offset:i])
		if err != nil {
			// Kotlin: groupValues[1].toLong() on a >19-digit run throws NumberFormatException.
			return 0, fmt.Errorf("invalid duration: %s", raw)
		}
		product, ok := multiplyExact(value, multiplier)
		if !ok {
			return 0, fmt.Errorf("duration is too large: %s", raw)
		}
		sum, ok := addExact(total, product)
		if !ok {
			return 0, fmt.Errorf("duration is too large: %s", raw)
		}
		total = sum
		offset = i + 1
	}
	if offset != len(raw) || total <= 0 {
		return 0, fmt.Errorf("invalid duration: %s", raw)
	}
	return total, nil
}

// allASCIIDigits mirrors Kotlin's `raw.all(Char::isDigit)`.
//
// DEVIATION (documented, not a fix): Kotlin's Char.isDigit is Unicode-aware and Long.parseLong accepts
// Unicode decimal digits via Character.digit, so "٣٠" parses as 30 in the Kotlin. Go's strconv is
// ASCII-only. Meanwhile the Kotlin's OWN regex branch uses `\d`, which without UNICODE_CHARACTER_CLASS
// is ASCII-only — so the Kotlin is already internally inconsistent here. ASCII on both branches is the
// closest single behaviour; the divergence is unreachable from any documented deployment.
func allASCIIDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// multiplyExact / addExact are Math.multiplyExact / Math.addExact: the product or sum, plus whether it
// stayed in int64 range.
func multiplyExact(a, b int64) (int64, bool) {
	p := a * b
	if a != 0 && (p/a != b || (a == -1 && b == math.MinInt64)) {
		return 0, false
	}
	return p, true
}

func addExact(a, b int64) (int64, bool) {
	s := a + b
	if ((a ^ s) & (b ^ s)) < 0 {
		return 0, false
	}
	return s, true
}
