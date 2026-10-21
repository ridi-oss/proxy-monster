package relay

import (
	"strings"
	"unicode"
	"unicode/utf16"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// BindMasks binds mask specs to result-set indexes by output ordinal; out-of-range ordinals are
// reported unbound so callers fail closed. Ports probe/Masks.kt bindMasks. The proto ordinal has explicit
// presence (*int32): an ABSENT ordinal (mask.Ordinal == nil) never binds — do NOT use GetOrdinal(), which
// returns 0 for nil and would silently bind a malformed/omitted mask to result column 0.
func BindMasks(masks []*pb.ColumnMask, resultColumnCount int) MaskBinding {
	byIndex := make(map[int]string)
	var unbound []*pb.ColumnMask
	for _, mask := range masks {
		if mask.Ordinal != nil && int(*mask.Ordinal) >= 0 && int(*mask.Ordinal) < resultColumnCount {
			ordinal := int(*mask.Ordinal)
			if _, exists := byIndex[ordinal]; !exists {
				byIndex[ordinal] = mask.GetKind()
			}
		} else {
			unbound = append(unbound, mask)
		}
	}
	return MaskBinding{ByIndex: byIndex, Unbound: unbound}
}

// applyMaskKind ports probe/Masking.kt Masking.apply. Kotlin String length, takeLast, and
// Char mapping operate on UTF-16 code units, so this deliberately does not use Go rune counts.
func applyMaskKind(value *string, kind string) *string {
	if value == nil || kind == "NULL" {
		return nil
	}
	var masked string
	switch kind {
	case "FIXED":
		masked = "####"
	case "LAST_N":
		units := utf16.Encode([]rune(*value))
		const visible = 4
		if len(units) <= visible {
			masked = strings.Repeat("*", len(units))
		} else {
			masked = strings.Repeat("*", len(units)-visible) + string(utf16.Decode(units[len(units)-visible:]))
		}
	case "FORMAT_PRESERVING":
		units := utf16.Encode([]rune(*value))
		for i, unit := range units {
			if isKotlinCharLetterOrDigit(rune(unit)) {
				units[i] = '*'
			}
		}
		masked = string(utf16.Decode(units))
	default:
		masked = "****"
	}
	return &masked
}

// isKotlinCharLetterOrDigit mirrors JDK 24 Character.isLetterOrDigit(char). Go 1.23 uses
// Unicode 15 tables while JDK 24 uses Unicode 16, whose eight new BMP letters must also be masked.
// Supplementary letters are represented by surrogate halves in Kotlin Char iteration and therefore
// intentionally remain unclassified here.
func isKotlinCharLetterOrDigit(r rune) bool {
	if r > 0xffff {
		return false
	}
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return true
	}
	switch r {
	case 0x1c89, 0x1c8a, 0xa7cb, 0xa7cc, 0xa7cd, 0xa7da, 0xa7db, 0xa7dc:
		return true
	default:
		return false
	}
}
