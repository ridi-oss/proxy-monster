package engine

import (
	"fmt"
	"strconv"
	"strings"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// RowsBytes is one result ceiling; 0 on a dimension means no bound from this entry.
type RowsBytes struct {
	Rows  int64
	Bytes int64
}

// ResultCaps is the proxy's cap table (PM_RESULT_CAPS, docs/result-caps.md): the default every statement
// gets, tightened per classification tag the statement returns unmasked.
type ResultCaps struct {
	Default RowsBytes
	ByTag   map[string]RowsBytes
}

// DefaultResultCaps is the table applied when PM_RESULT_CAPS is unset.
const DefaultResultCaps = "5000/50MB,pii:500/5MB"

// ParseResultCaps parses `<rows>[/<bytes>]` (the default) and `<tag>:<rows>[/<bytes>]` entries, comma
// separated. Bytes take a bare count or a K/M/G (10^3) suffix. Exactly one default entry is required.
func ParseResultCaps(spec string) (ResultCaps, error) {
	caps := ResultCaps{ByTag: map[string]RowsBytes{}}
	haveDefault := false
	for _, raw := range strings.Split(spec, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		tag, bound := "", entry
		if i := strings.IndexByte(entry, ':'); i >= 0 {
			tag, bound = strings.TrimSpace(entry[:i]), strings.TrimSpace(entry[i+1:])
			if tag == "" {
				return ResultCaps{}, fmt.Errorf("result caps: entry %q has an empty tag", entry)
			}
		}
		rb, err := parseRowsBytes(bound)
		if err != nil {
			return ResultCaps{}, fmt.Errorf("result caps: entry %q: %w", entry, err)
		}
		if tag == "" {
			if haveDefault {
				return ResultCaps{}, fmt.Errorf("result caps: more than one default entry")
			}
			if rb.Bytes == 0 {
				return ResultCaps{}, fmt.Errorf("result caps: the default entry needs rows and bytes")
			}
			caps.Default, haveDefault = rb, true
			continue
		}
		if _, dup := caps.ByTag[tag]; dup {
			return ResultCaps{}, fmt.Errorf("result caps: tag %q listed twice", tag)
		}
		caps.ByTag[tag] = rb
	}
	if !haveDefault {
		return ResultCaps{}, fmt.Errorf("result caps: a default entry (`<rows>/<bytes>`) is required")
	}
	return caps, nil
}

func parseRowsBytes(bound string) (RowsBytes, error) {
	rowsText, bytesText, hasBytes := strings.Cut(bound, "/")
	rows, err := strconv.ParseInt(strings.TrimSpace(rowsText), 10, 64)
	if err != nil || rows <= 0 {
		return RowsBytes{}, fmt.Errorf("rows must be a positive integer, got %q", rowsText)
	}
	rb := RowsBytes{Rows: rows}
	if hasBytes {
		rb.Bytes, err = parseByteSize(strings.TrimSpace(bytesText))
		if err != nil {
			return RowsBytes{}, err
		}
	}
	return rb, nil
}

func parseByteSize(text string) (int64, error) {
	upper := strings.ToUpper(strings.TrimSuffix(strings.ToUpper(text), "B"))
	mult := int64(1)
	switch {
	case strings.HasSuffix(upper, "K"):
		mult, upper = 1_000, strings.TrimSuffix(upper, "K")
	case strings.HasSuffix(upper, "M"):
		mult, upper = 1_000_000, strings.TrimSuffix(upper, "M")
	case strings.HasSuffix(upper, "G"):
		mult, upper = 1_000_000_000, strings.TrimSuffix(upper, "G")
	}
	n, err := strconv.ParseInt(upper, 10, 64)
	if err != nil || n <= 0 || n > (1<<62)/mult {
		return 0, fmt.Errorf("bytes must be a positive size (a count, or K/M/G), got %q", text)
	}
	return n * mult, nil
}

// Resolve returns the caps for a statement: none when unbounded, else the tightest rows and bytes among the
// default and every configured entry for a returned unmasked tag. An unknown tag adds nothing.
func (c ResultCaps) Resolve(unbounded bool, unmaskedTags []string) RowsBytes {
	if unbounded {
		return RowsBytes{}
	}
	out := c.Default
	for _, tag := range unmaskedTags {
		rb, ok := c.ByTag[tag]
		if !ok {
			continue
		}
		if rb.Rows > 0 && (out.Rows == 0 || rb.Rows < out.Rows) {
			out.Rows = rb.Rows
		}
		if rb.Bytes > 0 && (out.Bytes == 0 || rb.Bytes < out.Bytes) {
			out.Bytes = rb.Bytes
		}
	}
	return out
}

// Proto renders the table as the wire/storage message a stored result freezes.
func (c ResultCaps) Proto() *pb.ResultCaps {
	out := &pb.ResultCaps{Default: &pb.RowsBytes{Rows: c.Default.Rows, Bytes: c.Default.Bytes}, ByTag: map[string]*pb.RowsBytes{}}
	for tag, rb := range c.ByTag {
		out.ByTag[tag] = &pb.RowsBytes{Rows: rb.Rows, Bytes: rb.Bytes}
	}
	return out
}
