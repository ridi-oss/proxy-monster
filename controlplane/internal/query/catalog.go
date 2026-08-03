package query

import (
	"fmt"

	probepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/datasource"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/engine"
)

// CatalogColumnIndex is the ONE catalog representation shared by analyzer construction and exact
// lineage-key matching — Query.kt:201-204.
//
// Specs is the flat ColumnSpec list the analyzer was built over; RowsByKey maps the analyzer's own
// rendered key to the catalog row it came from. Order is preserved in Keys so a caller that needs to
// walk the index deterministically can.
type CatalogColumnIndex struct {
	Specs     []*probepb.ColumnSpec
	RowsByKey map[string]datasource.CatalogColumn
	// Keys is RowsByKey's insertion order — Kotlin's LinkedHashMap. Nothing in decideQuery iterates
	// it, but a Go map has no order and dropping it would make the type strictly weaker than the
	// Kotlin one it ports.
	Keys []string
}

// BuildCatalogColumnIndex builds the catalog's exact normalized-key index from an analyzer already
// built over specs (the same list, in the same order, as catalog maps to). Query.kt:213-228.
//
// 🔒 It REUSES [engine.Analyzer.ColumnKeys] rather than re-deriving every row's key with a second
// full-catalog walk, so a fold-rule divergence between the analyzer and the control plane is
// impossible BY CONSTRUCTION. INV-A13-16 is the contract it leans on: ColumnKeys[i] corresponds to
// the i-th element of the slice passed to AnalyzerFor.
//
// The two checks are DEFENSE IN DEPTH against a wiring bug, not a fold-drift concern: key uniqueness
// is already guaranteed by AnalyzerFor's own validation (INV-A13-13 — it would have returned an
// error), so decideQuery never observes a duplicate here. Kotlin states both as `require`, i.e. an
// IllegalArgumentException; here they are errors, and A6 step 3's catch turns either into
// `structuralDeny(CATALOG_CONFIGURATION_DENY: <msg>, stage="catalog", catalogMiss=true)` — so the
// messages below are WIRE-VISIBLE deny prose and are reproduced verbatim.
func BuildCatalogColumnIndex(
	catalog []datasource.CatalogColumn,
	specs []*probepb.ColumnSpec,
	analyzer *engine.Analyzer,
) (*CatalogColumnIndex, error) {
	if len(catalog) != len(analyzer.ColumnKeys) {
		return nil, fmt.Errorf("catalog/analyzer column count mismatch: %d vs %d",
			len(catalog), len(analyzer.ColumnKeys))
	}
	rowsByKey := make(map[string]datasource.CatalogColumn, len(catalog))
	keys := make([]string, 0, len(catalog))
	for i, row := range catalog {
		key := analyzer.ColumnKeys[i]
		// Kotlin: `require(rowsByKey.putIfAbsent(key, row) == null)` — putIfAbsent returns the
		// EXISTING value, so a non-null return is the collision.
		if _, exists := rowsByKey[key]; exists {
			return nil, fmt.Errorf("catalog contains ambiguous normalized column key '%s'", key)
		}
		rowsByKey[key] = row
		keys = append(keys, key)
	}
	return &CatalogColumnIndex{Specs: specs, RowsByKey: rowsByKey, Keys: keys}, nil
}

// CatalogCoverage is Query.kt:230-233's sealed interface: Covered, or Denied(reason).
//
// Modelled as a struct rather than an interface pair for the same reason authz.AuthzDecision is: the
// Covered case is a stateless singleton, so the whole discriminant is one boolean.
type CatalogCoverage struct {
	Covered bool
	Reason  string
}

// Covered is the CatalogCoverage.Covered object.
var Covered = CatalogCoverage{Covered: true}

// CoverageOf checks that every analyzer key touched by the statement matches exactly one row in the
// already-unique index — Query.kt:236-239. Analyzer keys remain OPAQUE: they are never parsed.
//
// It reports the FIRST missing key only, matching `touched.firstOrNull { it !in index.rowsByKey }`,
// and `touched` is walked in the caller's insertion order so "first" is deterministic.
//
// ⚠️ The long comment at Query.kt:531-544 is worth preserving here, because this looks like a stale
// -fragment path and is not one. A column TRULY absent from the catalog fails to RESOLVE (the
// analyzer is built from the same catalog) and takes the `!resolved` sql.unanalyzable route at step
// 16 instead. So step 18 is a fail-closed guard for an ANALYZER↔CP KEY-RENDERING DIVERGENCE — a
// contract bug. It routes through the same `sql.unanalyzable` escape hatch rather than hard-denying,
// on the principle that *authorization belongs to Cedar*: a principal without sql.unanalyzable stays
// fail-closed, while a holder may relay. That relay drops masks for CO-SELECTED COVERED COLUMNS TOO,
// which is no new capability over the step-16 relay, which likewise relays everything unmasked under
// the same grant.
func CoverageOf(index *CatalogColumnIndex, touched []string) CatalogCoverage {
	for _, key := range touched {
		if _, ok := index.RowsByKey[key]; !ok {
			return CatalogCoverage{
				Reason: "fail-closed: analyzer emitted column absent from catalog: " + key,
			}
		}
	}
	return Covered
}
