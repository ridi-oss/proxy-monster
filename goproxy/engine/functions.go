package engine

// FoldFunctionNames folds like a call (MySQL `AddTax` -> `addtax`) and drops duplicates, keeping order.
func FoldFunctionNames(db Db, names []string) []string {
	if len(names) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		l := db.FoldFunctionName(n)
		if _, dup := seen[l]; dup {
			continue
		}
		seen[l] = struct{}{}
		out = append(out, l)
	}
	return out
}
