-- Rename the two datasource-level exception gates from the orphaned `sql.` prefix to `exception.`.
-- After V18 moved the statement verbs to `stmt.cat.*`, `sql.unanalyzable` and `sql.unmaskable` were the
-- only `sql.*` actions left and the prefix no longer meant anything. They are not statement verbs: they
-- are deny-by-default override gates — `exception.unanalyzable` relays a statement the analyzer could not
-- analyze, `exception.unmaskable` relays a result the proxy cannot mask on the chosen wire path. The
-- schema action names moved with them, so every policy referencing the old ids is rewritten here.
--
-- The rewrite targets the Cedar ACTION reference specifically (`Action::"sql.unanalyzable"`) — never a bare
-- substring — so an unrelated `Role::"sql.unanalyzable"`, a `Tag::`, or a string literal that happens to
-- contain the text is left untouched (a bare swap could silently retarget a security forbid). Whitespace
-- around `::` is tolerated; the output stays canonical. An action named in a Cedar escape spelling
-- (`Action::"sql.\u{75}nanalyzable"`) is not rewritten and, since V18 also drops the old action from the
-- schema, fails startup validation after upgrade — rewrite it to the new id (fail-closed, never a silent
-- miss), exactly as V17 treats an escaped verb.
UPDATE policy SET
    cedar_src = regexp_replace(regexp_replace(
        cedar_src,
        'Action[[:space:]]*::[[:space:]]*"sql\.unanalyzable"', 'Action::"exception.unanalyzable"', 'g'),
        'Action[[:space:]]*::[[:space:]]*"sql\.unmaskable"',   'Action::"exception.unmaskable"',   'g'),
    updated_by = 'migration:V19',
    updated_at = now()
WHERE cedar_src ~ 'Action[[:space:]]*::[[:space:]]*"sql\.(unanalyzable|unmaskable)"';
