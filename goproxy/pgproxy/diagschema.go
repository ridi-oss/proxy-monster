package pgproxy

// pgSchemaMessages lists, per SQLSTATE, the primary messages (M) whose interpolations are schema names
// only, from the PostgreSQL 16 and 17 backend message catalogs. A target DB message is kept verbatim only
// when its SQLSTATE is listed and M matches one of the code's templates exactly. Placeholders:
//
//	"%s"  a quoted name; the capture stops at the template's quote, so a name containing " is stripped
//	%i    an unquoted name: [A-Za-z_][A-Za-z0-9_$]*
//	%t    a type name, as in "character varying" or "integer[]"
//
// A template is listed only when its interpolated name can come solely from statement text or the catalog.
// A template whose name a run-time value can become — through an object-name resolver that takes a string
// argument: a reg* cast (::regclass/::regtype/::regnamespace/::regoper/::regcollation), nextval/currval,
// the has_*_privilege family, pg_relation_size and the other size functions, pg_get_serial_sequence,
// pg_get_object_address — is omitted, even though enforcement denies a masked column as that argument. Those resolvers report the
// string back verbatim ("relation/type/schema/collation ... does not exist", "operator does not exist:
// ..."), so an allowlisted template there would relay a value the client only referenced indirectly. See
// docs/diagnostic-redaction.md and the leak coverage in diag_e2e_test.go.
var pgSchemaMessages = map[string][]string{
	// Undefined and duplicate relations, columns, schemas, types, and routines. `relation "%s" does not
	// exist` is omitted: ::regclass, nextval, has_table_privilege, pg_relation_size and the like resolve a
	// string argument to a relation name and report it in this exact text.
	"42P01": {
		`missing FROM-clause entry for table "%s"`,
		`table "%s" does not exist`,
		`view "%s" does not exist`,
		`sequence "%s" does not exist`,
		`materialized view "%s" does not exist`,
	},
	"42P07": {`relation "%s" already exists`},
	// `column "%s" of relation "%s" does not exist` is omitted: has_column_privilege, pg_get_serial_sequence,
	// and pg_get_object_address resolve a string argument to a column name and report it in this text.
	"42703": {
		`column "%s" does not exist`,
		`column %i.%i does not exist`,
		`column "%s" referenced in foreign key constraint does not exist`,
	},
	"42701": {
		`column "%s" specified more than once`,
		`column "%s" of relation "%s" already exists`,
	},
	"42702": {`column reference "%s" is ambiguous`},
	// `type "%s" does not exist` (::regtype), `collation "%s" ... does not exist` (::regcollation), and
	// `trigger "%s" for table "%s" does not exist` (pg_get_object_address) are omitted: each resolver turns a
	// string into that object name and reports it. 42883 (`operator does not exist: %o` via ::regoper,
	// `function %f`/`procedure %f does not exist` via pg_get_object_address) is omitted for the same reason.
	"42704": {
		`index "%s" does not exist`,
		`constraint "%s" of relation "%s" does not exist`,
	},
	"42P06": {`schema "%s" already exists`},
	"42710": {
		`constraint "%s" for relation "%s" already exists`,
		`trigger "%s" for relation "%s" already exists`,
		`type "%s" already exists`,
	},
	"42723": {`function "%s" already exists with same argument types`},
	// Type mismatch between a column and an expression: types only.
	"42804": {`column "%s" is of type %t but expression is of type %t`},
	// Privileges: the object kind and its unquoted name.
	"42501": {
		`permission denied for table %i`,
		`permission denied for view %i`,
		`permission denied for materialized view %i`,
		`permission denied for sequence %i`,
		`permission denied for schema %i`,
		`permission denied for function %i`,
		`permission denied for procedure %i`,
	},
	// Integrity violations: M names the constraint and relation; the row or key values are in D, dropped.
	"23502": {`null value in column "%s" of relation "%s" violates not-null constraint`},
	"23505": {`duplicate key value violates unique constraint "%s"`},
	"23503": {
		`insert or update on table "%s" violates foreign key constraint "%s"`,
		`update or delete on table "%s" violates foreign key constraint "%s" on table "%s"`,
	},
	"23514": {
		`new row for relation "%s" violates check constraint "%s"`,
		`check constraint "%s" of relation "%s" is violated by some row`,
	},
	"23P01": {`conflicting key value violates exclusion constraint "%s"`},
}
