package authz

import _ "embed"

// SchemaSource is the Cedar schema, embedded byte-for-byte from
// control-plane/src/main/resources/authz/schema.cedarschema (235 lines). It is the SAME file the
// Kotlin control-plane loads from the classpath — copied, never edited, so the two can be diffed
// during cutover.
//
// Embedding at compile time makes a missing schema a BUILD error rather than a runtime one. That is a
// strengthening relative to the JVM's classpath lookup, and per D10 the runtime validity check is
// still required: this string is the INPUT to schema resolution, and a schema that fails to resolve
// must abort startup exactly as the Kotlin's does.
//
// D5: cache the RESOLVED schema, not the AST. And schemaFor stays TEXT concatenation — an AST merge
// removes the malformed-declaration rejection, which is observable behaviour.
//
//go:embed schema.cedarschema
var SchemaSource string
