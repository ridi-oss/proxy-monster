package engines

import (
	"embed"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	pb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

// EngineCallSafe runs one marshaled EngineCallRequest from the control plane and returns a marshaled
// EngineCallResponse. A failure, a panic included, comes back in the response's error.
func EngineCallSafe(requestBytes []byte) (out []byte) {
	response := &pb.EngineCallResponse{}
	defer func() {
		if r := recover(); r != nil {
			response = &pb.EngineCallResponse{Error: fmt.Sprintf("engine call panicked: %v", r)}
		}
		out, _ = proto.Marshal(response)
	}()
	request := &pb.EngineCallRequest{}
	if err := proto.Unmarshal(requestBytes, request); err != nil {
		response.Error = "malformed engine call: " + err.Error()
		return
	}
	e, ok := ByProto(request.GetEngine())
	if !ok {
		response.Error = fmt.Sprintf("unsupported engine %s", request.GetEngine())
		return
	}
	if err := e.call(request, response); err != nil {
		response = &pb.EngineCallResponse{Error: err.Error()}
	}
	return
}

func (e *Engine) call(request *pb.EngineCallRequest, response *pb.EngineCallResponse) error {
	switch call := request.GetCall().(type) {
	case *pb.EngineCallRequest_Facts:
		response.Result = &pb.EngineCallResponse_Facts{Facts: e.facts()}
	case *pb.EngineCallRequest_CatalogName:
		response.Result = &pb.EngineCallResponse_Text{Text: e.CatalogName(call.CatalogName).String()}
	case *pb.EngineCallRequest_DefaultSchema:
		response.Result = &pb.EngineCallResponse_Text{Text: e.defaultSchema(call.DefaultSchema)}
	case *pb.EngineCallRequest_SchemaKind:
		// The control plane stores schema names in canonical spelling.
		schema := SchemaName{name: call.SchemaKind}
		response.Result = &pb.EngineCallResponse_SchemaKind{SchemaKind: &pb.SchemaKind{
			FixedSystem: slices.Contains(e.systemSchemas, schema),
			System:      e.IsSystemSchema(schema),
			Temp:        e.IsTempSchema(schema),
		}}
	case *pb.EngineCallRequest_AnalyzerConfig:
		session := call.AnalyzerConfig.GetSession()
		if session == nil {
			session = &pb.SessionObservation{}
		}
		config, err := e.analyzerConfig(e, call.AnalyzerConfig.GetDatasource(), session, call.AnalyzerConfig.GetSplit())
		if err != nil {
			return err
		}
		if config != nil {
			response.Result = &pb.EngineCallResponse_AnalyzerConfig{AnalyzerConfig: config}
		}
	case *pb.EngineCallRequest_ServerVersion:
		response.Result = &pb.EngineCallResponse_ServerVersion{ServerVersion: e.serverVersion(call.ServerVersion)}
	case *pb.EngineCallRequest_ManifestSeries:
		response.Result = &pb.EngineCallResponse_Text{Text: e.manifestSeries(call.ManifestSeries)}
	case *pb.EngineCallRequest_FunctionCatalog:
		catalog := e.functionCatalog(e, call.FunctionCatalog.GetRoutines(), call.FunctionCatalog.GetEngineVersion())
		response.Result = &pb.EngineCallResponse_FunctionCatalog{FunctionCatalog: catalog}
	case *pb.EngineCallRequest_ConnectionInfo:
		response.Result = &pb.EngineCallResponse_Valid{Valid: e.connectionInfoValid(e, call.ConnectionInfo)}
	case *pb.EngineCallRequest_DefaultSchemaStatement:
		if !e.DefaultSchemaSettable {
			return fmt.Errorf("%s has no statement that sets a default schema", e.WireName)
		}
		response.Result = &pb.EngineCallResponse_Text{Text: e.defaultSchemaPrefix + e.QuoteIdentifier(call.DefaultSchemaStatement)}
	default:
		return fmt.Errorf("unknown engine call %T", call)
	}
	return nil
}

func (e *Engine) facts() *pb.EngineFacts {
	system := make([]string, len(e.systemSchemas))
	for i, s := range e.systemSchemas {
		system[i] = s.name
	}
	return &pb.EngineFacts{
		WireName:                       e.WireName,
		IdentifierQuote:                e.IdentifierQuote,
		SystemSchemas:                  system,
		ConnectionProperties:           e.connectionProperties,
		CatalogIsConnectionIndependent: e.catalogIsConnectionIndependent,
		ChecksTargetErrors:             e.checksTargetErrors,
		NeedsCaseMode:                  e.needsCaseMode,
		ImplicitColumns:                e.implicitColumns,
		DefaultSchemaSettable:          e.DefaultSchemaSettable,
	}
}

// QuoteIdentifier writes name as one quoted identifier: users -> `users`, a`b -> `a“b`.
func (e *Engine) QuoteIdentifier(name string) string {
	return e.IdentifierQuote + strings.ReplaceAll(name, e.IdentifierQuote, e.IdentifierQuote+e.IdentifierQuote) + e.IdentifierQuote
}

var postgresSystemColumns = []*pb.ImplicitColumn{
	{Name: "ctid", DataType: "tid"},
	{Name: "xmin", DataType: "xid"},
	{Name: "xmax", DataType: "xid"},
	{Name: "cmin", DataType: "cid"},
	{Name: "cmax", DataType: "cid"},
	{Name: "tableoid", DataType: "oid"},
}

// PostgreSQL functions the grammar reserves as keywords: no pg_proc row, and no user function can shadow them.
var postgresGrammarFunctions = []string{
	"coalesce", "greatest", "least", "nullif", "grouping",
	"xmlconcat", "xmlelement", "xmlforest", "xmlparse", "xmlpi", "xmlroot", "xmltable",
}

//go:embed native-functions
var nativeFunctionFiles embed.FS

// nativeFunctions reads a pinned builtin list, one name per line; `#` lines and blanks are skipped.
func nativeFunctions(engine, version string) []string {
	data, err := nativeFunctionFiles.ReadFile(path.Join("native-functions", engine, version+".txt"))
	if err != nil {
		panic(err)
	}
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			names = append(names, strings.ToLower(line))
		}
	}
	return names
}

var (
	mysqlNatives  = map[string][]string{"8.0": nativeFunctions("mysql", "8.0"), "8.4": nativeFunctions("mysql", "8.4")}
	athenaNatives = map[string][]string{"3": nativeFunctions("athena", "3")}

	mysqlMinorVersion = regexp.MustCompile(`(\d+)\.(\d+)`)
)

// mysqlNativeFunctions are the builtins of the nearest pinned series: 8.4+ -> 8.4, anything else -> 8.0.
func mysqlNativeFunctions(version string) []string {
	m := mysqlMinorVersion.FindStringSubmatch(version)
	if m == nil {
		return mysqlNatives["8.0"]
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	if major == 8 && minor >= 4 {
		return mysqlNatives["8.4"]
	}
	return mysqlNatives["8.0"]
}

// {"mysql": [fnv_64], "app": [add_tax]} -> builtins = pinned natives, loadables = [fnv_64], udf app = [add_tax].
func mysqlFunctionCatalog(_ *Engine, routines []*pb.SchemaFunctions, version string) *pb.FunctionCatalog {
	catalog := &pb.FunctionCatalog{BuiltinFunctions: slices.Clone(mysqlNativeFunctions(version))}
	for _, r := range routines {
		if r.GetSchema() == "mysql" {
			catalog.LoadableFunctions = append(catalog.LoadableFunctions, r.GetNames()...)
		} else {
			catalog.UdfSchemas = append(catalog.UdfSchemas, &pb.SchemaFunctions{Schema: r.GetSchema(), Names: r.GetNames()})
		}
	}
	return catalog
}

// {"pg_catalog": [abs], "public": [add_tax], "pg_temp_3": [x]} -> builtins = [abs, coalesce, ...], udf public =
// [add_tax], pg_temp_3 dropped.
func postgresFunctionCatalog(e *Engine, routines []*pb.SchemaFunctions, _ string) *pb.FunctionCatalog {
	var pgCatalog []string
	for _, r := range routines {
		if r.GetSchema() == "pg_catalog" {
			pgCatalog = append(pgCatalog, r.GetNames()...)
		}
	}
	pgCatalog = distinct(append(pgCatalog, postgresGrammarFunctions...))
	catalog := &pb.FunctionCatalog{
		BuiltinFunctions:      pgCatalog,
		SystemFunctionSchemas: []*pb.SchemaFunctions{{Schema: "pg_catalog", Names: pgCatalog}},
	}
	for _, r := range routines {
		schema := SchemaName{name: r.GetSchema()}
		switch {
		case r.GetSchema() == "pg_catalog":
		case slices.Contains(e.systemSchemas, schema):
			catalog.SystemFunctionSchemas = append(catalog.SystemFunctionSchemas, &pb.SchemaFunctions{Schema: r.GetSchema(), Names: r.GetNames()})
		case !e.IsSystemSchema(schema):
			catalog.UdfSchemas = append(catalog.UdfSchemas, &pb.SchemaFunctions{Schema: r.GetSchema(), Names: r.GetNames()})
		}
	}
	return catalog
}

// Athena has no routine catalog: the builtins are the pinned list for the engine version, 3 when unknown.
func athenaFunctionCatalog(_ *Engine, _ []*pb.SchemaFunctions, version string) *pb.FunctionCatalog {
	natives, ok := athenaNatives[strings.TrimSpace(version)]
	if !ok {
		natives = athenaNatives["3"]
	}
	return &pb.FunctionCatalog{BuiltinFunctions: slices.Clone(natives)}
}

func distinct(names []string) []string {
	seen := make(map[string]bool, len(names))
	out := names[:0:0]
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

var (
	patchVersion           = regexp.MustCompile(`\d+\.\d+\.\d+`)
	minorVersion           = regexp.MustCompile(`\d+\.\d+`)
	postgresVersionPattern = regexp.MustCompile(`PostgreSQL\s+(\d+(?:\.\d+)?)`)
	numericVersion         = regexp.MustCompile(`\d+(?:\.\d+)?`)
	athenaVersionPattern   = regexp.MustCompile(`(?i)^(?:athena engine version )?([0-9]+)$`)
)

func isAurora(raw string) bool { return strings.Contains(strings.ToLower(raw), "aurora") }

// 8.0.mysql_aurora.3.04.0 identifies MySQL 8.0, not Aurora 3.04.0.
func mysqlServerVersion(raw string) *pb.ServerVersion {
	if strings.TrimSpace(raw) == "" {
		return &pb.ServerVersion{}
	}
	base, _, _ := strings.Cut(raw, "mysql_aurora")
	base, _, _ = strings.Cut(base, "(aurora")
	version := patchVersion.FindString(base)
	if version == "" {
		version = minorVersion.FindString(base)
	}
	return &pb.ServerVersion{Version: nonEmpty(version), Aurora: isAurora(raw)}
}

// "PostgreSQL 16.4 on x86_64" -> 16.4.
func postgresServerVersion(raw string) *pb.ServerVersion {
	if strings.TrimSpace(raw) == "" {
		return &pb.ServerVersion{}
	}
	version := ""
	if m := postgresVersionPattern.FindStringSubmatch(raw); m != nil {
		version = m[1]
	} else {
		version = numericVersion.FindString(raw)
	}
	return &pb.ServerVersion{Version: nonEmpty(version), Aurora: isAurora(raw)}
}

// "Athena engine version 3" -> 3.
func athenaServerVersion(raw string) *pb.ServerVersion {
	if m := athenaVersionPattern.FindStringSubmatch(strings.TrimSpace(raw)); m != nil {
		return &pb.ServerVersion{Version: &m[1]}
	}
	return &pb.ServerVersion{}
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// 8.0.44 -> 8.0.
func mysqlManifestSeries(version string) string {
	parts := strings.Split(version, ".")
	return strings.Join(parts[:min(2, len(parts))], ".")
}

// nativeConnectionInfoValid accepts a wire proxy's host:port with only the engine's allowed properties.
func nativeConnectionInfoValid(e *Engine, info *pb.EngineConnectionInfo) bool {
	if !e.allowsProperties(info) {
		return false
	}
	if info.GetEndpoint() == "" {
		return len(info.GetProperties()) == 0
	}
	host, port, err := net.SplitHostPort(info.GetEndpoint())
	return err == nil && host != "" && validPort(port, false) && !strings.ContainsAny(info.GetEndpoint(), "/?#@ ")
}

var athenaRegion = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)

// Athena publishes region, workgroup, catalog and database together, plus an optional https endpoint.
func athenaConnectionInfoValid(e *Engine, info *pb.EngineConnectionInfo) bool {
	if !e.allowsProperties(info) {
		return false
	}
	properties := info.GetProperties()
	if info.GetEndpoint() == "" && len(properties) == 0 {
		return true
	}
	if len(properties) != len(e.connectionProperties) {
		return false
	}
	for _, value := range properties {
		if strings.TrimSpace(value) == "" {
			return false
		}
	}
	if !athenaRegion.MatchString(properties["region"]) {
		return false
	}
	if info.GetEndpoint() == "" {
		return true
	}
	u, err := url.Parse(info.GetEndpoint())
	return err == nil && !strings.Contains(info.GetEndpoint(), "#") && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" &&
		!u.ForceQuery && u.Fragment == "" && (u.Path == "" || u.Path == "/") && validPort(u.Port(), true)
}

func (e *Engine) allowsProperties(info *pb.EngineConnectionInfo) bool {
	for key := range info.GetProperties() {
		if !slices.Contains(e.connectionProperties, key) {
			return false
		}
	}
	return true
}

func validPort(port string, optional bool) bool {
	if port == "" {
		return optional
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

// sessionAnalyzerConfig is the engine, its version, and the session the proxy observed.
func sessionAnalyzerConfig(e *Engine, ds *pb.EngineDatasource, session *pb.SessionObservation, _ bool) (*pb.EngineConfig, error) {
	return &pb.EngineConfig{Engine: e.Proto, EngineVersion: ds.GetEngineVersion(), Session: session}, nil
}

// MySQL needs lower_case_table_names; a split waits for it and the version, a decision without it fails.
func mysqlAnalyzerConfig(e *Engine, ds *pb.EngineDatasource, session *pb.SessionObservation, split bool) (*pb.EngineConfig, error) {
	if split && (strings.TrimSpace(ds.GetEngineVersion()) == "" || ds.MysqlLowerCaseTableNames == nil) {
		return nil, nil
	}
	if ds.MysqlLowerCaseTableNames == nil {
		return nil, fmt.Errorf("MySQL lower_case_table_names has not been captured by introspection")
	}
	return &pb.EngineConfig{
		Engine: e.Proto, EngineVersion: ds.GetEngineVersion(),
		MysqlLowerCaseTableNames: proto.Int32(ds.GetMysqlLowerCaseTableNames()), Session: session,
	}, nil
}

// A decision that carries no request (an editor run, a stored-result view) runs in the datasource's
// registered workgroup with no parameters.
func athenaAnalyzerConfig(e *Engine, ds *pb.EngineDatasource, session *pb.SessionObservation, split bool) (*pb.EngineConfig, error) {
	if session.GetAthena() == nil {
		session = proto.Clone(session).(*pb.SessionObservation)
		session.Engine = &pb.SessionObservation_Athena{Athena: &pb.AthenaSqlContext{Workgroup: ds.GetProperties()["workgroup"]}}
	}
	return sessionAnalyzerConfig(e, ds, session, split)
}
