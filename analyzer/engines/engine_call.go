package engines

import (
	"embed"
	"fmt"
	"net"
	"path"
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
		response.Result = &pb.EngineCallResponse_AnalyzerConfig{AnalyzerConfig: e.analyzerConfig(e, call.AnalyzerConfig.GetDatasource(), session)}
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
		ImplicitColumns:                e.implicitColumns,
		DefaultSchemaSettable:          e.DefaultSchemaSettable,
	}
}

// QuoteIdentifier writes name as one quoted identifier: users -> `users`, a`b -> `a“b`.
func (e *Engine) QuoteIdentifier(name string) string {
	return e.IdentifierQuote + strings.ReplaceAll(name, e.IdentifierQuote, e.IdentifierQuote+e.IdentifierQuote) + e.IdentifierQuote
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

func isAurora(raw string) bool { return strings.Contains(strings.ToLower(raw), "aurora") }

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
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

// sessionAnalyzerConfig is the engine, its datasource, and the session the proxy observed.
func sessionAnalyzerConfig(e *Engine, ds *pb.EngineDatasource, session *pb.SessionObservation) *pb.EngineConfig {
	return &pb.EngineConfig{Engine: e.Proto, Datasource: ds, Session: session}
}
