package engines

import (
	"embed"
	"fmt"
	"net"
	"net/url"
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
		response.Result = &pb.EngineCallResponse_Text{Text: e.Traits.defaultSchema(call.DefaultSchema)}
	case *pb.EngineCallRequest_SchemaKind:
		// The control plane stores schema names in canonical spelling.
		schema := SchemaName{name: call.SchemaKind}
		response.Result = &pb.EngineCallResponse_SchemaKind{SchemaKind: &pb.SchemaKind{
			FixedSystem: slices.Contains(e.Traits.systemSchemas, schema),
			System:      e.IsSystemSchema(schema),
			Temp:        e.IsTempSchema(schema),
		}}
	case *pb.EngineCallRequest_AnalyzerConfig:
		session := call.AnalyzerConfig.GetSession()
		if session == nil {
			session = &pb.SessionObservation{}
		}
		response.Result = &pb.EngineCallResponse_AnalyzerConfig{AnalyzerConfig: e.analyzerConfig(call.AnalyzerConfig.GetTarget(), session)}
	case *pb.EngineCallRequest_ServerVersion:
		response.Result = &pb.EngineCallResponse_ServerVersion{ServerVersion: e.Traits.serverVersion(call.ServerVersion)}
	case *pb.EngineCallRequest_ManifestSeries:
		response.Result = &pb.EngineCallResponse_Text{Text: e.Traits.manifestSeries(call.ManifestSeries)}
	case *pb.EngineCallRequest_FunctionCatalog:
		catalog := e.Traits.functionCatalog(e, call.FunctionCatalog.GetRoutines(), call.FunctionCatalog.GetEngineVersion())
		response.Result = &pb.EngineCallResponse_FunctionCatalog{FunctionCatalog: catalog}
	case *pb.EngineCallRequest_ConnectionInfo:
		response.Result = &pb.EngineCallResponse_Valid{Valid: e.connectionInfoValid(call.ConnectionInfo)}
	case *pb.EngineCallRequest_DefaultSchemaStatement:
		if !e.Traits.DefaultSchemaSettable {
			return fmt.Errorf("%s has no statement that sets a default schema", e.WireName)
		}
		response.Result = &pb.EngineCallResponse_Text{Text: e.Traits.defaultSchemaPrefix + e.QuoteIdentifier(call.DefaultSchemaStatement)}
	default:
		return fmt.Errorf("unknown engine call %T", call)
	}
	return nil
}

func (e *Engine) facts() *pb.EngineFacts {
	system := make([]string, len(e.Traits.systemSchemas))
	for i, s := range e.Traits.systemSchemas {
		system[i] = s.name
	}
	return &pb.EngineFacts{
		WireName:                       e.WireName,
		IdentifierQuote:                e.Traits.IdentifierQuote,
		SystemSchemas:                  system,
		ConnectionProperties:           e.Traits.connectionProperties,
		CatalogIsConnectionIndependent: e.Traits.catalogIsConnectionIndependent,
		ChecksTargetErrors:             e.Traits.checksTargetErrors,
		ImplicitColumns:                e.Traits.implicitColumns,
		DefaultSchemaSettable:          e.Traits.DefaultSchemaSettable,
	}
}

// QuoteIdentifier writes name as one quoted identifier: users -> `users`, a`b -> `a“b`.
func (e *Engine) QuoteIdentifier(name string) string {
	return e.Traits.IdentifierQuote + strings.ReplaceAll(name, e.Traits.IdentifierQuote, e.Traits.IdentifierQuote+e.Traits.IdentifierQuote) + e.Traits.IdentifierQuote
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

// connectionInfoValid reports whether the engine's proxies may publish info: all of the engine's properties or none,
// and a wire host:port, or for Athena an https URL with no path, query, user or fragment.
func (e *Engine) connectionInfoValid(info *pb.EngineConnectionInfo) bool {
	properties := info.GetProperties()
	if info.GetEndpoint() == "" && len(properties) == 0 {
		return true
	}
	if len(properties) != len(e.Traits.connectionProperties) {
		return false
	}
	for _, key := range e.Traits.connectionProperties {
		value, ok := properties[key]
		if !ok || strings.TrimSpace(value) == "" {
			return false
		}
		if pattern := e.Traits.connectionPropertyPatterns[key]; pattern != nil && !pattern.MatchString(value) {
			return false
		}
	}
	endpoint := info.GetEndpoint()
	switch {
	case endpoint == "":
		return true
	case e.Traits.endpointIsURL:
		u, err := url.Parse(endpoint)
		return err == nil && !strings.Contains(endpoint, "#") && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" &&
			!u.ForceQuery && u.Fragment == "" && (u.Path == "" || u.Path == "/") && validPort(u.Port(), true)
	default:
		host, port, err := net.SplitHostPort(endpoint)
		return err == nil && host != "" && validPort(port, false) && !strings.ContainsAny(endpoint, "/?#@ ")
	}
}

func validPort(port string, optional bool) bool {
	if port == "" {
		return optional
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

// analyzerConfig is the EngineConfig for one decision or a batch split.
func (e *Engine) analyzerConfig(targetSettings *pb.TargetSettings, session *pb.SessionObservation) *pb.EngineConfig {
	if session.GetEngine() == nil && e.Traits.defaultSession != nil {
		session = e.Traits.defaultSession(targetSettings)
	}
	return &pb.EngineConfig{Engine: e.Proto, Target: targetSettings, Session: session}
}
