package athena

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsa "github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/athena/types"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const metadataTimeout = 60 * time.Second

// newProxyCommandRunner answers the control plane's per-connection catalog commands from Glue table metadata.
func (t *target) newProxyCommandRunner(authz *spi.Authorizer) (*relay.ProxyCommandRunner, error) {
	generation, ok := t.generations.Next()
	if !ok {
		return nil, errors.New("athena: backend generation out of range")
	}
	return &relay.ProxyCommandRunner{
		Catalog:           t.catalogIdentity(),
		ConnectionID:      authz.ConnectionID(),
		BackendGeneration: generation,
		Inspector:         t,
		Push:              authz.Client().PushSchemaFragment,
	}, nil
}

// maxPreparedDefinitions bounds the definitions one decision may accumulate across its before-decide rounds.
const maxPreparedDefinitions = 8

// InspectSchema lists a database from Glue. The listing is the inspection, so its hash is always trusted.
func (t *target) InspectSchema(schema string, ifHashDiffers []byte) (*pb.SchemaFragmentPush, error) {
	ctx, cancel := context.WithTimeout(context.Background(), metadataTimeout)
	defer cancel()
	columns, err := t.fragmentColumns(ctx, t.settings.catalog, schema)
	if err != nil {
		return nil, fmt.Errorf("introspecting schema %q: %w", schema, err)
	}
	hash, err := fragmentHash(columns)
	if err != nil {
		return nil, err
	}
	if len(ifHashDiffers) > 0 && string(ifHashDiffers) == string(hash) {
		return &pb.SchemaFragmentPush{ContentHash: hash, Unchanged: true}, nil
	}
	return &pb.SchemaFragmentPush{ContentHash: hash, Columns: columns}, nil
}

// RunCommand reads a FetchAthenaPreparedDefinition's prepared statement from the workgroup and appends it to
// snapshot's Athena scope, so the re-sent decision carries it. Any other arm fails closed.
func (t *target) RunCommand(command *pb.ProxyCommand, snapshot *spi.SessionSnapshot) error {
	fetch := command.GetFetchAthenaPreparedDefinition()
	if fetch == nil {
		return relay.ErrUnknownCommand
	}
	return t.fetchPreparedDefinitionInto(fetch, snapshot)
}

// fragmentColumns lists one database's columns; a database Glue does not know is an empty fragment, so a
// statement naming it resolves fail-closed instead of erroring the connection.
func (t *target) fragmentColumns(ctx context.Context, catalog, database string) ([]*enginepb.Column, error) {
	columns, err := t.readColumns(ctx, catalog, database)
	var metadata *types.MetadataException
	if errors.As(err, &metadata) && strings.Contains(strings.ToLower(aws.ToString(metadata.Message)), "not found") {
		return []*enginepb.Column{}, nil
	}
	if err != nil {
		return nil, err
	}
	if columns == nil {
		columns = []*enginepb.Column{}
	}
	return columns, nil
}

func fragmentHash(columns []*enginepb.Column) ([]byte, error) {
	rows := make([][]any, 0, len(columns))
	for _, column := range columns {
		rows = append(rows, []any{column.GetCatalog(), column.GetSchema(), column.GetTable(), column.GetColumn(), column.GetDataType(), column.GetOrdinal(), column.GetNullable()})
	}
	data, err := json.Marshal(rows)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	return hash[:], nil
}

// fetchPreparedDefinitionInto answers a fetch_athena_prepared_definition command from the workgroup's own
// prepared statements and appends the result to session's Athena scope; the analyzer never trusts a
// definition the client supplied. The fetch must name the request's workgroup, must not repeat one already
// held, and the scope holds at most maxPreparedDefinitions per decision.
func (t *target) fetchPreparedDefinitionInto(fetch *enginepb.FetchAthenaPreparedDefinition, snapshot *spi.SessionSnapshot) error {
	if fetch.GetWorkgroup() == "" || fetch.GetName() == "" {
		return errors.New("blank prepared definition selector")
	}
	scope := snapshot.GetAthena()
	if snapshot == nil || scope == nil {
		return errors.New("the request carries no Athena scope")
	}
	if fetch.GetWorkgroup() != scope.GetWorkgroup() {
		return errors.New("prepared definition fetch names a workgroup outside the request scope")
	}
	for _, held := range scope.GetPreparedDefinitions() {
		if held.GetName() == fetch.GetName() && held.GetWorkgroup() == fetch.GetWorkgroup() {
			return fmt.Errorf("prepared definition %q was already fetched", fetch.GetName())
		}
	}
	if len(scope.GetPreparedDefinitions()) >= maxPreparedDefinitions {
		return errors.New("too many prepared definitions for one decision")
	}
	definition, err := t.fetchPreparedDefinition(fetch)
	if err != nil {
		return err
	}
	scope.PreparedDefinitions = append(scope.PreparedDefinitions, definition)
	return nil
}

func (t *target) fetchPreparedDefinition(fetch *enginepb.FetchAthenaPreparedDefinition) (*enginepb.AthenaPreparedDefinition, error) {
	ctx, cancel := context.WithTimeout(context.Background(), metadataTimeout)
	defer cancel()
	response, err := t.api.GetPreparedStatement(ctx, &awsa.GetPreparedStatementInput{
		WorkGroup: aws.String(fetch.GetWorkgroup()), StatementName: aws.String(fetch.GetName()),
	})
	if err != nil {
		return nil, err
	}
	statement := response.PreparedStatement
	if statement == nil || aws.ToString(statement.StatementName) != fetch.GetName() || aws.ToString(statement.QueryStatement) == "" {
		return nil, errors.New("athena: prepared statement metadata is incomplete")
	}
	return &enginepb.AthenaPreparedDefinition{Workgroup: fetch.GetWorkgroup(), Name: fetch.GetName(), QueryString: aws.ToString(statement.QueryStatement)}, nil
}
