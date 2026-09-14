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
	"github.com/ridi-oss/proxy-monster/goproxy/wire"
	"google.golang.org/protobuf/proto"
)

const metadataTimeout = 60 * time.Second

// refetcher answers the control plane's per-connection catalog commands from Glue table metadata. The
// listing is the measurement, so its hash is always trusted.
type refetcher struct {
	target       *target
	connectionID []byte
	generation   uint64
	push         func(*pb.SchemaFragmentPush) (uint64, error)
}

func (t *target) newRefetcher(connectionID []byte, push func(*pb.SchemaFragmentPush) (uint64, error)) (*refetcher, error) {
	generation, ok := wire.NextBackendGeneration()
	if !ok {
		return nil, errors.New("athena: backend generation out of range")
	}
	return &refetcher{target: t, connectionID: append([]byte(nil), connectionID...), generation: generation, push: push}, nil
}

func (r *refetcher) RunAll(commands []*pb.Refetch) error {
	for i, command := range commands {
		if err := r.run(command); err != nil {
			return fmt.Errorf("refetch command %d: %w", i, err)
		}
	}
	return nil
}

func (r *refetcher) run(command *pb.Refetch) error {
	if command.GetSchema() == "" {
		return errors.New("refetch command has blank schema")
	}
	catalog := r.target.catalogIdentity()
	if command.Catalog != nil && command.GetCatalog() != catalog {
		return fmt.Errorf("refetch catalog %q does not match target catalog %q", command.GetCatalog(), catalog)
	}
	ctx, cancel := context.WithTimeout(context.Background(), metadataTimeout)
	defer cancel()
	columns, err := r.target.fragmentColumns(ctx, r.target.config.catalog, command.GetSchema())
	if err != nil {
		return fmt.Errorf("introspecting schema %q: %w", command.GetSchema(), err)
	}
	hash, err := fragmentHash(columns)
	if err != nil {
		return err
	}
	push := &pb.SchemaFragmentPush{
		ConnectionId:      append([]byte(nil), r.connectionID...),
		Schema:            command.GetSchema(),
		Catalog:           proto.String(catalog),
		ContentHash:       hash,
		BackendGeneration: r.generation,
	}
	if len(command.GetIfHashDiffers()) > 0 && string(command.GetIfHashDiffers()) == string(hash) {
		push.Unchanged = true
	} else {
		push.Columns = columns
	}
	_, err = r.push(push)
	return err
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
