package relay

import (
	"errors"
	"fmt"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// Inspector is the engine's part of a ProxyCommandRunner: it reads the target behind one connection.
type Inspector interface {
	// InspectSchema returns schema's ContentHash with either Unchanged set (it equals ifHashDiffers) or its
	// Columns and Routines.
	InspectSchema(schema string, ifHashDiffers []byte) (*pb.SchemaFragmentPush, error)
	// RunCommand runs a command other than Refetch.
	RunCommand(command *pb.ProxyCommand, snapshot *spi.SessionSnapshot) error
}

// ProxyCommandRunner runs one connection's ProxyCommands and pushes each refetched schema to the control plane.
type ProxyCommandRunner struct {
	Catalog           string
	ConnectionID      []byte
	BackendGeneration uint64
	Inspector         Inspector
	Push              func(*pb.SchemaFragmentPush) (uint64, error)
}

// ErrUnknownCommand is a command arm the engine does not run; the list fails closed on it.
var ErrUnknownCommand = errors.New("not a command this engine runs")

// RunAll runs commands in order and stops at the first failure.
func (r *ProxyCommandRunner) RunAll(commands []*pb.ProxyCommand, snapshot *spi.SessionSnapshot) error {
	for i, command := range commands {
		if refetch := command.GetRefetch(); refetch != nil {
			if err := r.Refetch(refetch); err != nil {
				return fmt.Errorf("refetch command %d: %w", i, err)
			}
			continue
		}
		if err := r.Inspector.RunCommand(command, snapshot); err != nil {
			return fmt.Errorf("command %d: %w", i, err)
		}
	}
	return nil
}

// Refetch inspects one schema and pushes it. A failed inspection or push is an error, and the schema stays
// pending until it is re-asked.
func (r *ProxyCommandRunner) Refetch(command *pb.Refetch) error {
	if command.GetSchema() == "" {
		return errors.New("refetch command has blank schema")
	}
	if r.Push == nil {
		return errors.New("command runner has no push callback")
	}
	if r.Catalog == "" {
		return errors.New("command runner has no catalog")
	}
	if command.GetCatalog() != r.Catalog {
		return fmt.Errorf("refetch catalog %q does not match target catalog %q", command.GetCatalog(), r.Catalog)
	}
	push, err := r.Inspector.InspectSchema(command.GetSchema(), command.GetIfHashDiffers())
	if err != nil {
		return err
	}
	push.ConnectionId = append([]byte(nil), r.ConnectionID...)
	push.Schema = command.GetSchema()
	push.Catalog = r.Catalog
	push.BackendGeneration = r.BackendGeneration
	_, err = r.Push(push)
	return err
}

var _ spi.ProxyCommandRunner = (*ProxyCommandRunner)(nil)
