package run

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

const (
	tableDetailQueryTimeout   = 30 * time.Second
	tableDetailConnectTimeout = 5 * time.Second
)

// TableDetailRunner runs one short-lived, proxy-dialed table-detail session.
type TableDetailRunner struct {
	client   spi.TableDetailClient
	targetDb spi.TargetDb
	provider spi.Provider
}

// NewTableDetailRunner constructs a table-detail runner for one datasource target.
func NewTableDetailRunner(client spi.TableDetailClient, targetDb spi.TargetDb, provider spi.Provider) *TableDetailRunner {
	return &TableDetailRunner{client: client, targetDb: targetDb, provider: provider}
}

// Run blocks for the short table-detail session lifetime.
func (r *TableDetailRunner) Run(sessionID, schema, table string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream, err := r.client.OpenTableDetailStream(ctx)
	if err != nil {
		return
	}
	if err := stream.Send(&pb.ProxyTableDetailMsg{
		Kind: &pb.ProxyTableDetailMsg_SessionReady{
			SessionReady: &pb.TableDetailReady{SessionId: sessionID},
		},
	}); err != nil {
		return
	}

	detail, detailErr := r.read(schema, table)
	if detailErr != nil {
		message := "table introspection failed"
		if text := strings.TrimSpace(detailErr.Error()); text != "" {
			message += ": " + text
		}
		if err := stream.Send(&pb.ProxyTableDetailMsg{
			Kind: &pb.ProxyTableDetailMsg_Error{
				Error: &pb.TableDetailError{Message: message},
			},
		}); err != nil {
			return
		}
	} else {
		payload := []byte("null")
		if detail != nil {
			payload, err = json.Marshal(detail)
			if err != nil {
				message := "table introspection failed"
				if text := strings.TrimSpace(err.Error()); text != "" {
					message += ": " + text
				}
				if sendErr := stream.Send(&pb.ProxyTableDetailMsg{
					Kind: &pb.ProxyTableDetailMsg_Error{
						Error: &pb.TableDetailError{Message: message},
					},
				}); sendErr != nil {
					return
				}
				payload = nil
			}
		}
		if payload != nil {
			if err := stream.Send(&pb.ProxyTableDetailMsg{
				Kind: &pb.ProxyTableDetailMsg_Result{
					Result: &pb.TableDetailResult{Json: string(payload)},
				},
			}); err != nil {
				return
			}
		}
	}

	for {
		message, err := stream.Recv()
		if err != nil {
			return
		}
		if message.GetClose() != nil {
			return
		}
	}
}

func (r *TableDetailRunner) read(schema, table string) (*spi.TableDetail, error) {
	sqlDB, err := r.provider.OpenTarget(r.targetDb)
	if err != nil {
		return nil, err
	}
	defer sqlDB.Close()

	connectCtx, connectCancel := context.WithTimeout(context.Background(), tableDetailConnectTimeout+tableDetailQueryTimeout)
	defer connectCancel()
	conn, err := sqlDB.Conn(connectCtx)
	if err != nil {
		return nil, fmt.Errorf("connecting to target: %w", err)
	}
	defer conn.Close()

	resolvedSchema := r.provider.Dialect().ResolveSchema(schema, r.targetDb.Db)
	return r.provider.ReadTableDetail(conn, resolvedSchema, table)
}
