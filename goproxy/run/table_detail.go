package run

import (
	"context"
	"encoding/json"
	"strings"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// TableDetailRunner runs one short-lived, proxy-dialed table-detail session.
type TableDetailRunner struct {
	client   spi.TableDetailClient
	targetDb spi.Db
}

// NewTableDetailRunner constructs a table-detail runner for one datasource target.
func NewTableDetailRunner(client spi.TableDetailClient, targetDb spi.Db) *TableDetailRunner {
	return &TableDetailRunner{client: client, targetDb: targetDb}
}

// Run blocks for the short table-detail session lifetime.
func (r *TableDetailRunner) Run(sessionID string, table *enginepb.ObjectRef) {
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

	detail, detailErr := r.targetDb.ReadTableDetail(ctx, table)
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
