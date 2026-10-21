package run

import (
	"context"
	"encoding/json"
	"strings"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
)

// RunTableDetail blocks for one short-lived, proxy-dialed table-detail session.
func (r *Runner) RunTableDetail(sessionID string, table *enginepb.ObjectRef) {
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

	detail, detailErr := r.target.ReadTableDetail(ctx, table)
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
