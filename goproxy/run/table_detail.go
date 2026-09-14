package run

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/spi"
)

// TableDetailRunner runs one short-lived, proxy-dialed table-detail session.
type TableDetailRunner struct {
	client spi.TableDetailClient
	target spi.Target
}

// NewTableDetailRunner constructs a table-detail runner for one datasource target.
func NewTableDetailRunner(client spi.TableDetailClient, target spi.Target) *TableDetailRunner {
	return &TableDetailRunner{client: client, target: target}
}

// Run blocks for the short table-detail session lifetime.
func (r *TableDetailRunner) Run(open *pb.OpenTableDetailChannel) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream, err := r.client.OpenTableDetailStream(ctx)
	if err != nil {
		return
	}
	if err := stream.Send(&pb.ProxyTableDetailMsg{
		Kind: &pb.ProxyTableDetailMsg_SessionReady{
			SessionReady: &pb.TableDetailReady{SessionId: open.GetSessionId()},
		},
	}); err != nil {
		return
	}

	var detail *spi.TableDetail
	var detailErr error
	if open.Catalog != nil && open.GetCatalog() == "" {
		detailErr = errors.New("table selector has blank catalog")
	} else {
		detail, detailErr = r.target.ReadTableDetail(ctx, &enginepb.TableRef{Catalog: open.GetCatalog(), Schema: open.GetSchema(), Table: open.GetTable()})
	}
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
