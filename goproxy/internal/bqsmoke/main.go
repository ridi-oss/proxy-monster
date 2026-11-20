// Command bqsmoke is the smoke Storage Read client, and a relay that frames the emulator's Arrow as Google does.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: bqsmoke read|relay [flags]")
		os.Exit(2)
	}
	flags := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	addr := flags.String("addr", "", "read: the server's host:port; relay: the address to listen on")
	ca := flags.String("ca", "", "read: PEM bundle to trust; cleartext HTTP/2 without it")
	token := flags.String("token", "", "read: bearer token")
	parent := flags.String("parent", "", "read: projects/<billing project>")
	table := flags.String("table", "", "read: projects/<p>/datasets/<d>/tables/<t>")
	cert := flags.String("cert", "", "relay: TLS certificate")
	key := flags.String("key", "", "relay: TLS key")
	upstream := flags.String("upstream", "", "relay: the emulator's cleartext gRPC host:port")
	_ = flags.Parse(os.Args[2:])
	switch os.Args[1] {
	case "read":
		out, err := read(*addr, *ca, *token, *parent, *table)
		if err != nil {
			s, _ := status.FromError(err)
			fmt.Fprintf(os.Stderr, "%s: %s\n", s.Code(), s.Message())
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)
	case "relay":
		if err := relay(*addr, *cert, *key, *upstream); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		os.Exit(2)
	}
}

type result struct {
	Fields []string    `json:"fields"`
	Rows   [][]*string `json:"rows"`
}

func read(addr, ca, token, parent, table string) (*result, error) {
	creds := insecure.NewCredentials()
	if ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("no certificate in " + ca)
		}
		creds = credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := storagepb.NewBigQueryReadClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	session, err := client.CreateReadSession(ctx, &storagepb.CreateReadSessionRequest{
		Parent: parent, MaxStreamCount: 1,
		ReadSession: &storagepb.ReadSession{Table: table, DataFormat: storagepb.DataFormat_ARROW},
	})
	if err != nil {
		return nil, err
	}
	schema := session.GetArrowSchema().GetSerializedSchema()
	out := &result{Fields: []string{}, Rows: [][]*string{}}
	for _, stream := range session.GetStreams() {
		rows, err := client.ReadRows(ctx, &storagepb.ReadRowsRequest{ReadStream: stream.GetName()})
		if err != nil {
			return nil, err
		}
		for {
			response, err := rows.Recv()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, err
			}
			if err := decode(out, schema, response.GetArrowRecordBatch().GetSerializedRecordBatch()); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func decode(out *result, schema, batch []byte) error {
	reader, err := ipc.NewReader(io.MultiReader(bytes.NewReader(schema), bytes.NewReader(batch)))
	if err != nil {
		return err
	}
	defer reader.Release()
	out.Fields = out.Fields[:0]
	for _, field := range reader.Schema().Fields() {
		out.Fields = append(out.Fields, field.Name)
	}
	for reader.Next() {
		record := reader.RecordBatch()
		for i := range int(record.NumRows()) {
			row := make([]*string, record.NumCols())
			for j, column := range record.Columns() {
				if !column.IsNull(i) {
					value := column.ValueStr(i)
					row[j] = &value
				}
			}
			out.Rows = append(out.Rows, row)
		}
	}
	return reader.Err()
}

type relayServer struct {
	storagepb.UnimplementedBigQueryReadServer
	upstream storagepb.BigQueryReadClient
}

func relay(addr, cert, key, upstream string) error {
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(upstream, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{pair}})))
	storagepb.RegisterBigQueryReadServer(server, &relayServer{upstream: storagepb.NewBigQueryReadClient(conn)})
	return server.Serve(listener)
}

func (r *relayServer) CreateReadSession(ctx context.Context, request *storagepb.CreateReadSessionRequest) (*storagepb.ReadSession, error) {
	session, err := r.upstream.CreateReadSession(ctx, request)
	if err != nil {
		return nil, err
	}
	if arrow := session.GetArrowSchema(); arrow != nil {
		if arrow.SerializedSchema, err = schemaMessage(arrow.SerializedSchema); err != nil {
			return nil, err
		}
	}
	return session, nil
}

func (r *relayServer) ReadRows(request *storagepb.ReadRowsRequest, stream storagepb.BigQueryRead_ReadRowsServer) error {
	upstream, err := r.upstream.ReadRows(stream.Context(), request)
	if err != nil {
		return err
	}
	for {
		response, err := upstream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if arrow := response.GetArrowSchema(); arrow != nil {
			if arrow.SerializedSchema, err = schemaMessage(arrow.SerializedSchema); err != nil {
				return err
			}
		}
		if batch := response.GetArrowRecordBatch(); batch != nil {
			if batch.SerializedRecordBatch, err = batchMessage(batch.SerializedRecordBatch); err != nil {
				return err
			}
		}
		if err := stream.Send(response); err != nil {
			return err
		}
	}
}

func (r *relayServer) SplitReadStream(ctx context.Context, request *storagepb.SplitReadStreamRequest) (*storagepb.SplitReadStreamResponse, error) {
	return r.upstream.SplitReadStream(ctx, request)
}

func schemaMessage(stream []byte) ([]byte, error) {
	reader, err := ipc.NewReader(bytes.NewReader(stream))
	if err != nil {
		return nil, err
	}
	defer reader.Release()
	payload := ipc.GetSchemaPayload(reader.Schema(), memory.DefaultAllocator)
	defer payload.Release()
	var out bytes.Buffer
	_, err = payload.WritePayload(&out)
	return out.Bytes(), err
}

func batchMessage(stream []byte) ([]byte, error) {
	reader, err := ipc.NewReader(bytes.NewReader(stream))
	if err != nil {
		return nil, err
	}
	defer reader.Release()
	if !reader.Next() {
		return nil, fmt.Errorf("no record batch: %v", reader.Err())
	}
	payload, err := ipc.GetRecordBatchPayload(reader.RecordBatch())
	if err != nil {
		return nil, err
	}
	defer payload.Release()
	var out bytes.Buffer
	_, err = payload.WritePayload(&out)
	return out.Bytes(), err
}
