package athena

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
)

type endpointTransport struct {
	endpoint  *url.URL
	transport http.RoundTripper
}

func (t endpointTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	request = request.Clone(request.Context())
	if request.Host == "" {
		request.Host = request.URL.Host
	}
	request.URL.Scheme, request.URL.Host = t.endpoint.Scheme, t.endpoint.Host
	return t.transport.RoundTrip(request)
}

func testTarget(t *testing.T, handler http.HandlerFunc) *target {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.Host, "sts.") {
			w.Header().Set("Content-Type", "text/xml")
			_, _ = io.WriteString(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/test-role/session</Arn><UserId>AROATEST:session</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`)
			return
		}
		handler(w, request)
	}))
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := targetConfig{region: "us-east-1", workgroup: "primary", catalog: "AwsDataCatalog", database: "example", contextPath: ":memory:"}
	result, err := newTarget(context.Background(), cfg, aws.Config{
		Region: cfg.region, Credentials: credentials.NewStaticCredentialsProvider("test-key", "test-secret", "test-session"),
	}, endpointTransport{endpoint: endpoint, transport: server.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = result.Close() })
	return result
}

func TestProviderConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name  string
		env   map[string]string
		valid bool
	}{
		{"region from shared profile", nil, true},
		{"defaults", map[string]string{"AWS_REGION": "us-east-1"}, true},
		{"custom region", map[string]string{"PM_ATHENA_REGION": "cn-north-1"}, true},
		{"endpoint injection", map[string]string{"AWS_REGION": "us-east-1.attacker.example"}, false},
		{"empty scope", map[string]string{"AWS_REGION": "us-east-1", "PM_ATHENA_WORKGROUP": ""}, false},
		{"http advertised", map[string]string{"AWS_REGION": "us-east-1", "PM_ADVERTISE_ADDR": "http://proxy.example"}, false},
		{"https advertised is not host port", map[string]string{"AWS_REGION": "us-east-1", "PM_ADVERTISE_ADDR": "https://proxy.example:6443"}, false},
		{"host port advertised", map[string]string{"AWS_REGION": "us-east-1", "PM_ADVERTISE_ADDR": "proxy.example:6443"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := configure(func(key string) (string, bool) { value, ok := tc.env[key]; return value, ok })
			if (err == nil) != tc.valid {
				t.Fatalf("configure error = %v; valid = %v", err, tc.valid)
			}
		})
	}
}

func TestAWSForwardSigning(t *testing.T) {
	var received bool
	target := testTarget(t, func(w http.ResponseWriter, request *http.Request) {
		received = true
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if request.Host != "athena.us-east-1.amazonaws.com" || request.Header.Get("X-Amz-Security-Token") != "test-session" {
			t.Errorf("wrong upstream host or credentials")
		}
		provided := request.Header.Get("Authorization")
		when, err := time.Parse("20060102T150405Z", request.Header.Get("X-Amz-Date"))
		if err != nil {
			t.Error(err)
			return
		}
		request.Header.Del("Authorization")
		request.URL.Scheme, request.URL.Host = "https", request.Host
		hash := sha256.Sum256(body)
		err = v4.NewSigner().SignHTTP(request.Context(), aws.Credentials{AccessKeyID: "test-key", SecretAccessKey: "test-secret", SessionToken: "test-session"}, request, hex.EncodeToString(hash[:]), "athena", "us-east-1", when)
		if err != nil {
			t.Error(err)
			return
		}
		if request.Header.Get("Authorization") != provided {
			t.Errorf("signature does not match final forwarded payload")
		}
		w.Header().Set("X-Amzn-Requestid", "aws-native-id")
		_, _ = io.WriteString(w, `{"FutureField":1.00,"NextToken":"native-token"}`)
	})
	forwarder, err := NewForwarder(ForwardOptions{Endpoint: target.endpoint, MaxBodyBytes: defaultRequestLimit, Sign: target.sign, Transport: target.transport,
		Authorize: func(_ context.Context, request *http.Request, envelope *Envelope) (*Envelope, error) {
			if request.Header.Get("X-Amz-Target") != "AmazonAthena.FutureOperation" {
				return nil, ErrUnauthorized
			}
			return envelope, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://proxy.example/", strings.NewReader(`{"FutureInput":1.00}`))
	request.Header.Set("X-Amz-Target", "AmazonAthena.FutureOperation")
	request.Header.Set("Content-Type", "application/x-amz-json-1.1")
	request.Header.Set("Authorization", "Bearer local-token")
	response, err := forwarder.Forward(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !received || string(body) != `{"FutureField":1.00,"NextToken":"native-token"}` || response.Header.Get("X-Amzn-Requestid") != "aws-native-id" {
		t.Fatalf("native response changed: %s", body)
	}
}

func TestSDKMetadataPreservesCatalogAndPartitions(t *testing.T) {
	calls := make(map[string]int)
	target := testTarget(t, func(w http.ResponseWriter, request *http.Request) {
		operation := request.Header.Get("X-Amz-Target")
		calls[operation]++
		if !strings.Contains(request.Header.Get("Authorization"), "/us-east-1/athena/aws4_request") {
			t.Error("SDK request is unsigned")
		}
		body, _ := io.ReadAll(request.Body)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch operation {
		case "AmazonAthena.ListDataCatalogs":
			_, _ = io.WriteString(w, `{"DataCatalogsSummary":[{"CatalogName":"AwsDataCatalog"}]}`)
		case "AmazonAthena.ListDatabases":
			_, _ = io.WriteString(w, `{"DatabaseList":[{"Name":"example"}]}`)
		case "AmazonAthena.GetWorkGroup":
			_, _ = io.WriteString(w, `{"WorkGroup":{"Name":"primary","Configuration":{"EngineVersion":{"EffectiveEngineVersion":"Athena engine version 3"}}}}`)
		case "AmazonAthena.ListTableMetadata":
			if !strings.Contains(string(body), `"CatalogName":"AwsDataCatalog"`) || !strings.Contains(string(body), `"DatabaseName":"example"`) {
				t.Errorf("missing scoped namespace: %s", body)
			}
			if calls[operation] == 1 {
				_, _ = io.WriteString(w, `{"TableMetadataList":[{"Name":"events","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"email","Type":"string"}],"PartitionKeys":[{"Name":"day","Type":"date"}]}],"NextToken":"aws-next"}`)
			} else {
				if !strings.Contains(string(body), `"NextToken":"aws-next"`) {
					t.Error("SDK did not preserve pagination token")
				}
				_, _ = io.WriteString(w, `{"TableMetadataList":[]}`)
			}
		case "AmazonAthena.GetTableMetadata":
			_, _ = io.WriteString(w, `{"TableMetadata":{"Name":"events","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"email","Type":"string","Comment":"contact"}],"PartitionKeys":[{"Name":"day","Type":"date"}]}}`)
		default:
			t.Errorf("unexpected metadata call %s", operation)
			w.WriteHeader(400)
		}
	})
	catalog, err := target.ReadCatalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if catalog.GetCurrentCatalog() != "awsdatacatalog" || catalog.EngineVersion != "Athena engine version 3" || len(catalog.Catalog.Columns) != 2 || catalog.Catalog.Columns[1].Column != "day" || catalog.Catalog.Columns[1].Ordinal != 2 {
		t.Fatalf("bad catalog: %v", catalog)
	}
	detail, err := target.ReadTableDetail(context.Background(), &enginepb.TableRef{Catalog: "AwsDataCatalog", Schema: "example", Table: "events"})
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.Columns) != 2 || *detail.Catalog != "awsdatacatalog" || *detail.Columns[0].Comment != "contact" {
		t.Fatalf("bad detail: %+v", detail)
	}
	other, err := target.ReadTableDetail(context.Background(), &enginepb.TableRef{Catalog: "other", Schema: "elsewhere", Table: "events"})
	if err != nil || other == nil || other.Catalog == nil || *other.Catalog != "other" || other.Schema != "elsewhere" {
		t.Fatalf("explicit cross-catalog table failed: %v", err)
	}
	if calls["AmazonAthena.ListTableMetadata"] != 2 || calls["AmazonAthena.GetTableMetadata"] != 2 {
		t.Fatalf("wrong call counts: %v", calls)
	}
}
