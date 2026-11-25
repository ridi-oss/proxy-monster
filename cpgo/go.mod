module github.com/ridi-oss/proxy-monster/cpgo

go 1.27.4

require (
	github.com/alecthomas/kong v1.17.0
	github.com/aws/aws-sdk-go-v2 v1.48.0
	github.com/aws/aws-sdk-go-v2/config v1.33.21
	github.com/aws/aws-sdk-go-v2/service/acm v1.52.0
	github.com/aws/aws-sdk-go-v2/service/kms v1.63.0
	github.com/bradleyfalzon/ghinstallation/v2 v2.19.0
	github.com/cedar-policy/cedar-go v1.9.3
	github.com/go-jose/go-jose/v4 v4.1.9
	github.com/golang-jwt/jwt/v4 v4.5.2
	github.com/google/go-github/v88 v88.0.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.13.0
	github.com/moby/moby/api v1.57.0
	github.com/pires/go-proxyproto v0.16.0
	github.com/ridi-oss/proxy-monster/analyzer v0.0.0-00010101000000-000000000000
	github.com/ridi-oss/proxy-monster/auditmon v0.0.0-00010101000000-000000000000
	github.com/shurcooL/githubv4 v0.0.0-20260209031235-2402fdf4a9ed
	github.com/testcontainers/testcontainers-go v0.45.0
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78
	github.com/zitadel/oidc/v3 v3.52.0
	google.golang.org/grpc v1.85.0
	google.golang.org/protobuf v1.36.12
	tailscale.com v1.104.7
)

require (
	9fans.net/go v0.0.8-0.20250307142834-96bdba94b63f // indirect
	dario.cat/mergo v1.0.2 // indirect
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20261006220739-8c912ac31dd4 // indirect
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/akutz/memconn v0.1.0 // indirect
	github.com/alexbrainman/sspi v0.0.0-20250919150558-7d374ff0d59e // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.21.3 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.25 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.14.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssm v1.77.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.39.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.44.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.53.0 // indirect
	github.com/aws/smithy-go v1.28.9 // indirect
	github.com/axiomhq/hyperloglog v0.2.6 // indirect
	github.com/benbjohnson/immutable v0.4.3 // indirect
	github.com/bradfitz/reco v0.0.0-20260929154613-b883fbd17e3f // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coder/websocket v1.8.15 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v1.0.0-rc.2 // indirect
	github.com/coreos/go-iptables v0.8.0 // indirect
	github.com/cpuguy83/dockercfg v0.3.2 // indirect
	github.com/creachadair/msync v0.10.1 // indirect
	github.com/creack/pty v1.1.24 // indirect
	github.com/dblohm7/wingoes v0.0.0-20260526185140-fb298caac7ca // indirect
	github.com/dgryski/go-metro v0.0.0-20250106013310-edb8663e5e33 // indirect
	github.com/digitalocean/go-smbios v0.0.0-20180907143718-390a4f403a8e // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/djherbis/times v1.6.0 // indirect
	github.com/docker/go-connections v0.8.2 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/ebitengine/purego v0.10.1 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/gaissmai/bart v0.29.0 // indirect
	github.com/go-json-experiment/json v1.27.2 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go4org/hashtriemap v0.0.0-20260925222741-44e5305f85d9 // indirect
	github.com/go4org/plan9netshell v0.0.0-20250324183649-788daa080737 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-querystring v1.2.0 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/nftables v0.3.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/hdevalence/ed25519consensus v0.2.0 // indirect
	github.com/huin/goupnp v1.3.0 // indirect
	github.com/illarion/gonotify/v3 v3.0.2 // indirect
	github.com/insomniacslk/dhcp v0.0.0-20260901064844-234b97448fae // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/jellydator/ttlcache/v3 v3.4.1 // indirect
	github.com/jsimonetti/rtnetlink v1.4.2 // indirect
	github.com/kamstrup/intmap v0.5.2 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/kortschak/wol v0.0.0-20200729010619-da482cc4850a // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20260330125221-c963978e514e // indirect
	github.com/magiconair/properties v1.18.12 // indirect
	github.com/mdlayher/genetlink v1.4.0 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/sdnotify v1.0.0 // indirect
	github.com/mdlayher/socket v0.7.0 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/go-archive v0.3.3 // indirect
	github.com/moby/moby/client v0.6.2 // indirect
	github.com/moby/patternmatcher v0.6.1 // indirect
	github.com/moby/sys/sequential v0.7.0 // indirect
	github.com/moby/sys/user v0.4.1 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/muhlemmer/gu v0.3.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.26 // indirect
	github.com/pkg/sftp v1.13.11 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/ridi-oss/sqlglot-go v0.39.1 // indirect
	github.com/safchain/ethtool v0.7.0 // indirect
	github.com/shirou/gopsutil/v4 v4.26.6 // indirect
	github.com/shurcooL/graphql v0.0.0-20240915155400-7ee5256398cf // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	github.com/tailscale/certstore v0.1.1-0.20260409135935-3638fb84b77d // indirect
	github.com/tailscale/gliderssh v0.3.4-0.20261026144310-31f7cf365d3a // indirect
	github.com/tailscale/go-winio v0.0.0-20231025203758-c4f33415bf55 // indirect
	github.com/tailscale/hujson v0.0.0-20260727124030-b80ff77dac4f // indirect
	github.com/tailscale/netlink v1.1.1-0.20240822203006-4d49adab4de7 // indirect
	github.com/tailscale/peercred v0.0.0-20250107143737-35a0c7bd7edc // indirect
	github.com/tailscale/web-client-prebuilt v0.0.0-20260917222731-e0ed2d0d0fea // indirect
	github.com/tailscale/wf v0.0.0-20240214030419-6fbb0a674ee6 // indirect
	github.com/tailscale/wireguard-go v0.0.0-20261106233718-9e0ab45c16ca // indirect
	github.com/tailscale/xnet v0.0.0-20240729143630-8497ac4dab2e // indirect
	github.com/tklauser/go-sysconf v0.4.0 // indirect
	github.com/tklauser/numcpus v0.12.0 // indirect
	github.com/u-root/u-root v0.16.0 // indirect
	github.com/u-root/uio v0.0.0-20240224005618-d2acac8f3701 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	github.com/zitadel/schema v1.3.2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.70.0 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	go4.org/netipx v0.0.0-20260823151212-3075585bcbeb // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/exp v0.0.0-20260908205506-85c1c2202aba // indirect
	golang.org/x/exp/typeparams v0.0.0-20260811152304-ee035b5b010f // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/oauth2 v0.38.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/term v0.48.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard/windows v1.0.1 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260817212433-ac3dfec99bb1 // indirect
	gvisor.dev/gvisor v0.0.0-20260915211658-a6f909f08a72 // indirect
	honnef.co/go/tools v0.8.1 // indirect
)

// auditmon/canon is the audit hash both writers produce, and analyzer/probe/pb holds the shared proto types;
// resolve both from source so the GOWORK=off image build (control-plane/Dockerfile copies them in) matches
// the workspace.
replace github.com/ridi-oss/proxy-monster/auditmon => ../auditmon

replace github.com/ridi-oss/proxy-monster/analyzer => ../analyzer
