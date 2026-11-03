package workload

import (
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestInferKindFromTheIssuerHost(t *testing.T) {
	for raw, want := range map[string]Kind{
		"https://token.actions.githubusercontent.com":                                  KindGitHubActions,
		"https://a138e0e5-af47-4d31-b269-501bb492d706.tokens.sts.global.api.aws":       KindAWSSTS,
		"https://app.terraform.io":                                                     KindHCPTerraform,
		"https://oidc.eks.ap-northeast-2.amazonaws.com/id/CD3D446872038FB4C348B438766": KindKubernetes,
		"https://tokens.sts.global.api.aws.evil.example":                               KindGeneric,
		"https://gitlab.com": KindGeneric,
	} {
		u, _ := url.Parse(raw)
		if got := inferKind(u); got != want {
			t.Errorf("%s: %s, want %s", raw, got, want)
		}
	}
}

func TestApplyKindsOverridesNamedIssuersOnly(t *testing.T) {
	in := []Issuer{{Name: "tfe", URL: "https://tfe.example.com", Kind: KindGeneric}}
	got, err := ApplyKinds(in, "tfe=hcp-terraform")
	if err != nil || got[0].Kind != KindHCPTerraform || in[0].Kind != KindGeneric {
		t.Fatalf("%+v %v", got, err)
	}
	for _, bad := range []string{"tfe=gitlab", "other=aws-sts", "tfe"} {
		if _, err := ApplyKinds(in, bad); err == nil || !strings.Contains(err.Error(), "PM_WORKLOAD_ISSUER_KINDS") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestFlattenLiftsTheAWSNamespaceAndJoinsNestedKeys(t *testing.T) {
	var raw map[string]any
	dec := json.NewDecoder(strings.NewReader(`{"iss":"x","aud":"a","exp":1,"iat":1,"jti":"j","sub":"arn:aws:iam::1:role/r",
		"https://sts.amazonaws.com/":{"aws_account":"1","ou_path":["o/r/ou-1/","o/r/ou-2/"],"ec2_role_delivery":2,
		"principal_tags":{"kubernetes-namespace":"batch"}},
		"kubernetes.io":{"namespace":"ns","serviceaccount":{"name":"sa"}},"repository":"acme/shop","admin":true}`))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		t.Fatal(err)
	}
	want := Claims{"sub": {"arn:aws:iam::1:role/r"}, "aws_account": {"1"}, "ou_path": {"o/r/ou-1/", "o/r/ou-2/"}, "ec2_role_delivery": {"2"},
		"principal_tags.kubernetes-namespace": {"batch"}, "kubernetes.io.namespace": {"ns"}, "kubernetes.io.serviceaccount.name": {"sa"},
		"repository": {"acme/shop"}, "admin": {"true"}}
	if got := flatten(raw); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
}

func TestBindingMatchesSubjectAndEveryCondition(t *testing.T) {
	b := Binding{Subject: "repo:acme/shop:environment:*", Conditions: map[string][]string{"repository": {"acme/shop"}, "ou_path": {"o/r/ou-2/*"}}}
	claims := Claims{"repository": {"acme/shop"}, "ou_path": {"o/r/ou-1/", "o/r/ou-2/ou-3/"}}
	if !b.matches("repo:acme/shop:environment:prod", claims) {
		t.Error("should match")
	}
	if b.matches("repo:acme/shop:ref:refs/heads/main", claims) {
		t.Error("subject prefix should not match a ref subject")
	}
	if b.matches("repo:acme/shop:environment:prod", Claims{"repository": {"acme/shop"}}) {
		t.Error("a missing claim should not match")
	}
	exact := Binding{Subject: "arn:aws:iam::1:role/r"}
	if exact.matches("arn:aws:iam::1:role/r2", nil) || !exact.matches("arn:aws:iam::1:role/r", nil) {
		t.Error("exact subject")
	}
}
