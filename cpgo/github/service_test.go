package github

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/ridi-oss/proxy-monster/cpgo/gobridge"
	pb "github.com/ridi-oss/proxy-monster/cpgo/gobridge/pb"
)

// bridge serves f's client as the GitHubSource service over a real loopback connection.
func bridge(t *testing.T, f *fakeGitHub) (pb.GitHubSourceClient, context.Context) {
	t.Helper()
	s, err := gobridge.Listen(0, "secret")
	if err != nil {
		t.Fatal(err)
	}
	pb.RegisterGitHubSourceServer(s.GRPC(), NewService(f.client(t)))
	s.Serve(make(chan error, 1))
	t.Cleanup(func() { _ = s.Close() })
	cc, err := grpc.NewClient(strings.TrimPrefix(s.Env(), gobridge.AddrEnv+"="), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return pb.NewGitHubSourceClient(cc), metadata.AppendToOutgoingContext(context.Background(), gobridge.TokenKey, "secret")
}

var pbRepo = &pb.Repo{Owner: "acme", Name: "shop"}

func TestTheServiceKeepsAMissingRollupApartFromNoChecks(t *testing.T) {
	f := newFake(t)
	f.graphql(ok(prResponse(pr(1, prOpts{checks: s("null")}), pr(2, prOpts{checks: s("")}))))
	gs, ctx := bridge(t, f)
	out, err := gs.ReadPullRequests(ctx, &pb.ReadPullRequestsRequest{Repo: pbRepo, Numbers: []int32{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	if out.PullRequests[1].Checks != nil || out.PullRequests[2].Checks == nil || len(out.PullRequests[2].Checks.Checks) != 0 {
		t.Fatalf("checks %v / %v", out.PullRequests[1].Checks, out.PullRequests[2].Checks)
	}
	if out.RateLimit.GetRemaining() != 4999 || out.PullRequests[1].GetAutoMerge().GetEnabledBy().GetLogin() != "alice" {
		t.Fatalf("rate limit %v, auto-merge %v", out.RateLimit, out.PullRequests[1].GetAutoMerge())
	}
	r := out.PullRequests[1].Reviews[0]
	if r.State != pb.ReviewState_APPROVED || r.GetCommit() != "sha1" || out.PullRequests[1].Reviews[1].Commit != nil {
		t.Fatalf("reviews %v", out.PullRequests[1].Reviews)
	}
}

func TestTheServiceAnswersAGitHubFailureWithItsKind(t *testing.T) {
	f := newFake(t)
	f.on("GET", "/repos/acme/shop/compare/a...b", status(404, `{"message":"Not Found"}`))
	gs, ctx := bridge(t, f)
	_, err := gs.CompareCommits(ctx, &pb.CompareCommitsRequest{Repo: pbRepo, Base: "a", Head: "b"})
	st := grpcstatus.Convert(err)
	var detail *pb.GitHubError
	for _, d := range st.Details() {
		if e, ok := d.(*pb.GitHubError); ok {
			detail = e
		}
	}
	if detail == nil || detail.Kind != pb.GitHubError_NOT_FOUND || !strings.Contains(detail.Message, "-> 404") {
		t.Fatalf("status %v details %v", st, st.Details())
	}

	f.on("GET", "/repos/acme/shop/compare/a...b", ok(`{"status":"sideways"}`))
	_, err = gs.CompareCommits(ctx, &pb.CompareCommitsRequest{Repo: pbRepo, Base: "a", Head: "b"})
	if st := grpcstatus.Convert(err); st.Code() != codes.Internal || len(st.Details()) != 0 {
		t.Fatalf("a failure other than GitHub's: %v", st)
	}
}

func TestTheServicePostsOrUpsertsAComment(t *testing.T) {
	f := newFake(t)
	f.on("POST", "/repos/acme/shop/issues/1/comments", status(201, "{}"))
	f.on("GET", "/repos/acme/shop/issues/1/comments", ok("[]"))
	gs, ctx := bridge(t, f)
	if _, err := gs.PostComment(ctx, &pb.PostCommentRequest{Repo: pbRepo, Pr: 1, Body: "hi"}); err != nil {
		t.Fatal(err)
	}
	if _, err := gs.PostComment(ctx, &pb.PostCommentRequest{Repo: pbRepo, Pr: 1, Marker: new("status"), Body: "ok"}); err != nil {
		t.Fatal(err)
	}
	posts := f.to("POST", "/repos/acme/shop/issues/1/comments")
	if len(posts) != 2 || posts[0].json(t)["body"] != "hi" || posts[1].json(t)["body"] != "<!-- proxy-monster:status -->\nok" {
		t.Fatalf("posts %v", posts)
	}
}

func TestTheServiceMapsCheckStatusAndConclusion(t *testing.T) {
	f := newFake(t)
	f.on("GET", "/repos/acme/shop/commits/sha1/check-runs", ok(`{"total_count":0,"check_runs":[]}`))
	f.on("POST", "/repos/acme/shop/check-runs", status(201, `{"id":8}`))
	gs, ctx := bridge(t, f)
	_, err := gs.PostCheck(ctx, &pb.PostCheckRequest{Repo: pbRepo, HeadSha: "sha1", Name: "query executed",
		Status: pb.CheckStatus_COMPLETED, Conclusion: pb.CheckConclusion_SKIPPED, Title: "No SQL"})
	if err != nil {
		t.Fatal(err)
	}
	body := f.to("POST", "/repos/acme/shop/check-runs")[0].json(t)
	if body["status"] != "completed" || body["conclusion"] != "skipped" {
		t.Fatalf("body %v", body)
	}
}

func TestTheServiceMapsEveryPullRequestField(t *testing.T) {
	f := newFake(t)
	f.graphql(ok(prResponse(merged(2), pr(1, prOpts{}))))
	f.on("GET", "/repos/acme/shop/compare/a...b", ok(`{"status":"ahead"}`))
	gs, ctx := bridge(t, f)
	out, err := gs.ReadPullRequests(ctx, &pb.ReadPullRequestsRequest{Repo: pbRepo, Numbers: []int32{2, 1}})
	if err != nil {
		t.Fatal(err)
	}
	m := out.PullRequests[2]
	if !m.Merged || m.Open || m.GetMergedAt().AsTime().Format(time.RFC3339) != "2026-10-08T12:00:00Z" || m.GetMergeCommit() != "merge2" {
		t.Fatalf("merged %v", m)
	}
	o := out.PullRequests[1]
	c := o.Checks.Checks
	if len(c) != 3 || c[0].Status != pb.CheckStatus_COMPLETED || c[0].Conclusion != pb.CheckConclusion_SUCCESS || !c[0].Required || c[0].Own ||
		!c[1].Own || c[2].Status != pb.CheckStatus_IN_PROGRESS || c[2].Conclusion != pb.CheckConclusion_CHECK_CONCLUSION_UNSPECIFIED {
		t.Fatalf("checks %v", c)
	}
	if o.Files[0].Change != pb.FileChange_DELETED || o.Files[1].Change != pb.FileChange_ADDED || o.Reviews[1].State != pb.ReviewState_DISMISSED {
		t.Fatalf("files %v reviews %v", o.Files, o.Reviews)
	}
	if a := o.Commits; len(a) != 6 || a[0].GetUserId() != "101" || a[0].GetEmail() != "alice@acme.com" || a[2].UserId != nil || a[2].Email != nil || !a[4].Merge {
		t.Fatalf("commits %v", a)
	}
	rel, err := gs.CompareCommits(ctx, &pb.CompareCommitsRequest{Repo: pbRepo, Base: "a", Head: "b"})
	if err != nil || rel.Relation != pb.CommitRelation_AHEAD {
		t.Fatalf("compare %v %v", rel, err)
	}
}
