package github

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var (
	ctx  = context.Background()
	repo = Repo{Owner: "acme", Name: "shop"}
)

func s(v string) *string { return &v }

func ts(v string) *time.Time {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		panic(err)
	}
	return &t
}

func wantKind(t *testing.T, err error, kind Kind) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Kind != kind {
		t.Fatalf("got error %v, want kind %s", err, kind)
	}
	return e
}

func TestAppJWTIsRS256SignedByTheAppKeyWithABackdatedIat(t *testing.T) {
	for _, key := range []string{pkcs8PEM(), pkcs1PEM()} {
		f := newFake(t)
		f.on("GET", "/repos/acme/shop/contents/a.sql", ok("x"))
		if _, err := f.clientAt(t, f.srv.URL, key).ReadFile(ctx, repo, "main", "a.sql"); err != nil {
			t.Fatal(err)
		}
		bearer := strings.TrimPrefix(f.to("GET", "/repos/acme/shop/installation")[0].header.Get("Authorization"), "Bearer ")
		parts := strings.Split(bearer, ".")
		if len(parts) != 3 {
			t.Fatalf("not a JWT: %q", bearer)
		}
		var header map[string]string
		var claims map[string]any
		h, _ := base64.RawURLEncoding.DecodeString(parts[0])
		c, _ := base64.RawURLEncoding.DecodeString(parts[1])
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		_ = json.Unmarshal(h, &header)
		_ = json.Unmarshal(c, &claims)
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
			t.Fatalf("signature: %v", err)
		}
		if header["alg"] != "RS256" || claims["iss"] != appID {
			t.Fatalf("header %v claims %v", header, claims)
		}
		iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
		if iat > time.Now().Unix() || exp <= iat || exp-iat > 600 {
			t.Fatalf("claims %v", claims)
		}
	}
}

func TestAMalformedKeyIsRejectedWithoutEchoingIt(t *testing.T) {
	_, err := NewPEMSigner("-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----")
	if err == nil || err.Error() != "invalid GitHub App private key" {
		t.Fatalf("got %v", err)
	}
}

func TestInstallationTokensAreExchangedOnceReusedAndRenewedBeforeExpiry(t *testing.T) {
	f := newFake(t)
	f.graphql(ok(prResponse(pr(1, prOpts{}))))
	c := f.client(t)
	if _, err := c.ReadPullRequests(ctx, repo, []int{1}); err != nil {
		t.Fatal(err)
	}
	if got := f.to("POST", "/app/installations/42/access_tokens"); len(got) != 1 || !strings.HasPrefix(got[0].header.Get("Authorization"), "Bearer ey") {
		t.Fatalf("exchanges %v", got)
	}
	if got := f.to("POST", "/graphql")[0].header.Get("Authorization"); got != "token ghs_token1" {
		t.Fatalf("got %q", got)
	}
	if _, err := c.ReadPullRequests(ctx, repo, []int{1}); err != nil {
		t.Fatal(err)
	}
	if len(f.to("POST", "/app/installations/42/access_tokens")) != 1 || len(f.to("GET", "/repos/acme/shop/installation")) != 1 {
		t.Fatal("token or installation not reused")
	}
	f.tokenTTL = 30 * time.Second
	c = f.client(t)
	for range 2 {
		if _, err := c.ReadPullRequests(ctx, repo, []int{1}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.ReadPullRequests(ctx, repo, []int{1}); err != nil {
		t.Fatal(err)
	}
	gql := f.to("POST", "/graphql")
	if n := len(f.to("POST", "/app/installations/42/access_tokens")); n != 4 || gql[len(gql)-1].header.Get("Authorization") != "token ghs_token4" {
		t.Fatalf("a token within a minute of expiry must be renewed on each call: %d exchanges", n)
	}
}

func TestA401EvictsTheTokenAndRetriesOnce(t *testing.T) {
	f := newFake(t)
	f.graphql(status(401, `{"message":"Bad credentials"}`), ok(prResponse(pr(1, prOpts{}))))
	got, err := f.client(t).ReadPullRequests(ctx, repo, []int{1})
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v %v", got, err)
	}
	var auths []string
	for _, r := range f.to("POST", "/graphql") {
		auths = append(auths, r.header.Get("Authorization"))
	}
	if !reflect.DeepEqual(auths, []string{"token ghs_token1", "token ghs_token2"}) {
		t.Fatalf("auths %v", auths)
	}

	f.clear()
	f.graphql(status(401, `{"message":"Bad credentials"}`))
	_, err = f.client(t).ReadPullRequests(ctx, repo, []int{1})
	wantKind(t, err, Unauthorized)
	if n := len(f.to("POST", "/graphql")); n != 2 {
		t.Fatalf("calls %d", n)
	}
}

func TestReadPullRequestsReadsEveryPRInOneQueryAndMapsEachField(t *testing.T) {
	f := newFake(t)
	f.graphql(ok(prResponse(pr(1, prOpts{}), merged(2))))
	c := f.client(t)
	prs, err := c.ReadPullRequests(ctx, repo, []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	body := f.to("POST", "/graphql")[0].json(t)
	query := body["query"].(string)
	vars := body["variables"].(map[string]any)
	if vars["owner"] != "acme" || vars["name"] != "shop" || vars["n0"] != 1.0 || vars["n1"] != 2.0 {
		t.Fatalf("variables %v", vars)
	}
	if !strings.Contains(query, "pr0:") || !strings.Contains(query, "pr1:") || strings.Contains(query, "acme") || strings.Contains(query, "shop") {
		t.Fatalf("query %s", query)
	}
	// Each alias's isRequired names its own number; an undeclared $n would make GitHub reject the query.
	if strings.Count(query, "isRequired(pullRequestNumber: $n0)") != 2 || strings.Count(query, "isRequired(pullRequestNumber: $n1)") != 2 ||
		strings.Contains(query, "$n)") {
		t.Fatalf("isRequired variables in %s", query)
	}

	alice := &User{ID: "101", Login: "alice"}
	want := PullRequest{
		Number: 1, Open: true, Draft: true, HeadSHA: "sha1", BaseRef: "main", Author: alice,
		AutoMerge: &AutoMerge{EnabledBy: alice, EnabledAt: ts("2026-10-09T00:10:00Z"), MergeMethod: "SQUASH"},
		Mergeable: "MERGEABLE", MergeState: "BLOCKED", CanBeRebased: true, ReviewDecision: "REVIEW_REQUIRED", UnresolvedThreads: 2,
		Reviews: []Review{
			{ID: "501", Reviewer: &User{"102", "bob"}, State: "APPROVED", SubmittedAt: ts("2026-10-09T00:20:00Z"), URL: "https://github.com/acme/shop/pull/1#r501", Commit: s("sha1")},
			{ID: "502", Reviewer: &User{"103", "carol"}, State: "DISMISSED", SubmittedAt: ts("2026-10-09T00:05:00Z"), URL: "https://github.com/acme/shop/pull/1#r502"},
		},
		Checks: []Check{
			{Name: "build", Required: true, Status: CheckCompleted, Conclusion: s("SUCCESS")},
			{Name: "pm/query executed", Required: true, Status: CheckInProgress, Own: true},
			{Name: "ci/legacy", Status: CheckInProgress},
		},
		Files: []ChangedFile{{"sql/old.sql", "DELETED"}, {"sql/new.sql", "ADDED"}},
		Commits: []CommitAuthor{
			{UserID: s("101"), Email: s("alice@acme.com")},
			{UserID: s("101"), Email: s(" alice@acme.com")},
			{},
			{UserID: s("102"), Email: s("bob@acme.com")},
			{UserID: s("101"), Email: s("merge@acme.com"), Merge: true},
			{Email: s("nouser@acme.com")},
		},
	}
	if got := prs[1]; !reflect.DeepEqual(got, want) {
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(want)
		t.Fatalf("open PR\n got %s\nwant %s", gj, wj)
	}
	closed := prs[2]
	if closed.Open || !closed.Merged || !closed.MergedAt.Equal(*ts("2026-10-08T12:00:00Z")) || *closed.MergeCommit != "merge2" ||
		closed.Author != nil || closed.AutoMerge != nil || closed.Checks != nil {
		t.Fatalf("merged PR %+v", closed)
	}
	if rl := c.RateLimit(); rl == nil || rl.Remaining != 4999 || !rl.ResetAt.Equal(*ts("2026-10-09T01:00:00Z")) {
		t.Fatalf("rate limit %+v", rl)
	}
}

func TestAnEmptyPRListMakesNoCall(t *testing.T) {
	f := newFake(t)
	got, err := f.client(t).ReadPullRequests(ctx, repo, nil)
	if err != nil || len(got) != 0 || len(f.requests) != 0 {
		t.Fatalf("got %v %v, %d requests", got, err, len(f.requests))
	}
}

func TestAPRGitHubReportsAsNotFoundIsAbsentAnyOtherErrorFails(t *testing.T) {
	f := newFake(t)
	f.graphql(ok(`{"data":{"rateLimit":`+rate+`,"repository":{"pr0":`+pr(1, prOpts{})+`,"pr1":null}},
		"errors":[{"type":"NOT_FOUND","path":["repository","pr1"],"message":"Could not resolve"}]}`), ok(prResponse(pr(1, prOpts{}))))
	got, err := f.client(t).ReadPullRequests(ctx, repo, []int{1, 9})
	if err != nil || len(got) != 1 || got[1].Number != 1 {
		t.Fatalf("got %v %v", got, err)
	}

	f.graphql(ok(`{"data":null,"errors":[{"type":"NOT_FOUND","path":["repository"],"message":"Could not resolve"}]}`))
	_, err = f.client(t).ReadPullRequests(ctx, repo, []int{1})
	wantKind(t, err, GraphQL)
}

func TestARollupForACommitOtherThanTheHeadYieldsNoChecks(t *testing.T) {
	f := newFake(t)
	f.graphql(ok(prResponse(pr(1, prOpts{rollupOID: "older"}))))
	got, err := f.client(t).ReadPullRequests(ctx, repo, []int{1})
	if err != nil || got[1].Checks != nil {
		t.Fatalf("got %v %v", got[1].Checks, err)
	}
}

func TestNoRollupYieldsNoChecksAndAnEmptyRollupYieldsNoneRun(t *testing.T) {
	f := newFake(t)
	f.graphql(ok(prResponse(pr(1, prOpts{checks: s("null")}))))
	got, err := f.client(t).ReadPullRequests(ctx, repo, []int{1})
	if err != nil || got[1].Checks != nil {
		t.Fatalf("got %v %v", got[1].Checks, err)
	}
	j, _ := json.Marshal(got[1])
	if !strings.Contains(string(j), `"checks":null`) {
		t.Fatalf("no rollup must reach Kotlin as null: %s", j)
	}

	f.graphql(ok(prResponse(pr(1, prOpts{checks: s("")}))))
	got, err = f.client(t).ReadPullRequests(ctx, repo, []int{1})
	if err != nil || got[1].Checks == nil || len(got[1].Checks) != 0 {
		t.Fatalf("got %v %v", got[1].Checks, err)
	}
	j, _ = json.Marshal(got[1])
	if !strings.Contains(string(j), `"checks":[]`) {
		t.Fatalf("an empty rollup must reach Kotlin as []: %s", j)
	}
}

func TestAPushWhileTheRollupIsPagedYieldsNoChecks(t *testing.T) {
	f := newFake(t)
	f.graphql(
		ok(prResponse(pr(1, prOpts{checksNext: "c1"}))),
		ok(`{"data":{"rateLimit":`+rate+`,"repository":{"pullRequest":{"commits":{"nodes":[{"commit":{"oid":"sha2",
			"statusCheckRollup":{"contexts":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[]}}}}]}}}}}`),
	)
	got, err := f.client(t).ReadPullRequests(ctx, repo, []int{1})
	if err != nil || got[1].Checks != nil || len(f.to("POST", "/graphql")) != 2 {
		t.Fatalf("got %v %v", got[1].Checks, err)
	}
}

const (
	rulesPath  = "/repos/acme/shop/rules/branches/release%2F1"
	branchPath = "/repos/acme/shop/branches/release%2F1"
)

func TestBranchRulesMergeRulesetAndBranchProtectionContextsCachedForFiveMinutes(t *testing.T) {
	f := newFake(t)
	f.on("GET", rulesPath, ok(`[{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"build"},{"context":"lint","integration_id":1}]}},
		{"type":"pull_request","parameters":{}}]`))
	f.on("GET", branchPath, ok(`{"name":"release/1","protection":{"required_status_checks":{"contexts":["ci/legacy"],"checks":[{"context":"ci/legacy"},{"context":"e2e","app_id":5}]}}}`))
	c := f.client(t)
	want := []string{"build", "ci/legacy", "e2e", "lint"}
	check := func(rules, branch int) {
		t.Helper()
		got, err := c.BranchRules(ctx, repo, "release/1")
		if err != nil || !reflect.DeepEqual(got.Contexts, want) {
			t.Fatalf("got %v %v", got, err)
		}
		if len(f.to("GET", rulesPath)) != rules || len(f.to("GET", branchPath)) != branch {
			t.Fatalf("calls %d %d", len(f.to("GET", rulesPath)), len(f.to("GET", branchPath)))
		}
	}
	check(1, 1)
	if f.to("GET", rulesPath)[0].query.Get("per_page") != "100" {
		t.Fatal("per_page")
	}
	f.now = f.now.Add(299 * time.Second)
	check(1, 1)
	f.now = f.now.Add(2 * time.Second)
	check(2, 2)
}

func TestRulesetPagesAreReadUntilAShortPage(t *testing.T) {
	f := newFake(t)
	filler := "[" + strings.TrimSuffix(strings.Repeat(`{"type":"deletion"},`, 100), ",") + "]"
	f.on("GET", rulesPath, func(request) reply {
		return reply{status: 200, body: filler, link: rulesPath + "?per_page=100&page=2"}
	}, ok(`[{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"late"}]}}]`))
	f.on("GET", branchPath, ok(`{"name":"release/1","protection":{"enabled":false}}`))
	got, err := f.client(t).BranchRules(ctx, repo, "release/1")
	if err != nil || !reflect.DeepEqual(got.Contexts, []string{"late"}) {
		t.Fatalf("got %v %v", got, err)
	}
	var pages []string
	for _, r := range f.to("GET", rulesPath) {
		pages = append(pages, r.query.Get("page"))
	}
	if !reflect.DeepEqual(pages, []string{"", "2"}) {
		t.Fatalf("pages %v", pages)
	}
}

func TestBranchRulesReadEveryRuleThatCanBlockAMerge(t *testing.T) {
	f := newFake(t)
	f.on("GET", rulesPath, ok(`[
		{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":true,"required_status_checks":[{"context":"build"}]}},
		{"type":"pull_request","parameters":{"required_review_thread_resolution":true,"allowed_merge_methods":["merge","squash"]}},
		{"type":"required_linear_history"},
		{"type":"pull_request","parameters":{"required_approving_review_count":0,"require_code_owner_review":true}},
		{"type":"deletion"},{"type":"copilot_code_review","parameters":{}},{"type":"update","parameters":{}},
		{"type":"commit_message_pattern","parameters":{"operator":"starts_with","pattern":"x"}},
		{"type":"merge_queue","parameters":{}},{"type":"code_quality","parameters":{}},{"type":"merge_queue","parameters":{}}]`))
	f.on("GET", branchPath, ok(`{"name":"release/1","protection":{"enabled":true}}`))
	got, err := f.client(t).BranchRules(ctx, repo, "release/1")
	want := BranchRules{
		Contexts: []string{"build"}, Strict: true, ThreadResolution: true, MergeMethods: []string{"squash"},
		Unchecked: []string{"branch_protection", "code_quality", "commit_message_pattern", "merge_queue", "pull_request", "update"},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestMergeMethodRulesThatAllowNoMethodAreUnchecked(t *testing.T) {
	f := newFake(t)
	f.on("GET", rulesPath, ok(`[{"type":"pull_request","parameters":{"allowed_merge_methods":["merge"]}},{"type":"required_linear_history"}]`))
	f.on("GET", branchPath, ok(`{"name":"release/1","protection":{"enabled":false}}`))
	got, err := f.client(t).BranchRules(ctx, repo, "release/1")
	if err != nil || !reflect.DeepEqual(got.Unchecked, []string{"required_linear_history"}) {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestAMissingBranchHasNoRulesAndAnyOtherErrorIsNotCached(t *testing.T) {
	f := newFake(t)
	f.on("GET", rulesPath, status(404, `{"message":"Not Found"}`))
	f.on("GET", branchPath, status(404, `{"message":"Not Found"}`))
	got, err := f.client(t).BranchRules(ctx, repo, "release/1")
	if err != nil || !reflect.DeepEqual(got, BranchRules{Contexts: []string{}}) {
		t.Fatalf("got %v %v", got, err)
	}

	c := f.client(t)
	f.on("GET", branchPath, status(500, `{"message":"boom"}`), ok(`{"name":"release/1","protection":{"required_status_checks":{"contexts":["build"]}}}`))
	_, err = c.BranchRules(ctx, repo, "release/1")
	wantKind(t, err, Server)
	got, err = c.BranchRules(ctx, repo, "release/1")
	if err != nil || !reflect.DeepEqual(got.Contexts, []string{"build"}) {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestAFurtherPageOfFilesIsFetchedUntilComplete(t *testing.T) {
	f := newFake(t)
	f.graphql(
		ok(prResponse(pr(1, prOpts{filesNext: "c1"}))),
		ok(`{"data":{"rateLimit":`+rate+`,"repository":{"pullRequest":{"files":{"pageInfo":{"hasNextPage":false,"endCursor":null},
			"nodes":[{"path":"sql/more.sql","changeType":"MODIFIED"}]}}}}}`),
	)
	got, err := f.client(t).ReadPullRequests(ctx, repo, []int{1})
	if err != nil {
		t.Fatal(err)
	}
	want := []ChangedFile{{"sql/old.sql", "DELETED"}, {"sql/new.sql", "ADDED"}, {"sql/more.sql", "MODIFIED"}}
	if !reflect.DeepEqual(got[1].Files, want) {
		t.Fatalf("files %v", got[1].Files)
	}
	page := f.to("POST", "/graphql")[1].json(t)
	if page["variables"].(map[string]any)["after"] != "c1" || !strings.Contains(page["query"].(string), "files(first: 100, after: $after)") {
		t.Fatalf("page %v", page)
	}
}

func TestAFurtherPageOfReviewThreadsIsFetchedUntilComplete(t *testing.T) {
	f := newFake(t)
	f.graphql(
		ok(prResponse(pr(1, prOpts{threadsNext: "t1"}))),
		ok(`{"data":{"rateLimit":`+rate+`,"repository":{"pullRequest":{"reviewThreads":{"pageInfo":{"hasNextPage":false,"endCursor":null},
			"nodes":[{"isResolved":true},{"isResolved":false}]}}}}}`),
	)
	got, err := f.client(t).ReadPullRequests(ctx, repo, []int{1})
	if err != nil || got[1].UnresolvedThreads != 3 {
		t.Fatalf("got %v %v", got[1].UnresolvedThreads, err)
	}
	page := f.to("POST", "/graphql")[1].json(t)
	if page["variables"].(map[string]any)["after"] != "t1" || !strings.Contains(page["query"].(string), "reviewThreads(first: 100, after: $after)") {
		t.Fatalf("page %v", page)
	}
}

func TestCompareCommitsMapsEachComparisonStatusAndFailsOnAnyOther(t *testing.T) {
	f := newFake(t)
	path := "/repos/acme/shop/compare/aaa...bbb"
	for status, want := range map[string]Relation{"ahead": Ahead, "identical": Identical, "behind": Behind, "diverged": Diverged} {
		f.on("GET", path, ok(`{"status":"`+status+`","ahead_by":1,"behind_by":0}`))
		if got, err := f.client(t).CompareCommits(ctx, repo, "aaa", "bbb"); err != nil || got != want {
			t.Fatalf("%s: got %v %v", status, got, err)
		}
	}
	f.on("GET", path, ok(`{"status":"unknown"}`))
	if _, err := f.client(t).CompareCommits(ctx, repo, "aaa", "bbb"); err == nil {
		t.Fatal("an unknown status must fail")
	}
	f.on("GET", path, status(404, `{"message":"Not Found"}`))
	_, err := f.client(t).CompareCommits(ctx, repo, "aaa", "bbb")
	wantKind(t, err, NotFound)
}

func TestReadFileAsksForRawContentAtAnEncodedPathAndRef(t *testing.T) {
	f := newFake(t)
	path := "/repos/acme/shop/contents/sql/a%20b.sql"
	f.on("GET", path, ok("\x01\x02\x03"))
	got, err := f.client(t).ReadFile(ctx, repo, "feature/x y", "sql/a b.sql")
	if err != nil || string(got) != "\x01\x02\x03" {
		t.Fatalf("got %q %v", got, err)
	}
	r := f.to("GET", path)[0]
	if r.header.Get("Accept") != "application/vnd.github.raw+json" || r.query.Get("ref") != "feature/x y" ||
		r.header.Get("X-GitHub-Api-Version") != "2022-11-28" || r.header.Get("User-Agent") != "proxy-monster" {
		t.Fatalf("request %+v", r)
	}
}

func TestPostCheckCreatesARunThenUpdatesThisAppsRun(t *testing.T) {
	f := newFake(t)
	list := "/repos/acme/shop/commits/sha1/check-runs"
	f.on("GET", list, ok(`{"total_count":0,"check_runs":[]}`), ok(`{"total_count":2,"check_runs":[{"id":7,"app":{"id":999}},{"id":8,"app":{"id":`+appID+`}}]}`))
	f.on("POST", "/repos/acme/shop/check-runs", status(201, `{"id":8}`))
	f.on("PATCH", "/repos/acme/shop/check-runs/8", ok(`{"id":8}`))
	c := f.client(t)

	if err := c.PostCheck(ctx, repo, "sha1", "proxy-monster", CheckInProgress, nil, "Running", "Checking SQL"); err != nil {
		t.Fatal(err)
	}
	q := f.to("GET", list)[0].query
	if q.Get("check_name") != "proxy-monster" || q.Get("filter") != "latest" || q.Get("app_id") != appID {
		t.Fatalf("lookup %v", q)
	}
	created := f.to("POST", "/repos/acme/shop/check-runs")[0].json(t)
	want := map[string]any{"name": "proxy-monster", "head_sha": "sha1", "status": "in_progress", "output": map[string]any{"title": "Running", "summary": "Checking SQL"}}
	if !reflect.DeepEqual(created, want) {
		t.Fatalf("created %v", created)
	}

	if err := c.PostCheck(ctx, repo, "sha1", "proxy-monster", CheckCompleted, s("FAILURE"), "Denied", "No grant"); err != nil {
		t.Fatal(err)
	}
	patch := f.to("PATCH", "/repos/acme/shop/check-runs/8")[0].json(t)
	if len(f.to("POST", "/repos/acme/shop/check-runs")) != 1 || patch["status"] != "completed" || patch["conclusion"] != "failure" || len(f.to("PATCH", "/repos/acme/shop/check-runs/7")) != 0 {
		t.Fatalf("patch %v", patch)
	}
	if err := c.PostCheck(ctx, repo, "sha1", "proxy-monster", CheckCompleted, s("SKIPPED"), "No SQL", ""); err != nil {
		t.Fatal(err)
	}
	patches := f.to("PATCH", "/repos/acme/shop/check-runs/8")
	if patches[len(patches)-1].json(t)["conclusion"] != "skipped" {
		t.Fatal("skipped")
	}
	if err := c.PostCheck(ctx, repo, "sha1", "proxy-monster", CheckCompleted, nil, "t", "s"); err == nil {
		t.Fatal("a completed check without a conclusion must fail")
	}
}

func TestARunFromAnotherAppIsNotUpdated(t *testing.T) {
	f := newFake(t)
	f.on("GET", "/repos/acme/shop/commits/sha1/check-runs", ok(`{"total_count":1,"check_runs":[{"id":7,"app":{"id":999}}]}`))
	f.on("POST", "/repos/acme/shop/check-runs", status(201, `{"id":9}`))
	if err := f.client(t).PostCheck(ctx, repo, "sha1", "proxy-monster", CheckQueued, nil, "t", "s"); err != nil {
		t.Fatal(err)
	}
	if len(f.to("POST", "/repos/acme/shop/check-runs")) != 1 || len(f.to("PATCH", "/repos/acme/shop/check-runs/7")) != 0 {
		t.Fatal("another app's run was touched")
	}
}

func TestDismissReviewPUTsADismissal(t *testing.T) {
	f := newFake(t)
	path := "/repos/acme/shop/pulls/1/reviews/501/dismissals"
	f.on("PUT", path, ok("{}"))
	if err := f.client(t).DismissReview(ctx, repo, 1, "501", "SQL changed after approval"); err != nil {
		t.Fatal(err)
	}
	if got := f.to("PUT", path)[0].json(t); !reflect.DeepEqual(got, map[string]any{"message": "SQL changed after approval"}) {
		t.Fatalf("body %v", got)
	}
}

func TestPostCommentPostsTheBodyAsIs(t *testing.T) {
	f := newFake(t)
	f.on("POST", "/repos/acme/shop/issues/1/comments", status(201, "{}"))
	if err := f.client(t).PostComment(ctx, repo, 1, "hello"); err != nil {
		t.Fatal(err)
	}
	if got := f.to("POST", "/repos/acme/shop/issues/1/comments")[0].json(t); got["body"] != "hello" {
		t.Fatalf("body %v", got)
	}
}

func TestUpsertCommentCreatesAMarkedCommentWhenNoneExists(t *testing.T) {
	f := newFake(t)
	f.on("GET", "/repos/acme/shop/issues/1/comments", ok(`[{"id":1,"body":"<!-- proxy-monster:status -->\nforged","performed_via_github_app":null}]`))
	f.on("POST", "/repos/acme/shop/issues/1/comments", status(201, "{}"))
	if err := f.client(t).UpsertComment(ctx, repo, 1, "status", "all good"); err != nil {
		t.Fatal(err)
	}
	if got := f.to("POST", "/repos/acme/shop/issues/1/comments")[0].json(t)["body"]; got != "<!-- proxy-monster:status -->\nall good" {
		t.Fatalf("body %q", got)
	}
	if len(f.to("PATCH", "/repos/acme/shop/issues/comments/1")) != 0 {
		t.Fatal("a forged comment was edited")
	}
}

func TestUpsertCommentEditsTheAppsMarkedCommentOnALaterPage(t *testing.T) {
	f := newFake(t)
	var first []string
	for i := 1; i <= 100; i++ {
		first = append(first, fmt.Sprintf(`{"id":%d,"body":"chatter","performed_via_github_app":{"id":%s}}`, i, appID))
	}
	f.on("GET", "/repos/acme/shop/issues/1/comments", ok("["+strings.Join(first, ",")+"]"),
		ok(`[{"id":500,"body":"<!-- proxy-monster:status -->\nold","performed_via_github_app":{"id":`+appID+`}}]`))
	f.on("PATCH", "/repos/acme/shop/issues/comments/500", ok("{}"))
	if err := f.client(t).UpsertComment(ctx, repo, 1, "status", "new"); err != nil {
		t.Fatal(err)
	}
	gets := f.to("GET", "/repos/acme/shop/issues/1/comments")
	if len(gets) != 2 || gets[0].query.Get("page") != "1" || gets[1].query.Get("page") != "2" || gets[0].query.Get("per_page") != "100" {
		t.Fatalf("pages %v", gets)
	}
	if got := f.to("PATCH", "/repos/acme/shop/issues/comments/500")[0].json(t)["body"]; got != "<!-- proxy-monster:status -->\nnew" {
		t.Fatalf("body %q", got)
	}
	if len(f.to("POST", "/repos/acme/shop/issues/1/comments")) != 0 {
		t.Fatal("posted a new comment")
	}
}

func identity(nameID *string, provider bool, emails []string) responder {
	return func(r request) reply {
		var body struct {
			Query string `json:"query"`
		}
		_ = json.Unmarshal(r.body, &body)
		q := body.Query
		switch {
		case strings.Contains(q, "samlIdentityProvider"):
			nodes := "[]"
			if nameID != nil {
				nodes = `[{"samlIdentity":{"nameId":"` + *nameID + `"}}]`
			}
			idp := "null"
			if provider {
				idp = `{"externalIdentities":{"nodes":` + nodes + `}}`
			}
			return reply{status: 200, body: `{"data":{"rateLimit":` + rate + `,"organization":{"samlIdentityProvider":` + idp + `}}}`, header: nil}
		case strings.Contains(q, "organizationVerifiedDomainEmails"):
			e, _ := json.Marshal(emails)
			return reply{status: 200, body: `{"data":{"rateLimit":` + rate + `,"user":{"organizationVerifiedDomainEmails":` + string(e) + `}}}`, header: nil}
		}
		return reply{status: 500, body: `{"message":"unexpected query"}`, header: nil}
	}
}

func TestExternalIdentityReadsTheSAMLNameID(t *testing.T) {
	f := newFake(t)
	f.graphql(identity(s("alice@example.com"), true, nil))
	c := f.client(t)
	got, err := c.ExternalIdentity(ctx, "acme", "alice")
	if err != nil || got == nil || *got != "alice@example.com" {
		t.Fatalf("got %v %v", got, err)
	}
	vars := f.to("POST", "/graphql")[0].json(t)["variables"].(map[string]any)
	if vars["org"] != "acme" || vars["login"] != "alice" || len(f.to("GET", "/orgs/acme/installation")) != 1 || c.RateLimit() == nil {
		t.Fatalf("variables %v", vars)
	}

	f.graphql(identity(nil, false, nil))
	if got, err := f.client(t).ExternalIdentity(ctx, "acme", "alice"); err != nil || got != nil {
		t.Fatalf("no provider: got %v %v", got, err)
	}
}

func TestAnyGraphQLErrorFailsALookup(t *testing.T) {
	f := newFake(t)
	f.graphql(ok(`{"data":{"organization":null},"errors":[{"type":"FORBIDDEN","path":["organization"],"message":"no"}]}`))
	_, err := f.client(t).ExternalIdentity(ctx, "acme", "alice")
	if e := wantKind(t, err, GraphQL); e.Message != "POST /graphql -> GraphQL errors: no" {
		t.Fatalf("message %q", e.Message)
	}
	f.graphql(ok(`{"data":{"user":null},"errors":[{"type":"NOT_FOUND","path":["user"],"message":"no"}]}`))
	_, err = f.client(t).VerifiedEmails(ctx, "acme", "alice")
	wantKind(t, err, GraphQL)
}

func TestVerifiedEmailsReadsTheOrgDomainEmails(t *testing.T) {
	f := newFake(t)
	f.graphql(identity(nil, false, []string{"a@example.com", "b@example.com"}))
	got, err := f.client(t).VerifiedEmails(ctx, "acme", "alice")
	if err != nil || !reflect.DeepEqual(got, []string{"a@example.com", "b@example.com"}) {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestAServerErrorDuringResolutionFails(t *testing.T) {
	f := newFake(t)
	f.graphql(status(500, `{"message":"boom"}`))
	_, err := f.client(t).ExternalIdentity(ctx, "acme", "alice")
	if e := wantKind(t, err, Server); e.Status != 500 {
		t.Fatalf("status %d", e.Status)
	}
}

func TestHTTPErrorsMapToKindsThatCarryNoCredential(t *testing.T) {
	f := newFake(t)
	f.on("GET", "/repos/acme/shop/contents/missing.sql", status(404, `{"message":"Not Found"}`))
	_, err := f.client(t).ReadFile(ctx, repo, "main", "missing.sql")
	notFound := wantKind(t, err, NotFound)
	if notFound.Message != "GET /repos/acme/shop/contents/missing.sql -> 404: Not Found" {
		t.Fatalf("message %q", notFound.Message)
	}

	f.on("GET", "/repos/acme/shop/contents/a.sql", func(request) reply {
		return reply{status: 403, body: `{"message":"API rate limit exceeded"}`, header: map[string]string{"X-Ratelimit-Remaining": "0", "X-Ratelimit-Reset": "1791507600"}}
	})
	_, err = f.client(t).ReadFile(ctx, repo, "main", "a.sql")
	limited := wantKind(t, err, RateLimited)
	if limited.ResetAt == nil || limited.ResetAt.Unix() != 1791507600 {
		t.Fatalf("reset %v", limited.ResetAt)
	}

	f.on("GET", "/repos/acme/shop/contents/b.sql", status(403, `{"message":"Resource not accessible"}`))
	_, err = f.client(t).ReadFile(ctx, repo, "main", "b.sql")
	wantKind(t, err, Forbidden)

	f.mu.Lock()
	var creds []string
	for _, r := range f.requests {
		if _, a, ok := strings.Cut(r.header.Get("Authorization"), " "); ok {
			creds = append(creds, a)
		}
	}
	f.mu.Unlock()
	if len(creds) == 0 {
		t.Fatal("no credentials seen")
	}
	for _, e := range []*Error{notFound, limited} {
		for _, c := range creds {
			if strings.Contains(e.Message, c) {
				t.Fatalf("%q carries a credential", e.Message)
			}
		}
	}
}

func TestAGHESAPIURLSendsGraphQLToAPIGraphQL(t *testing.T) {
	f := newFake(t)
	f.on("POST", "/api/graphql", ok(prResponse(pr(1, prOpts{}))))
	f.on("GET", "/api/v3/repos/acme/shop/installation", ok(`{"id":42}`))
	f.on("POST", "/api/v3/app/installations/42/access_tokens", ok(`{"token":"ghs_ghes","expires_at":"`+f.now.Add(time.Hour).Format(time.RFC3339)+`"}`))
	if _, err := f.clientAt(t, f.srv.URL+"/api/v3", pkcs8PEM()).ReadPullRequests(ctx, repo, []int{1}); err != nil {
		t.Fatal(err)
	}
	if len(f.to("POST", "/api/graphql")) != 1 {
		t.Fatal("GraphQL did not go to /api/graphql")
	}
}

func TestTruncateKeepsWholeCharacters(t *testing.T) {
	got := truncate(strings.Repeat("가", 250))
	if !utf8.ValidString(got) || utf8.RuneCountInString(got) != messageLimit {
		t.Fatalf("got %d runes, valid=%t", utf8.RuneCountInString(got), utf8.ValidString(got))
	}
}

func TestARollupIsPagedUntilComplete(t *testing.T) {
	f := newFake(t)
	f.graphql(
		ok(prResponse(pr(1, prOpts{checksNext: "c1"}))),
		ok(`{"data":{"rateLimit":`+rate+`,"repository":{"pullRequest":{"commits":{"nodes":[{"commit":{"oid":"sha1",
			"statusCheckRollup":{"contexts":{"pageInfo":{"hasNextPage":false,"endCursor":null},
			"nodes":[{"__typename":"CheckRun","name":"e2e","status":"COMPLETED","conclusion":"TIMED_OUT","isRequired":true}]}}}}]}}}}}`),
	)
	got, err := f.client(t).ReadPullRequests(ctx, repo, []int{1})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range got[1].Checks {
		names = append(names, c.Name+"="+*orEmpty(c.Conclusion))
	}
	if strings.Join(names, " ") != "build=SUCCESS pm/query executed= ci/legacy= e2e=TIMED_OUT" {
		t.Fatalf("checks %v", names)
	}
	page := f.to("POST", "/graphql")[1].json(t)
	if page["variables"].(map[string]any)["after"] != "c1" || !strings.Contains(page["query"].(string), "contexts(first: 100, after: $after)") {
		t.Fatalf("page %v", page)
	}
}

func orEmpty(s *string) *string {
	if s == nil {
		return new("")
	}
	return s
}

func TestAnUnreadableAnswerFailsTheBatchRatherThanDropAPR(t *testing.T) {
	f := newFake(t)
	first := pr(1, prOpts{})
	first = first[:len(first)-1] + `,"surprise":1}`
	f.graphql(ok(prResponse(first, pr(2, prOpts{}))))
	if got, err := f.client(t).ReadPullRequests(ctx, repo, []int{1, 2}); err == nil {
		t.Fatalf("got %v, want an error", got)
	}
}

func TestARenamedBranchRedirectIsFollowed(t *testing.T) {
	f := newFake(t)
	f.on("GET", rulesPath, ok(`[]`))
	f.on("GET", branchPath, func(request) reply {
		return reply{status: 301, body: `{"message":"Moved Permanently"}`, header: map[string]string{"Location": f.srv.URL + "/repos/acme/shop/branches/release%2F2"}}
	})
	f.on("GET", "/repos/acme/shop/branches/release%2F2", ok(`{"name":"release/2","protection":{"required_status_checks":{"contexts":["build"]}}}`))
	got, err := f.client(t).BranchRules(ctx, repo, "release/1")
	if err != nil || !reflect.DeepEqual(got.Contexts, []string{"build"}) {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestAnErrorInsideAPresentPRFailsTheRead(t *testing.T) {
	f := newFake(t)
	errAt := `"errors":[{"type":"SERVICE_UNAVAILABLE","path":["repository","pr0","reviews"],"message":"timeout"}]`
	nullReviews := `{"data":{"rateLimit":` + rate + `,"repository":{"pr0":` + withoutReviews(pr(1, prOpts{})) + `}},` + errAt + `}`
	f.graphql(ok(nullReviews))
	if got, err := f.client(t).ReadPullRequests(ctx, repo, []int{1}); err == nil {
		t.Fatalf("got %v, want an error", got)
	}

	f.clear()
	missing := `{"data":{"rateLimit":` + rate + `,"repository":{"pr0":` + pr(1, prOpts{}) + `,"pr1":null}},"errors":[{"type":"NOT_FOUND","path":["repository","pr1"],"message":"no"}]}`
	f.graphql(ok(missing), ok(prResponse(pr(1, prOpts{}))))
	got, err := f.client(t).ReadPullRequests(ctx, repo, []int{1, 9})
	if err != nil || len(got) != 1 || len(f.to("POST", "/graphql")) != 2 {
		t.Fatalf("a missing pull request must drop out on a second read: %v %v", got, err)
	}
	vars := f.to("POST", "/graphql")[1].json(t)["variables"].(map[string]any)
	if vars["n0"] != 1.0 || vars["n1"] != nil {
		t.Fatalf("second read variables %v", vars)
	}
}

func withoutReviews(node string) string {
	i := strings.Index(node, `"reviews":{`)
	j := strings.Index(node, `"files":{`)
	return node[:i] + `"reviews":null,` + node[j:]
}
