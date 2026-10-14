package github

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/shurcooL/githubv4"
)

var (
	reviewStates     = []string{"APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED", "PENDING"}
	checkConclusions = []string{"SUCCESS", "NEUTRAL", "SKIPPED", "FAILURE", "CANCELLED", "TIMED_OUT", "ACTION_REQUIRED", "STALE"}
	fileChanges      = []string{"ADDED", "DELETED", "MODIFIED", "RENAMED", "COPIED", "CHANGED"}
)

type pageInfo struct {
	HasNextPage bool
	EndCursor   *string
}

type userRef struct {
	Login *string
	User  struct {
		DatabaseID *int64 `graphql:"databaseId"`
	} `graphql:"... on User"`
}

type actor struct {
	Login *string
	User  struct {
		DatabaseID *int64 `graphql:"databaseId"`
	} `graphql:"... on User"`
	Bot struct {
		DatabaseID *int64 `graphql:"databaseId"`
	} `graphql:"... on Bot"`
}

type reviewNode struct {
	DatabaseID  *int64 `graphql:"databaseId"`
	State       string
	SubmittedAt *time.Time
	URL         *string `graphql:"url"`
	Commit      *struct {
		OID string `graphql:"oid"`
	}
	Author *userRef
}

type reviewsPage struct {
	PageInfo pageInfo
	Nodes    []reviewNode
}

type fileNode struct {
	Path       *string
	ChangeType string
}

type filesPage struct {
	PageInfo pageInfo
	Nodes    []fileNode
}

// $n is the pull request's number variable; the batch query renames it per alias.
type contextNode struct {
	Typename string `graphql:"__typename"`
	CheckRun struct {
		Name       string
		Status     string
		Conclusion *string
		IsRequired *bool `graphql:"isRequired(pullRequestNumber: $n)"`
	} `graphql:"... on CheckRun"`
	StatusContext struct {
		Context    string
		State      string
		IsRequired *bool `graphql:"isRequired(pullRequestNumber: $n)"`
	} `graphql:"... on StatusContext"`
}

type contextsPage struct {
	PageInfo pageInfo
	Nodes    []contextNode
}

type headCommit struct {
	Nodes []struct {
		Commit *struct {
			OID               string `graphql:"oid"`
			StatusCheckRollup *struct {
				Contexts contextsPage `graphql:"contexts(first: 100)"`
			}
		}
	}
}

type prNode struct {
	State       string
	Merged      *bool
	MergedAt    *time.Time
	MergeCommit *struct {
		OID string `graphql:"oid"`
	}
	HeadRefOID       *string `graphql:"headRefOid"`
	BaseRefName      *string
	Author           *actor
	AutoMergeRequest *struct {
		EnabledAt *time.Time
		EnabledBy *userRef
	}
	Reviews *reviewsPage `graphql:"reviews(first: 100)"`
	Files   *filesPage   `graphql:"files(first: 100)"`
	Commits headCommit   `graphql:"commits(last: 1)"`
	Authors struct {
		Nodes []struct {
			Commit *struct {
				Parents struct{ TotalCount int }
				Author  *struct {
					Email *string
					User  *struct {
						DatabaseID *int64 `graphql:"databaseId"`
					}
				}
			}
		}
	} `graphql:"authors: commits(first: 100)"`
}

// headRollup is the last commit's rollup; it is the head's only when nothing was pushed mid-read.
func (h headCommit) headRollup() (oid string, contexts *contextsPage, ok bool) {
	if len(h.Nodes) == 0 || h.Nodes[0].Commit == nil {
		return "", nil, false
	}
	c := h.Nodes[0].Commit
	if c.StatusCheckRollup != nil {
		contexts = &c.StatusCheckRollup.Contexts
	}
	return c.OID, contexts, true
}

var prNodeType = reflect.TypeFor[prNode]()

// retag is t with "$n" in every graphql tag replaced by variable.
func retag(t reflect.Type, variable string) reflect.Type {
	switch t.Kind() {
	case reflect.Pointer:
		return reflect.PointerTo(retag(t.Elem(), variable))
	case reflect.Slice:
		return reflect.SliceOf(retag(t.Elem(), variable))
	case reflect.Struct:
		if t.PkgPath() != "" && t.PkgPath() != prNodeType.PkgPath() {
			return t
		}
		fields := make([]reflect.StructField, t.NumField())
		for i := range fields {
			f := t.Field(i)
			if tag, ok := f.Tag.Lookup("graphql"); ok {
				f.Tag = reflect.StructTag(`graphql:"` + strings.ReplaceAll(tag, "$n)", variable+")") + `"`)
			}
			f.Type = retag(f.Type, variable)
			fields[i] = f
		}
		return reflect.StructOf(fields)
	}
	return t
}

// ReadPullRequests reads the numbered pull requests in one query; one GitHub returns as null is absent.
func (c *Client) ReadPullRequests(ctx context.Context, repo Repo, numbers []int) (map[int]PullRequest, error) {
	result := map[int]PullRequest{}
	if len(numbers) == 0 {
		return result, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.withRepo(ctx, repo, func(inst *installation) error {
		clear(result)
		nodes, answerErr, err := c.batch(ctx, inst, repo, numbers)
		if err != nil {
			return err
		}
		// GitHub answers a missing pull request with null and an error. Asked again without the nulls, an
		// error is about a pull request that exists, and fails the read.
		if answerErr != nil {
			if len(nodes) == len(numbers) {
				return c.graphqlFailure(answerErr)
			}
			present := make([]int, 0, len(nodes))
			for _, n := range numbers {
				if nodes[n] != nil {
					present = append(present, n)
				}
			}
			if nodes, answerErr, err = c.batch(ctx, inst, repo, present); err != nil {
				return err
			}
			if answerErr != nil {
				return c.graphqlFailure(answerErr)
			}
		}
		for _, n := range numbers {
			if nodes[n] == nil {
				continue
			}
			pr, err := c.readPullRequest(ctx, inst, repo, n, nodes[n])
			if err != nil {
				return err
			}
			result[n] = pr
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// batch asks for numbers in one query and returns the pull requests GitHub returned, with the errors list
// GitHub answered beside them; err is a failure to get or read the answer.
func (c *Client) batch(ctx context.Context, inst *installation, repo Repo, numbers []int) (map[int]*prNode, error, error) {
	vars := map[string]any{"owner": githubv4.String(repo.Owner), "name": githubv4.String(repo.Name)}
	fields := make([]reflect.StructField, len(numbers))
	for i, n := range numbers {
		v := fmt.Sprintf("$n%d", i)
		vars[v[1:]] = githubv4.Int(n)
		fields[i] = reflect.StructField{
			Name: fmt.Sprintf("PR%d", i),
			Type: reflect.PointerTo(retag(prNodeType, v)),
			Tag:  reflect.StructTag(fmt.Sprintf(`graphql:"pr%d: pullRequest(number: %s)"`, i, v)),
		}
	}
	q := reflect.New(reflect.StructOf([]reflect.StructField{
		{Name: "RateLimit", Type: reflect.TypeFor[*rateLimit]()},
		{Name: "Repository", Type: reflect.PointerTo(reflect.StructOf(fields)), Tag: `graphql:"repository(owner: $owner, name: $name)"`},
	}))
	err := inst.gql.Query(ctx, q.Interface(), vars)
	c.noteRateLimit(q.Elem().Field(0).Interface().(*rateLimit))
	repository := q.Elem().Field(1)
	if err != nil && (repository.IsNil() || !isGraphQLErrors(err)) {
		return nil, nil, c.graphqlFailure(err)
	}
	if repository.IsNil() {
		return nil, nil, fmt.Errorf("GitHub returned no repository")
	}
	nodes := map[int]*prNode{}
	for i, n := range numbers {
		alias := repository.Elem().Field(i)
		if alias.IsNil() {
			continue
		}
		// The retagged type has prNode's field names, so its JSON is prNode's.
		b, err := json.Marshal(alias.Interface())
		if err != nil {
			return nil, nil, err
		}
		var node prNode
		if err := json.Unmarshal(b, &node); err != nil {
			return nil, nil, err
		}
		nodes[n] = &node
	}
	return nodes, err, nil
}

// pullRequestPage is one further page of a pull request's connection.
type pullRequestPage[T any] struct {
	RateLimit  *rateLimit
	Repository *struct {
		PullRequest *T `graphql:"pullRequest(number: $n)"`
	} `graphql:"repository(owner: $owner, name: $name)"`
}

func page[T any](ctx context.Context, c *Client, inst *installation, repo Repo, number int, after string) (*T, error) {
	var q pullRequestPage[T]
	vars := map[string]any{"owner": githubv4.String(repo.Owner), "name": githubv4.String(repo.Name), "n": githubv4.Int(number), "after": githubv4.String(after)}
	err := inst.gql.Query(ctx, &q, vars)
	c.noteRateLimit(q.RateLimit)
	if err != nil {
		return nil, c.graphqlFailure(err)
	}
	if q.Repository == nil || q.Repository.PullRequest == nil {
		return nil, fmt.Errorf("GitHub returned no pull request page")
	}
	return q.Repository.PullRequest, nil
}

func (c *Client) readPullRequest(ctx context.Context, inst *installation, repo Repo, number int, node *prNode) (PullRequest, error) {
	if node.HeadRefOID == nil {
		return PullRequest{}, fmt.Errorf("GitHub returned a pull request without a head")
	}
	headSHA := *node.HeadRefOID
	var reviews []reviewNode
	if node.Reviews != nil {
		reviews = node.Reviews.Nodes
		for p := node.Reviews.PageInfo; p.HasNextPage; {
			next, err := page[struct {
				Reviews *reviewsPage `graphql:"reviews(first: 100, after: $after)"`
			}](ctx, c, inst, repo, number, cursor(p))
			if err != nil {
				return PullRequest{}, err
			}
			if next.Reviews == nil {
				return PullRequest{}, fmt.Errorf("GitHub returned no reviews page")
			}
			reviews, p = append(reviews, next.Reviews.Nodes...), next.Reviews.PageInfo
		}
	}
	if node.Files == nil {
		return PullRequest{}, fmt.Errorf("GitHub returned no files for a pull request")
	}
	files := node.Files.Nodes
	for p := node.Files.PageInfo; p.HasNextPage; {
		next, err := page[struct {
			Files *filesPage `graphql:"files(first: 100, after: $after)"`
		}](ctx, c, inst, repo, number, cursor(p))
		if err != nil {
			return PullRequest{}, err
		}
		if next.Files == nil {
			return PullRequest{}, fmt.Errorf("GitHub returned no files page")
		}
		files, p = append(files, next.Files.Nodes...), next.Files.PageInfo
	}
	checks, err := c.readChecks(ctx, inst, repo, number, headSHA, node.Commits)
	if err != nil {
		return PullRequest{}, err
	}
	if node.BaseRefName == nil {
		return PullRequest{}, fmt.Errorf("GitHub returned a pull request without a base")
	}
	pr := PullRequest{
		Number:   number,
		Open:     node.State == "OPEN",
		Merged:   node.Merged != nil && *node.Merged,
		MergedAt: node.MergedAt,
		HeadSHA:  headSHA,
		BaseRef:  *node.BaseRefName,
		Author:   sourceUser(node.Author),
		Reviews:  []Review{},
		Checks:   checks,
		Files:    []ChangedFile{},
		Commits:  []CommitAuthor{},
	}
	if node.MergeCommit != nil {
		pr.MergeCommit = &node.MergeCommit.OID
	}
	if a := node.AutoMergeRequest; a != nil {
		pr.AutoMerge = &AutoMerge{EnabledBy: refUser(a.EnabledBy), EnabledAt: a.EnabledAt}
	}
	for _, r := range reviews {
		if r.DatabaseID == nil {
			return PullRequest{}, fmt.Errorf("GitHub returned a review without an id")
		}
		if !slices.Contains(reviewStates, r.State) {
			return PullRequest{}, fmt.Errorf("GitHub returned an unknown review state")
		}
		rv := Review{ID: strconv.FormatInt(*r.DatabaseID, 10), Reviewer: refUser(r.Author), State: r.State, SubmittedAt: r.SubmittedAt}
		if r.URL != nil {
			rv.URL = *r.URL
		}
		if r.Commit != nil {
			rv.Commit = &r.Commit.OID
		}
		pr.Reviews = append(pr.Reviews, rv)
	}
	for _, f := range files {
		if f.Path == nil {
			return PullRequest{}, fmt.Errorf("GitHub returned a file without a path")
		}
		change := "CHANGED"
		if slices.Contains(fileChanges, f.ChangeType) {
			change = f.ChangeType
		}
		pr.Files = append(pr.Files, ChangedFile{Path: *f.Path, Change: change})
	}
	for _, n := range node.Authors.Nodes {
		if n.Commit == nil {
			continue
		}
		var a CommitAuthor
		if au := n.Commit.Author; au != nil {
			a.Email = au.Email
			if au.User != nil && au.User.DatabaseID != nil {
				a.UserID = new(strconv.FormatInt(*au.User.DatabaseID, 10))
			}
		}
		a.Merge = n.Commit.Parents.TotalCount > 1
		pr.Commits = append(pr.Commits, a)
	}
	return pr, nil
}

// readChecks is nil when the head commit's rollup cannot be read: there is none, or a push moved the head
// while it was paged.
func (c *Client) readChecks(ctx context.Context, inst *installation, repo Repo, number int, headSHA string, commits headCommit) ([]Check, error) {
	oid, contexts, ok := commits.headRollup()
	if !ok || oid != headSHA || contexts == nil {
		return nil, nil
	}
	nodes := contexts.Nodes
	for p := contexts.PageInfo; p.HasNextPage; {
		next, err := page[struct {
			Commits struct {
				Nodes []struct {
					Commit *struct {
						OID               string `graphql:"oid"`
						StatusCheckRollup *struct {
							Contexts contextsPage `graphql:"contexts(first: 100, after: $after)"`
						}
					}
				}
			} `graphql:"commits(last: 1)"`
		}](ctx, c, inst, repo, number, cursor(p))
		if err != nil {
			return nil, err
		}
		cs := next.Commits.Nodes
		if len(cs) == 0 || cs[0].Commit == nil || cs[0].Commit.OID != headSHA || cs[0].Commit.StatusCheckRollup == nil {
			return nil, nil
		}
		nodes, p = append(nodes, cs[0].Commit.StatusCheckRollup.Contexts.Nodes...), cs[0].Commit.StatusCheckRollup.Contexts.PageInfo
	}
	checks := make([]Check, 0, len(nodes))
	for _, n := range nodes {
		checks = append(checks, check(n))
	}
	return checks, nil
}

func cursor(p pageInfo) string {
	if p.EndCursor == nil {
		return ""
	}
	return *p.EndCursor
}

func check(n contextNode) Check {
	if n.Typename == "StatusContext" {
		c := Check{Name: n.StatusContext.Context, Required: n.StatusContext.IsRequired != nil && *n.StatusContext.IsRequired, Status: CheckInProgress}
		switch n.StatusContext.State {
		case "SUCCESS":
			c.Status, c.Conclusion = CheckCompleted, new("SUCCESS")
		case "FAILURE", "ERROR":
			c.Status, c.Conclusion = CheckCompleted, new("FAILURE")
		}
		return c
	}
	r := n.CheckRun
	c := Check{Name: r.Name, Required: r.IsRequired != nil && *r.IsRequired, Status: CheckQueued}
	switch r.Status {
	case "IN_PROGRESS":
		c.Status = CheckInProgress
	case "COMPLETED":
		c.Status = CheckCompleted
	}
	if r.Conclusion != nil {
		conclusion := "FAILURE"
		if slices.Contains(checkConclusions, *r.Conclusion) {
			conclusion = *r.Conclusion
		}
		c.Conclusion = &conclusion
	}
	return c
}

func sourceUser(a *actor) *User {
	if a == nil {
		return nil
	}
	id := a.User.DatabaseID
	if id == nil {
		id = a.Bot.DatabaseID
	}
	return user(a.Login, id)
}

func refUser(u *userRef) *User {
	if u == nil {
		return nil
	}
	return user(u.Login, u.User.DatabaseID)
}

func user(login *string, id *int64) *User {
	if login == nil || id == nil || *login == "ghost" {
		return nil
	}
	return &User{ID: strconv.FormatInt(*id, 10), Login: *login}
}

// isGraphQLErrors reports whether err is the errors list of a decoded answer, which githubv4 returns as an
// unexported type, rather than a transport or decoding failure.
func isGraphQLErrors(err error) bool {
	return reflect.TypeOf(err).String() == "graphql.errors"
}
