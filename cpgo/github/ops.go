package github

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	gh "github.com/google/go-github/v88/github"
	"github.com/shurcooL/githubv4"
)

func (c *Client) ReadFile(ctx context.Context, repo Repo, ref, path string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var buf bytes.Buffer
	err := c.withRepo(ctx, repo, func(inst *installation) error {
		buf.Reset()
		var segments []string
		for s := range strings.SplitSeq(path, "/") {
			if s != "" {
				segments = append(segments, url.PathEscape(s))
			}
		}
		u := fmt.Sprintf("repos/%s/%s/contents/%s?ref=%s", url.PathEscape(repo.Owner), url.PathEscape(repo.Name),
			strings.Join(segments, "/"), url.QueryEscape(ref))
		req, err := inst.rest.NewRequest(ctx, "GET", u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", rawAccept)
		_, err = inst.rest.Do(req, &buf)
		return err
	})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *Client) CompareCommits(ctx context.Context, repo Repo, base, head string) (Relation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var status string
	err := c.withRepo(ctx, repo, func(inst *installation) error {
		cmp, _, err := inst.rest.Repositories.CompareCommits(ctx, repo.Owner, repo.Name, base, head, &gh.ListOptions{PerPage: 1})
		status = cmp.GetStatus()
		return err
	})
	if err != nil {
		return "", err
	}
	switch status {
	case "ahead":
		return Ahead, nil
	case "identical":
		return Identical, nil
	case "behind":
		return Behind, nil
	case "diverged":
		return Diverged, nil
	}
	return "", fmt.Errorf("GitHub returned an unknown comparison status: %s", status)
}

// RequiredChecks is the status contexts branch's rulesets and branch protection require, cached for five minutes.
func (c *Client) RequiredChecks(ctx context.Context, repo Repo, branch string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := strings.ToLower(repo.Owner+"/"+repo.Name) + "\x00" + branch
	now := c.now()
	if cached, ok := c.requiredChecks[key]; ok && now.Before(cached.at.Add(requiredChecksTTL)) {
		return cached.contexts, nil
	}
	contexts := map[string]bool{}
	err := c.withRepo(ctx, repo, func(inst *installation) error {
		clear(contexts)
		for rule, err := range inst.rest.Repositories.ListRulesForBranchIter(ctx, repo.Owner, repo.Name, url.PathEscape(branch), &gh.ListOptions{PerPage: 100}) {
			if isNotFound(err) {
				break
			}
			if err != nil {
				return err
			}
			if r, ok := rule.(*gh.RequiredStatusChecksBranchRule); ok {
				for _, s := range r.Parameters.RequiredStatusChecks {
					contexts[s.Context] = true
				}
			}
		}
		// The branch endpoint needs only metadata read; its `/protection` sub-resource needs administration.
		b, _, err := inst.rest.Repositories.GetBranch(ctx, repo.Owner, repo.Name, branch, 1)
		if isNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if rsc := b.GetProtection().GetRequiredStatusChecks(); rsc != nil {
			if rsc.Contexts != nil {
				for _, s := range *rsc.Contexts {
					contexts[s] = true
				}
			}
			if rsc.Checks != nil {
				for _, s := range *rsc.Checks {
					contexts[s.Context] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	list := make([]string, 0, len(contexts))
	for s := range contexts {
		list = append(list, s)
	}
	slices.Sort(list)
	c.requiredChecks[key] = cachedChecks{at: now, contexts: list}
	return list, nil
}

// PostCheck creates this App's check run on headSha, or updates the one it already has.
func (c *Client) PostCheck(ctx context.Context, repo Repo, headSha, name, status string, conclusion *string, title, summary string) error {
	if status == CheckCompleted && conclusion == nil {
		return errors.New("a completed check needs a conclusion")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.withRepo(ctx, repo, func(inst *installation) error {
		runs, _, err := inst.rest.Checks.ListCheckRunsForRef(ctx, repo.Owner, repo.Name, headSha, &gh.ListCheckRunsOptions{
			CheckName: &name, Filter: new("latest"), AppID: &c.appID,
		})
		if err != nil {
			return err
		}
		var existing *gh.CheckRun
		for _, r := range runs.CheckRuns {
			if r.GetApp().GetID() == c.appID {
				existing = r
				break
			}
		}
		st := strings.ToLower(status)
		output := &gh.CheckRunOutput{Title: &title, Summary: &summary}
		var lower *string
		if status == CheckCompleted {
			lower = new(strings.ToLower(*conclusion))
		}
		if existing != nil {
			_, _, err = inst.rest.Checks.UpdateCheckRun(ctx, repo.Owner, repo.Name, existing.GetID(), gh.UpdateCheckRunOptions{
				Name: name, Status: &st, Conclusion: lower, Output: output,
			})
			return err
		}
		_, _, err = inst.rest.Checks.CreateCheckRun(ctx, repo.Owner, repo.Name, gh.CreateCheckRunOptions{
			Name: name, HeadSHA: headSha, Status: &st, Conclusion: lower, Output: output,
		})
		return err
	})
}

func (c *Client) DismissReview(ctx context.Context, repo Repo, pr int, reviewID, message string) error {
	id, err := strconv.ParseInt(reviewID, 10, 64)
	if err != nil {
		return fmt.Errorf("review id %q is not a number", reviewID)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.withRepo(ctx, repo, func(inst *installation) error {
		_, _, err := inst.rest.PullRequests.DismissReview(ctx, repo.Owner, repo.Name, pr, id, &gh.PullRequestReviewDismissalRequest{Message: &message})
		return err
	})
}

func (c *Client) PostComment(ctx context.Context, repo Repo, pr int, body string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.withRepo(ctx, repo, func(inst *installation) error {
		_, _, err := inst.rest.Issues.CreateComment(ctx, repo.Owner, repo.Name, pr, &gh.IssueComment{Body: &body})
		return err
	})
}

// UpsertComment edits this App's comment carrying marker, or posts a new one.
func (c *Client) UpsertComment(ctx context.Context, repo Repo, pr int, marker, body string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	markerLine := "<!-- proxy-monster:" + marker + " -->"
	text := markerLine + "\n" + body
	return c.withRepo(ctx, repo, func(inst *installation) error {
		existing, err := c.findMarkedComment(ctx, inst, repo, pr, markerLine)
		if err != nil {
			return err
		}
		if existing == 0 {
			_, _, err = inst.rest.Issues.CreateComment(ctx, repo.Owner, repo.Name, pr, &gh.IssueComment{Body: &text})
			return err
		}
		_, _, err = inst.rest.Issues.EditComment(ctx, repo.Owner, repo.Name, existing, &gh.IssueComment{Body: &text})
		return err
	})
}

// markedComment is an issue comment with the App that posted it, which go-github's IssueComment omits.
type markedComment struct {
	ID   int64   `json:"id"`
	Body *string `json:"body"`
	App  *gh.App `json:"performed_via_github_app"`
}

func (c *Client) findMarkedComment(ctx context.Context, inst *installation, repo Repo, pr int, markerLine string) (int64, error) {
	for page := 1; ; page++ {
		u := fmt.Sprintf("repos/%s/%s/issues/%d/comments?per_page=%d&page=%d", url.PathEscape(repo.Owner), url.PathEscape(repo.Name), pr, commentPage, page)
		req, err := inst.rest.NewRequest(ctx, "GET", u, nil)
		if err != nil {
			return 0, err
		}
		var comments []markedComment
		if _, err := inst.rest.Do(req, &comments); err != nil {
			return 0, err
		}
		for _, cm := range comments {
			if cm.App.GetID() == c.appID && cm.Body != nil && strings.HasPrefix(*cm.Body, markerLine) {
				return cm.ID, nil
			}
		}
		if len(comments) < commentPage {
			return 0, nil
		}
	}
}

// ExternalIdentity is the SAML nameId org links to login; nil when it has none.
func (c *Client) ExternalIdentity(ctx context.Context, org, login string) (*string, error) {
	var q struct {
		RateLimit    *rateLimit
		Organization *struct {
			SAMLIdentityProvider *struct {
				ExternalIdentities struct {
					Nodes []struct {
						SAMLIdentity *struct {
							NameID *string `graphql:"nameId"`
						} `graphql:"samlIdentity"`
					}
				} `graphql:"externalIdentities(login: $login, first: 1)"`
			} `graphql:"samlIdentityProvider"`
		} `graphql:"organization(login: $org)"`
	}
	if err := c.orgQuery(ctx, org, login, &q, func() *rateLimit { return q.RateLimit }); err != nil {
		return nil, err
	}
	if q.Organization == nil || q.Organization.SAMLIdentityProvider == nil {
		return nil, nil
	}
	nodes := q.Organization.SAMLIdentityProvider.ExternalIdentities.Nodes
	if len(nodes) == 0 || nodes[0].SAMLIdentity == nil {
		return nil, nil
	}
	return nodes[0].SAMLIdentity.NameID, nil
}

// VerifiedEmails is login's emails in org's verified domains.
func (c *Client) VerifiedEmails(ctx context.Context, org, login string) ([]string, error) {
	var q struct {
		RateLimit *rateLimit
		User      *struct {
			Emails []string `graphql:"organizationVerifiedDomainEmails(login: $org)"`
		} `graphql:"user(login: $login)"`
	}
	if err := c.orgQuery(ctx, org, login, &q, func() *rateLimit { return q.RateLimit }); err != nil {
		return nil, err
	}
	if q.User == nil {
		return []string{}, nil
	}
	return append([]string{}, q.User.Emails...), nil
}

// orgQuery runs an identity lookup; any GraphQL error fails it rather than fall through to a weaker resolver.
func (c *Client) orgQuery(ctx context.Context, org, login string, q any, limit func() *rateLimit) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.withOrg(ctx, org, func(inst *installation) error {
		err := inst.gql.Query(ctx, q, map[string]any{"org": githubv4.String(org), "login": githubv4.String(login)})
		c.noteRateLimit(limit())
		if err != nil {
			return c.graphqlFailure(err)
		}
		return nil
	})
}

func isNotFound(err error) bool {
	e, ok := errors.AsType[*Error](err)
	return ok && e.Kind == NotFound
}
