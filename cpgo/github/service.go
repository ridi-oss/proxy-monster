package github

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/ridi-oss/proxy-monster/cpgo/gobridge/pb"
)

// Service serves the client as the GitHubSource bridge service.
type Service struct {
	pb.UnimplementedGitHubSourceServer
	c *Client
}

func NewService(c *Client) *Service { return &Service{c: c} }

func repoOf(r *pb.Repo) Repo { return Repo{Owner: r.GetOwner(), Name: r.GetName()} }

func (s *Service) ReadPullRequests(ctx context.Context, in *pb.ReadPullRequestsRequest) (*pb.ReadPullRequestsResponse, error) {
	numbers := make([]int, len(in.GetNumbers()))
	for i, n := range in.GetNumbers() {
		numbers[i] = int(n)
	}
	prs, err := s.c.ReadPullRequests(ctx, repoOf(in.GetRepo()), numbers)
	if err != nil {
		return nil, grpcError(err)
	}
	out := &pb.ReadPullRequestsResponse{PullRequests: map[int32]*pb.PullRequest{}, RateLimit: s.rateLimit()}
	for n, pr := range prs {
		out.PullRequests[int32(n)] = pullRequestPB(pr)
	}
	return out, nil
}

func (s *Service) ReadFile(ctx context.Context, in *pb.ReadFileRequest) (*pb.ReadFileResponse, error) {
	b, err := s.c.ReadFile(ctx, repoOf(in.GetRepo()), in.GetRef(), in.GetPath())
	if err != nil {
		return nil, grpcError(err)
	}
	return &pb.ReadFileResponse{Content: b}, nil
}

func (s *Service) CompareCommits(ctx context.Context, in *pb.CompareCommitsRequest) (*pb.CompareCommitsResponse, error) {
	rel, err := s.c.CompareCommits(ctx, repoOf(in.GetRepo()), in.GetBase(), in.GetHead())
	if err != nil {
		return nil, grpcError(err)
	}
	return &pb.CompareCommitsResponse{Relation: pb.CommitRelation(pb.CommitRelation_value[string(rel)])}, nil
}

func (s *Service) RequiredChecks(ctx context.Context, in *pb.RequiredChecksRequest) (*pb.RequiredChecksResponse, error) {
	contexts, err := s.c.RequiredChecks(ctx, repoOf(in.GetRepo()), in.GetBranch())
	if err != nil {
		return nil, grpcError(err)
	}
	return &pb.RequiredChecksResponse{Contexts: contexts}, nil
}

func (s *Service) PostCheck(ctx context.Context, in *pb.PostCheckRequest) (*emptypb.Empty, error) {
	var conclusion *string
	if in.GetConclusion() != pb.CheckConclusion_CHECK_CONCLUSION_UNSPECIFIED {
		conclusion = new(in.GetConclusion().String())
	}
	err := s.c.PostCheck(ctx, repoOf(in.GetRepo()), in.GetHeadSha(), in.GetName(), in.GetStatus().String(), conclusion, in.GetTitle(), in.GetSummary())
	return &emptypb.Empty{}, grpcError(err)
}

func (s *Service) DismissReview(ctx context.Context, in *pb.DismissReviewRequest) (*emptypb.Empty, error) {
	err := s.c.DismissReview(ctx, repoOf(in.GetRepo()), int(in.GetPr()), in.GetReviewId(), in.GetMessage())
	return &emptypb.Empty{}, grpcError(err)
}

func (s *Service) PostComment(ctx context.Context, in *pb.PostCommentRequest) (*emptypb.Empty, error) {
	var err error
	if in.Marker != nil {
		err = s.c.UpsertComment(ctx, repoOf(in.GetRepo()), int(in.GetPr()), in.GetMarker(), in.GetBody())
	} else {
		err = s.c.PostComment(ctx, repoOf(in.GetRepo()), int(in.GetPr()), in.GetBody())
	}
	return &emptypb.Empty{}, grpcError(err)
}

func (s *Service) ExternalIdentity(ctx context.Context, in *pb.IdentityRequest) (*pb.ExternalIdentityResponse, error) {
	nameID, err := s.c.ExternalIdentity(ctx, in.GetOrg(), in.GetLogin())
	if err != nil {
		return nil, grpcError(err)
	}
	return &pb.ExternalIdentityResponse{NameId: nameID, RateLimit: s.rateLimit()}, nil
}

func (s *Service) VerifiedEmails(ctx context.Context, in *pb.IdentityRequest) (*pb.VerifiedEmailsResponse, error) {
	emails, err := s.c.VerifiedEmails(ctx, in.GetOrg(), in.GetLogin())
	if err != nil {
		return nil, grpcError(err)
	}
	return &pb.VerifiedEmailsResponse{Emails: emails, RateLimit: s.rateLimit()}, nil
}

func (s *Service) rateLimit() *pb.RateLimit {
	rl := s.c.RateLimit()
	if rl == nil {
		return nil
	}
	return &pb.RateLimit{Remaining: int32(rl.Remaining), ResetAt: timestamppb.New(rl.ResetAt)}
}

var kinds = map[Kind]pb.GitHubError_Kind{
	Unauthorized:  pb.GitHubError_UNAUTHORIZED,
	Forbidden:     pb.GitHubError_FORBIDDEN,
	NotFound:      pb.GitHubError_NOT_FOUND,
	RateLimited:   pb.GitHubError_RATE_LIMITED,
	Unprocessable: pb.GitHubError_UNPROCESSABLE,
	Server:        pb.GitHubError_SERVER,
	GraphQL:       pb.GitHubError_GRAPHQL,
}

// grpcError carries a failed GitHub call as a GitHubError status detail, and any other failure as INTERNAL.
func grpcError(err error) error {
	if err == nil {
		return nil
	}
	e, ok := errors.AsType[*Error](err)
	if !ok {
		return grpcstatus.Error(codes.Internal, err.Error())
	}
	detail := &pb.GitHubError{Kind: kinds[e.Kind], Message: e.Message, Status: int32(e.Status)}
	if e.ResetAt != nil {
		detail.ResetAt = timestamppb.New(*e.ResetAt)
	}
	st, derr := grpcstatus.New(codes.Unavailable, e.Message).WithDetails(detail)
	if derr != nil {
		return grpcstatus.Error(codes.Internal, e.Message)
	}
	return st.Err()
}

func tsPB(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func userPB(u *User) *pb.SourceUser {
	if u == nil {
		return nil
	}
	return &pb.SourceUser{Id: u.ID, Login: u.Login}
}

func pullRequestPB(pr PullRequest) *pb.PullRequest {
	out := &pb.PullRequest{
		Number:      int32(pr.Number),
		Open:        pr.Open,
		Draft:       pr.Draft,
		Merged:      pr.Merged,
		MergedAt:    tsPB(pr.MergedAt),
		MergeCommit: pr.MergeCommit,
		HeadSha:     pr.HeadSHA,
		BaseRef:     pr.BaseRef,
		Author:      userPB(pr.Author),
	}
	if a := pr.AutoMerge; a != nil {
		out.AutoMerge = &pb.AutoMerge{EnabledBy: userPB(a.EnabledBy), EnabledAt: tsPB(a.EnabledAt)}
	}
	for _, r := range pr.Reviews {
		out.Reviews = append(out.Reviews, &pb.Review{
			Id: r.ID, Reviewer: userPB(r.Reviewer), State: pb.ReviewState(pb.ReviewState_value[r.State]),
			SubmittedAt: tsPB(r.SubmittedAt), Url: r.URL, Commit: r.Commit,
		})
	}
	if pr.Checks != nil {
		out.Checks = &pb.Checks{}
		for _, c := range pr.Checks {
			pc := &pb.Check{Name: c.Name, Required: c.Required, Status: pb.CheckStatus(pb.CheckStatus_value[c.Status])}
			if c.Conclusion != nil {
				pc.Conclusion = pb.CheckConclusion(pb.CheckConclusion_value[*c.Conclusion])
			}
			out.Checks.Checks = append(out.Checks.Checks, pc)
		}
	}
	for _, f := range pr.Files {
		out.Files = append(out.Files, &pb.ChangedFile{Path: f.Path, Change: pb.FileChange(pb.FileChange_value[f.Change])})
	}
	for _, c := range pr.Commits {
		out.Commits = append(out.Commits, &pb.CommitAuthor{UserId: c.UserID, Email: c.Email, Merge: c.Merge})
	}
	return out
}
