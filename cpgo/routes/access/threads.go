package access

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/jackc/pgx/v5"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
	"github.com/ridi-oss/proxy-monster/cpgo/timeline"
)

const commentMaxChars = 4000

// requestThread is Kotlin's RequestThread: the thread, and what the caller may do on it.
type requestThread struct {
	RequestID    int64            `json:"requestId"`
	CCs          []string         `json:"ccs"`
	Participants []string         `json:"participants"`
	Timeline     []timeline.Event `json:"timeline"`
	CanComment   bool             `json:"canComment"`
	CanCC        bool             `json:"canCc"`
	CanClose     bool             `json:"canClose"`
	CanDecide    bool             `json:"canDecide"`
	// People names each principal on the request: its requester, deciders, participants, CCs and actors.
	People map[string]person `json:"people"`
}

type person struct {
	Name  *string `json:"name,omitempty"`
	Email *string `json:"email,omitempty"`
}

// workflowRequest is the request, unless it is missing or an editor's or the wire proxy's own task row.
func (a access) workflowRequest(ctx context.Context, id int64) (*accessRequest, error) {
	req, err := getRequest(ctx, a.pool, id)
	if err != nil {
		return nil, err
	}
	if req == nil || req.CreatorKind == nil || *req.CreatorKind != "WORKFLOW" {
		return nil, api.NotFound("request")
	}
	return req, nil
}

// closable: not started, so closing undoes nothing. A pull request's request closes with its pull request.
func closable(req *accessRequest) bool {
	return req.Source != "github" && (req.Status == "PENDING" || (req.Kind == "QUERY" && req.Status == "APPROVED"))
}

// involved lists the workflow requests the caller filed or took part in; another person's statement shows only
// when it carries no protected literal.
func (a access) involved(w http.ResponseWriter, r *http.Request) error {
	principal := api.Principal(r.Context())
	rows, err := db.New(a.pool).InvolvedRequests(r.Context(), principal)
	return api.WriteRows(w, rows, err, func(row db.InvolvedRequestsRow) accessRequest {
		req := toAccessRequest(db.AccessRequestsRow(row))
		if req.Principal != principal && (req.StatementCarriesProtectedLiteral == nil || *req.StatementCarriesProtectedLiteral) {
			req.SQL = nil
		}
		return req
	})
}

func (a access) thread(w http.ResponseWriter, r *http.Request, id int64) error {
	ctx := r.Context()
	req, err := a.workflowRequest(ctx, id)
	if err != nil {
		return err
	}
	may, err := a.decider(ctx, req)
	if err != nil {
		return err
	}
	if ok, err := may("task.read"); err != nil || !ok {
		if err == nil {
			err = api.NotFound("request")
		}
		return err
	}
	t := requestThread{RequestID: id, CCs: req.CCs}
	if t.Participants, err = db.New(a.pool).RequestParticipants(ctx, id); err != nil {
		return err
	}
	if t.Timeline, err = timeline.List(ctx, a.pool, id); err != nil {
		return err
	}
	if t.People, err = a.people(ctx, req, t); err != nil {
		return err
	}
	if t.CanComment, err = may("task.comment"); err != nil {
		return err
	}
	if t.CanCC, err = may("task.cc"); err != nil {
		return err
	}
	if closable(req) {
		if t.CanClose, err = may("task.cancel"); err != nil {
			return err
		}
	}
	if req.Status == "PENDING" {
		if t.CanDecide, err = may("task.approve"); err != nil {
			return err
		}
	}
	api.WriteJSON(w, http.StatusOK, t)
	return nil
}

// comment adds a comment or, with lgtm, an LGTM, which is shown but never approves.
func (a access) comment(w http.ResponseWriter, r *http.Request, id int64) error {
	ctx := r.Context()
	var in struct {
		Body *string `json:"body"`
		LGTM bool    `json:"lgtm"`
	}
	if err := api.DecodeBody(r, &in); err != nil {
		return err
	}
	var text *string
	if in.Body != nil {
		if t := strings.TrimSpace(*in.Body); t != "" {
			text = &t
		}
	}
	if !in.LGTM && text == nil {
		return api.CodeFieldRequired.Err("fields", "body")
	}
	// Kotlin's String.length: UTF-16 code units.
	if text != nil && len(utf16.Encode([]rune(*text))) > commentMaxChars {
		return api.CodeCommentTooLong.Err("max", strconv.Itoa(commentMaxChars))
	}
	req, err := a.workflowRequest(ctx, id)
	if err != nil {
		return err
	}
	if err := a.require(ctx, req, "task.comment", api.CodeCommentForbidden); err != nil {
		return err
	}
	kind := timeline.Comment
	if in.LGTM {
		kind = timeline.LGTM
	}
	var ev *timeline.Event
	err = pgx.BeginFunc(ctx, a.pool, func(tx pgx.Tx) error {
		actor := api.ActorOf(ctx)
		var err error
		ev, err = timeline.Record(ctx, tx, id, kind, &actor.Principal, actor.Channel, text)
		return err
	})
	if err == nil && ev == nil {
		err = api.NotFound("request")
	}
	if err != nil {
		return err
	}
	a.signal(ctx, id, notice{event: "commented"})
	api.WriteJSON(w, http.StatusCreated, ev)
	return nil
}

func (a access) people(ctx context.Context, req *accessRequest, t requestThread) (map[string]person, error) {
	principals := append([]string{req.Principal}, t.Participants...)
	principals = append(principals, t.CCs...)
	for _, p := range []*string{req.DecidedBy, req.ExecutedBy, req.ForceRunBy} {
		if p != nil {
			principals = append(principals, *p)
		}
	}
	for _, e := range t.Timeline {
		if e.Actor != nil {
			principals = append(principals, *e.Actor)
		}
	}
	rows, err := db.New(a.pool).PeopleByPrincipal(ctx, principals)
	out := make(map[string]person, len(rows))
	for _, r := range rows {
		out[r.Principal] = person{Name: r.DisplayName, Email: r.Email}
	}
	return out, err
}

func (a access) require(ctx context.Context, req *accessRequest, action string, denied api.Code) error {
	may, err := a.decider(ctx, req)
	if err != nil {
		return err
	}
	ok, err := may(action)
	if err == nil && !ok {
		err = denied.Err()
	}
	return err
}

func (a access) addCC(w http.ResponseWriter, r *http.Request, id int64) error {
	var in struct {
		Principal *string `json:"principal"`
	}
	if err := api.DecodeBody(r, &in); err != nil || in.Principal == nil {
		return api.CodeInvalidValue.Err("field", "body")
	}
	return a.setCC(w, r, id, *in.Principal, true)
}

func (a access) removeCC(w http.ResponseWriter, r *http.Request, id int64) error {
	return a.setCC(w, r, id, r.PathValue("principal"), false)
}

// setCC adds or removes a CC named by an active principal or an active user's email.
func (a access) setCC(w http.ResponseWriter, r *http.Request, id int64, who string, add bool) error {
	ctx := r.Context()
	req, err := a.workflowRequest(ctx, id)
	if err != nil {
		return err
	}
	if err := a.require(ctx, req, "task.cc", api.CodeCCForbidden); err != nil {
		return err
	}
	who = strings.TrimSpace(who)
	cc, ok, err := a.activePrincipal(ctx, who)
	switch {
	case err != nil:
		return err
	case !ok && add:
		return api.CodeUnknownUser.Err()
	case !ok:
		cc = who
	}
	if add && cc == req.Principal {
		return api.CodeCCRequester.Err()
	}
	return a.decided(w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (int64, notice, error) {
		q := db.New(tx)
		kind, n := timeline.CCAdded, notice{event: "cc-added", principal: cc}
		if add {
			if slices.Contains(req.CCs, cc) {
				return id, notice{}, nil
			}
			if err := q.AddCC(ctx, db.AddCCParams{RequestID: id, Principal: cc}); err != nil {
				return id, notice{}, err
			}
		} else {
			removed, err := q.RemoveCC(ctx, db.RemoveCCParams{RequestID: id, Principal: cc})
			if err != nil || removed == 0 {
				return id, notice{}, err
			}
			kind, n = timeline.CCRemoved, notice{event: "cc-removed"}
		}
		_, err := timeline.Record(ctx, tx, id, kind, &actor.Principal, actor.Channel, &cc)
		return id, n, err
	})
}

// activePrincipal resolves who as Kotlin's listActivePrincipals, else as the one active user with that email.
func (a access) activePrincipal(ctx context.Context, who string) (string, bool, error) {
	q := db.New(a.pool)
	active, err := q.IsActivePrincipal(ctx, who)
	if err != nil || active {
		return who, active, err
	}
	byEmail, err := q.ActivePrincipalsByEmail(ctx, who)
	if err != nil || len(byEmail) != 1 {
		return "", false, err
	}
	return byEmail[0], true, nil
}

// close ends a request that has not started as CANCELLED; a running query is stopped through the approval routes.
func (a access) close(w http.ResponseWriter, r *http.Request, id int64) error {
	ctx := r.Context()
	req, err := a.workflowRequest(ctx, id)
	if err != nil {
		return err
	}
	if err := a.require(ctx, req, "task.cancel", api.CodeCancelForbidden); err != nil {
		return err
	}
	if !closable(req) {
		return api.CodeNotCancelable.Err()
	}
	return a.decided(w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (int64, notice, error) {
		n, err := db.New(tx).CloseRequest(ctx, id)
		if err != nil {
			return id, notice{}, err
		}
		if n == 0 {
			return id, notice{}, api.CodeNotCancelable.Err()
		}
		idText := strconv.FormatInt(id, 10)
		if err := audit.Admin(ctx, tx, actor, "task.cancel", audit.Entity("AccessRequest", idText), "close request #"+idText); err != nil {
			return id, notice{}, err
		}
		_, err = timeline.Record(ctx, tx, id, timeline.Closed, &actor.Principal, actor.Channel, nil)
		return id, notifyCancelled, err
	})
}
