package routes

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ridi-oss/proxy-monster/cpgo/api"
	"github.com/ridi-oss/proxy-monster/cpgo/audit"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

type dbtx interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

type ref struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// appUser and appGroup are Kotlin's AppUser and AppGroup, fields in declaration order.
type appUser struct {
	ID          int64   `json:"id"`
	Principal   string  `json:"principal"`
	DisplayName *string `json:"displayName,omitempty"`
	Email       *string `json:"email,omitempty"`
	Source      string  `json:"source"`
	ExternalID  *string `json:"externalId,omitempty"`
	Active      bool    `json:"active"`
	CreatedAt   string  `json:"createdAt"`
	Groups      []ref   `json:"groups"`
}

type appGroup struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	Source      string  `json:"source"`
	ExternalID  *string `json:"externalId,omitempty"`
	MemberCount int     `json:"memberCount"`
	Roles       []ref   `json:"roles"`
}

type groupMember struct {
	UserID      int64   `json:"userId"`
	Principal   string  `json:"principal"`
	DisplayName *string `json:"displayName,omitempty"`
}

type groupRole struct {
	RoleID   int64  `json:"roleId"`
	RoleName string `json:"roleName"`
}

type identity struct {
	pool          *pgxpool.Pool
	sessionsEnded func(ctx context.Context, principal string) error
}

func refsBy[R any](rows []R, owned func(R) (int64, ref)) map[int64][]ref {
	out := map[int64][]ref{}
	for _, row := range rows {
		owner, r := owned(row)
		out[owner] = append(out[owner], r)
	}
	return out
}

func toAppUser(r db.UsersRow, groups map[int64][]ref) appUser {
	u := appUser{ID: r.ID, Principal: r.Principal, DisplayName: r.DisplayName, Email: r.Email, Source: r.Source,
		ExternalID: r.ExternalID, Active: r.Active, CreatedAt: javaInstant(r.CreatedAt), Groups: groups[r.ID]}
	if u.Groups == nil {
		u.Groups = []ref{}
	}
	return u
}

func getUser(ctx context.Context, q dbtx, id int64) (*appUser, error) {
	queries := db.New(q)
	rows, err := queries.GroupsOfUser(ctx, id)
	if err != nil {
		return nil, err
	}
	groups := refsBy(rows, func(g db.GroupsOfUserRow) (int64, ref) { return g.UserID, ref{g.ID, g.Name} })
	row, err := queries.User(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u := toAppUser(db.UsersRow(row), groups)
	return &u, nil
}

func mustUser(ctx context.Context, q dbtx, id int64) (*appUser, error) {
	u, err := getUser(ctx, q, id)
	if err == nil && u == nil {
		err = notFound("user")
	}
	return u, err
}

func getGroup(ctx context.Context, q dbtx, id int64) (*appGroup, error) {
	queries := db.New(q)
	count, err := queries.GroupMemberCount(ctx, id)
	if err != nil {
		return nil, err
	}
	rows, err := queries.RoleRefsOfGroup(ctx, id)
	if err != nil {
		return nil, err
	}
	roles := refsBy(rows, func(r db.RoleRefsOfGroupRow) (int64, ref) { return r.GroupID, ref{r.ID, r.Name} })
	g := appGroup{MemberCount: int(count), Roles: roles[id]}
	if g.Roles == nil {
		g.Roles = []ref{}
	}
	row, err := queries.Group(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("group")
	}
	g.ID, g.Name, g.Description, g.Source, g.ExternalID = row.ID, row.Name, row.Description, row.Source, row.ExternalID
	return &g, err
}

// mutableGroup is the group, refused when it is SYSTEM-owned.
func mutableGroup(ctx context.Context, q dbtx, id int64) (*appGroup, error) {
	g, err := getGroup(ctx, q, id)
	if err == nil && g.Source == "SYSTEM" {
		err = &managementError{code: "group.system_immutable"}
	}
	return g, err
}

func (h identity) listUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	queries := db.New(h.pool)
	memberships, err := queries.GroupsOfUsers(ctx)
	if err != nil {
		fail(w, err)
		return
	}
	groups := refsBy(memberships, func(g db.GroupsOfUsersRow) (int64, ref) { return g.UserID, ref{g.ID, g.Name} })
	rows, err := queries.Users(ctx)
	if err != nil {
		fail(w, err)
		return
	}
	users := make([]appUser, len(rows))
	for i, row := range rows {
		users[i] = toAppUser(row, groups)
	}
	api.WriteJSON(w, http.StatusOK, users)
}

func (h identity) listGroups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	queries := db.New(h.pool)
	mappings, err := queries.RoleRefsOfGroups(ctx)
	if err != nil {
		fail(w, err)
		return
	}
	roles := refsBy(mappings, func(r db.RoleRefsOfGroupsRow) (int64, ref) { return r.GroupID, ref{r.ID, r.Name} })
	counts := map[int64]int{}
	memberCounts, err := queries.GroupMemberCounts(ctx)
	if err != nil {
		fail(w, err)
		return
	}
	for _, c := range memberCounts {
		counts[c.GroupID] = int(c.Count)
	}
	rows, err := queries.Groups(ctx)
	if err != nil {
		fail(w, err)
		return
	}
	groups := make([]appGroup, len(rows))
	for i, row := range rows {
		g := appGroup{ID: row.ID, Name: row.Name, Description: row.Description, Source: row.Source, ExternalID: row.ExternalID,
			MemberCount: counts[row.ID], Roles: roles[row.ID]}
		if g.Roles == nil {
			g.Roles = []ref{}
		}
		groups[i] = g
	}
	api.WriteJSON(w, http.StatusOK, groups)
}

func lockPrincipal(ctx context.Context, tx pgx.Tx, principal string) error {
	return db.New(tx).LockPrincipal(ctx, principal)
}

// lockCurrentPrincipal locks the user's principal, re-reading it under the lock until a concurrent rename
// has settled. "" when there is no such user.
func lockCurrentPrincipal(ctx context.Context, tx pgx.Tx, id int64) (string, error) {
	principalOf := func() (string, error) {
		p, err := db.New(tx).PrincipalOfUser(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return p, err
	}
	seen, err := principalOf()
	for err == nil && seen != "" {
		if err = lockPrincipal(ctx, tx, seen); err != nil {
			break
		}
		var current string
		if current, err = principalOf(); err != nil || current == seen {
			return current, err
		}
		seen = current
	}
	return seen, err
}

// releaseTombstone frees principal from the inactive SCIM row a rename left behind, so it can be reused.
func releaseTombstone(ctx context.Context, tx pgx.Tx, principal string, exclude *int64) error {
	if err := lockPrincipal(ctx, tx, principal); err != nil {
		return err
	}
	q := db.New(tx)
	if tombstone, err := q.IsTombstone(ctx, principal); err != nil || !tombstone {
		return err
	}
	if err := q.DeletePrincipalRoles(ctx, principal); err != nil {
		return err
	}
	return q.DeleteTombstone(ctx, db.DeleteTombstoneParams{Principal: principal, Exclude: exclude})
}

// revokeCredentials is Kotlin's revokeActiveCredentialsTx: tokens, JIT grants, daemon sessions and web
// sessions, under the principal's lock. Every revoked principal goes to ended, so a retry re-sends the signal.
func revokeCredentials(ctx context.Context, tx pgx.Tx, principal string, ended *[]string) error {
	if err := lockPrincipal(ctx, tx, principal); err != nil {
		return err
	}
	q := db.New(tx)
	for _, revoke := range []func(context.Context, string) error{q.DeactivateTokens, q.DeactivateGrants, q.DeactivateDaemonSessions} {
		if err := revoke(ctx, principal); err != nil {
			return err
		}
	}
	n, err := q.DeactivateWebSessions(ctx, principal)
	if err == nil && n > 0 {
		err = q.DeleteEditorRequests(ctx, principal)
	}
	*ended = append(*ended, principal)
	return err
}

// signalEnded tells Kotlin, after the commit, whose credentials the write revoked.
func (h identity) signalEnded(ended *[]string) func(context.Context) error {
	return func(ctx context.Context) error {
		for _, p := range *ended {
			if err := h.sessionsEnded(ctx, p); err != nil {
				return err
			}
		}
		return nil
	}
}

type userInput struct {
	Principal   *string `json:"principal"`
	DisplayName *string `json:"displayName"`
	Email       *string `json:"email"`
	Active      *bool   `json:"active"`
}

func decodeUser(r *http.Request) (userInput, bool, error) {
	var in userInput
	if err := decodeBody(r, &in); err != nil || in.Principal == nil {
		return in, false, &managementError{code: "common.invalid_value", params: api.Params{{"field", "body"}}}
	}
	return in, in.Active == nil || *in.Active, nil
}

func userEntity(principal string) string { return audit.Entity("User", principal) }

func (h identity) createUser(w http.ResponseWriter, r *http.Request) {
	in, active, err := decodeUser(r)
	if err != nil {
		writeMutationError(w, err)
		return
	}
	var ended []string
	mutate(h.pool, w, r, http.StatusCreated, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		principal := *in.Principal
		if err := required("principal", principal); err != nil {
			return nil, err
		}
		if err := releaseTombstone(ctx, tx, principal, nil); err != nil {
			return nil, err
		}
		id, err := db.New(tx).CreateUser(ctx, db.CreateUserParams{Principal: principal, DisplayName: in.DisplayName, Email: in.Email, Active: active})
		if err != nil {
			return nil, unique(err, "principal", principal)
		}
		if !active {
			if err := revokeCredentials(ctx, tx, principal, &ended); err != nil {
				return nil, err
			}
		}
		u, err := mustUser(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		return u, audit.Admin(ctx, tx, actor, "admin.identity", userEntity(u.Principal), "create user '"+u.Principal+"'")
	}, h.signalEnded(&ended))
}

// updateUser edits a user. A rename retires the old principal (an inactive tombstone, its credentials
// revoked) and a deactivation revokes the new one's, all in the edit's transaction.
func (h identity) updateUser(w http.ResponseWriter, r *http.Request, id int64) {
	in, active, err := decodeUser(r)
	if err != nil {
		writeMutationError(w, err)
		return
	}
	var ended []string
	mutate(h.pool, w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		before, err := mustUser(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		principal := *in.Principal
		if err := required("principal", principal); err != nil {
			return nil, err
		}
		current, err := lockCurrentPrincipal(ctx, tx, id)
		if err == nil {
			err = releaseTombstone(ctx, tx, principal, &id)
		}
		if err == nil {
			err = db.New(tx).UpdateUser(ctx, db.UpdateUserParams{Principal: principal, DisplayName: in.DisplayName, Email: in.Email, Active: active, ID: id})
		}
		if err == nil && current != "" && current != principal {
			if err = db.New(tx).TombstoneUser(ctx, current); err == nil {
				err = revokeCredentials(ctx, tx, current, &ended)
			}
		}
		if err == nil && !active {
			err = revokeCredentials(ctx, tx, principal, &ended)
		}
		if err != nil {
			return nil, unique(err, "principal", principal)
		}
		after, err := mustUser(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		return after, audit.Admin(ctx, tx, actor, "admin.identity", userEntity(after.Principal),
			updateSummary("user", before.Principal, after.Principal))
	}, h.signalEnded(&ended))
}

// deprovisionUser deactivates, never deletes, and revokes the principal's credentials.
func (h identity) deprovisionUser(w http.ResponseWriter, r *http.Request, id int64) {
	var ended []string
	mutate(h.pool, w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		before, err := mustUser(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		current, err := lockCurrentPrincipal(ctx, tx, id)
		if err != nil || current == "" {
			return nil, err
		}
		if err := db.New(tx).DeactivateUser(ctx, id); err != nil {
			return nil, err
		}
		if err := revokeCredentials(ctx, tx, current, &ended); err != nil {
			return nil, err
		}
		return nil, audit.Admin(ctx, tx, actor, "admin.identity", userEntity(before.Principal), "deprovision user '"+before.Principal+"'")
	}, h.signalEnded(&ended))
}

type groupInput struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

func decodeGroup(r *http.Request) (groupInput, error) {
	var in groupInput
	if err := decodeBody(r, &in); err != nil || in.Name == nil {
		return in, &managementError{code: "common.invalid_value", params: api.Params{{"field", "body"}}}
	}
	return in, nil
}

func groupEntity(name string) string { return audit.Entity("Group", name) }

func (h identity) createGroup(w http.ResponseWriter, r *http.Request) {
	in, err := decodeGroup(r)
	if err != nil {
		writeMutationError(w, err)
		return
	}
	mutate(h.pool, w, r, http.StatusCreated, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		if err := required("name", *in.Name); err != nil {
			return nil, err
		}
		id, err := db.New(tx).CreateGroup(ctx, db.CreateGroupParams{Name: *in.Name, Description: in.Description})
		if err != nil {
			return nil, unique(err, "group", *in.Name)
		}
		g, err := getGroup(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		return g, audit.Admin(ctx, tx, actor, "admin.identity", groupEntity(g.Name), "create group '"+g.Name+"'")
	})
}

func (h identity) updateGroup(w http.ResponseWriter, r *http.Request, id int64) {
	in, err := decodeGroup(r)
	if err != nil {
		writeMutationError(w, err)
		return
	}
	mutate(h.pool, w, r, http.StatusOK, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		before, err := mutableGroup(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		if err := required("name", *in.Name); err != nil {
			return nil, err
		}
		if err := db.New(tx).UpdateGroup(ctx, db.UpdateGroupParams{Name: *in.Name, Description: in.Description, ID: id}); err != nil {
			return nil, unique(err, "group", *in.Name)
		}
		after, err := getGroup(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		return after, audit.Admin(ctx, tx, actor, "admin.identity", groupEntity(after.Name), updateSummary("group", before.Name, after.Name))
	})
}

// deleteGroup soft-deletes: memberships and role mappings stay, but the group no longer grants roles.
func (h identity) deleteGroup(w http.ResponseWriter, r *http.Request, id int64) {
	mutate(h.pool, w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		g, err := mutableGroup(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		n, err := db.New(tx).DeleteGroup(ctx, id)
		if err != nil || n == 0 {
			return nil, err
		}
		return nil, audit.Admin(ctx, tx, actor, "admin.identity", groupEntity(g.Name), "delete group '"+g.Name+"'")
	})
}

func listMembers(ctx context.Context, q dbtx, group int64) ([]groupMember, error) {
	rows, err := db.New(q).GroupMembers(ctx, group)
	if err != nil {
		return nil, err
	}
	out := make([]groupMember, len(rows))
	for i, m := range rows {
		out[i] = groupMember{m.ID, m.Principal, m.DisplayName}
	}
	return out, nil
}

func listGroupRoles(ctx context.Context, q dbtx, group int64) ([]groupRole, error) {
	rows, err := db.New(q).RolesOfGroup(ctx, group)
	if err != nil {
		return nil, err
	}
	out := make([]groupRole, len(rows))
	for i, r := range rows {
		out[i] = groupRole{r.ID, r.Name}
	}
	return out, nil
}

func (h identity) members(w http.ResponseWriter, r *http.Request, id int64) {
	ctx := r.Context()
	_, err := getGroup(ctx, h.pool, id)
	var out []groupMember
	if err == nil {
		out, err = listMembers(ctx, h.pool, id)
	}
	if err != nil {
		writeMutationError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, out)
}

func (h identity) groupRoles(w http.ResponseWriter, r *http.Request, id int64) {
	ctx := r.Context()
	_, err := getGroup(ctx, h.pool, id)
	var out []groupRole
	if err == nil {
		out, err = listGroupRoles(ctx, h.pool, id)
	}
	if err != nil {
		writeMutationError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, out)
}

func decodeID(r *http.Request, field string) (int64, error) {
	var in map[string]*int64
	if err := decodeBody(r, &in); err != nil || in[field] == nil {
		return 0, &managementError{code: "common.invalid_value", params: api.Params{{"field", "body"}}}
	}
	return *in[field], nil
}

func (h identity) addMember(w http.ResponseWriter, r *http.Request, id int64) {
	userID, err := decodeID(r, "userId")
	if err != nil {
		writeMutationError(w, err)
		return
	}
	mutate(h.pool, w, r, http.StatusCreated, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		g, err := mutableGroup(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		u, err := mustUser(ctx, tx, userID)
		if err != nil {
			return nil, err
		}
		n, err := db.New(tx).AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: id, UserID: userID})
		if err != nil {
			return nil, err
		}
		if n > 0 {
			if err := audit.Admin(ctx, tx, actor, "admin.identity", groupEntity(g.Name), "add '"+u.Principal+"' to group '"+g.Name+"'"); err != nil {
				return nil, err
			}
		}
		members, err := listMembers(ctx, tx, id)
		for _, m := range members {
			if m.UserID == userID {
				return m, err
			}
		}
		return nil, err
	})
}

func pathInt(r *http.Request, name string) (int64, bool) {
	n, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	return n, err == nil
}

func (h identity) removeMember(w http.ResponseWriter, r *http.Request, id int64) {
	userID, ok := pathInt(r, "userId")
	if !ok {
		api.WriteError(w, http.StatusBadRequest, "common.bad_id", nil)
		return
	}
	mutate(h.pool, w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		g, err := mutableGroup(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		u, err := mustUser(ctx, tx, userID)
		if err != nil {
			return nil, err
		}
		n, err := db.New(tx).RemoveGroupMember(ctx, db.RemoveGroupMemberParams{GroupID: id, UserID: userID})
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, notFound("group member")
		}
		return nil, audit.Admin(ctx, tx, actor, "admin.identity", groupEntity(g.Name), "remove '"+u.Principal+"' from group '"+g.Name+"'")
	})
}

// lockMutableGroup row-locks the group so a single role change cannot interleave with a whole-set replace.
func lockMutableGroup(ctx context.Context, tx pgx.Tx, id int64) (string, error) {
	row, err := db.New(tx).LockGroup(ctx, id)
	source, name := row.Source, row.Name
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", notFound("group")
	case err != nil:
		return "", err
	case source == "SYSTEM":
		return "", &managementError{code: "group.system_immutable"}
	}
	return name, nil
}

func liveRole(ctx context.Context, tx pgx.Tx, id int64) (string, error) {
	name, err := db.New(tx).LiveRoleName(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", notFound("role")
	}
	return name, err
}

func (h identity) addGroupRole(w http.ResponseWriter, r *http.Request, id int64) {
	roleID, err := decodeID(r, "roleId")
	if err != nil {
		writeMutationError(w, err)
		return
	}
	mutate(h.pool, w, r, http.StatusCreated, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		group, err := lockMutableGroup(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		role, err := liveRole(ctx, tx, roleID)
		if err != nil {
			return nil, err
		}
		n, err := db.New(tx).AddGroupRole(ctx, db.AddGroupRoleParams{GroupID: id, RoleID: roleID})
		if err == nil && n > 0 {
			err = audit.Admin(ctx, tx, actor, "admin.identity", groupEntity(group), "add role '"+role+"' to group '"+group+"'")
		}
		return groupRole{roleID, role}, err
	})
}

func (h identity) removeGroupRole(w http.ResponseWriter, r *http.Request, id int64) {
	roleID, ok := pathInt(r, "roleId")
	if !ok {
		api.WriteError(w, http.StatusBadRequest, "common.bad_id", nil)
		return
	}
	mutate(h.pool, w, r, http.StatusNoContent, func(ctx context.Context, tx pgx.Tx, actor audit.Actor) (any, error) {
		group, err := lockMutableGroup(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		role, err := liveRole(ctx, tx, roleID)
		if err != nil {
			return nil, err
		}
		n, err := db.New(tx).RemoveGroupRole(ctx, db.RemoveGroupRoleParams{GroupID: id, RoleID: roleID})
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, notFound("group role mapping")
		}
		return nil, audit.Admin(ctx, tx, actor, "admin.identity", groupEntity(group), "remove role '"+role+"' from group '"+group+"'")
	})
}
