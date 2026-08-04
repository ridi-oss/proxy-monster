package identity

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ridi-oss/proxy-monster/gocp/internal/dbtest"
	"github.com/ridi-oss/proxy-monster/gocp/internal/store"
	"github.com/ridi-oss/proxy-monster/gocp/internal/types"
)

// ---------------------------------------------------------------------------------------------
// 🔴 EVERY CASE HERE IS NEW. `UserGroupStore`'s group half is exercised in the Kotlin only through
// SCIM and admin route suites; there is no store-level test to migrate, and A11's three SYSTEM
// guards sit directly on top of these four statements.
// ---------------------------------------------------------------------------------------------

type crudFixture struct {
	t     testing.TB
	ctx   context.Context
	db    *store.Db
	seed  *dbtest.Seed
	store *UserGroupStore
}

func newCrudFixture(t testing.TB) *crudFixture {
	t.Helper()
	db, _ := dbtest.MigratedStore(t)
	return &crudFixture{
		t: t, ctx: context.Background(), db: db,
		seed: dbtest.NewSeed(t, db), store: NewUserGroupStore(db.Pool),
	}
}

func (f *crudFixture) systemGroup(name string) int64 {
	f.t.Helper()
	var id int64
	if err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO app_group (name, source) VALUES ($1, 'SYSTEM') RETURNING id`, name).Scan(&id); err != nil {
		f.t.Fatalf("seed SYSTEM group %s: %v", name, err)
	}
	return id
}

// 🔒 F34 — `isSystemGroup` keys on the `source` COLUMN, never on the `system:` name prefix.
// V8__seed.sql seeds SEVEN SYSTEM groups; a name-based guard would protect one and leave six mutable,
// and a group named `system:*` that is NOT source=SYSTEM must stay mutable.
//
// BootstrapAdminDbTest case 4 is the seeded-vs-user-created pair, over BOTH predicates: `isSystemGroup`
// (id-keyed, the admin paths) and `isSystemGroupByName` (name-keyed, which is what the SCIM POST upsert
// resolves by, since it matches an existing group on displayName).
// KT: BootstrapAdminDbTest.kt#isSystemGroup distinguishes the seeded system group from a user-created one
func TestIsSystemGroupKeysOnTheColumnAndNotOnTheNamePrefix(t *testing.T) {
	f := newCrudFixture(t)

	// A SYSTEM group whose name looks perfectly ordinary.
	plainlyNamed := f.systemGroup("engineering-ops")
	system, err := f.store.IsSystemGroup(f.ctx, plainlyNamed)
	if err != nil || !system {
		t.Errorf("a source=SYSTEM group must be system whatever it is called: %v %v", system, err)
	}

	// A LOCAL group whose name starts with the reserved prefix.
	prefixed := f.seed.Group("system:looks-official")
	system, err = f.store.IsSystemGroup(f.ctx, prefixed)
	if err != nil || system {
		t.Errorf("a source=LOCAL group must be mutable whatever it is called: %v %v", system, err)
	}

	// A missing row is FALSE, not an error — the callers check existence separately.
	system, err = f.store.IsSystemGroup(f.ctx, 987654321)
	if err != nil || system {
		t.Errorf("a missing row must answer false with no error: %v %v", system, err)
	}

	// All seven seeded SYSTEM groups, by the column.
	rows, err := f.db.Pool.Query(f.ctx, `SELECT id, name FROM app_group WHERE source='SYSTEM' AND id <> $1`, plainlyNamed)
	if err != nil {
		t.Fatalf("read seeded groups: %v", err)
	}
	defer rows.Close()
	seeded := 0
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seeded++
		if got, err := f.store.IsSystemGroup(f.ctx, id); err != nil || !got {
			t.Errorf("seeded SYSTEM group %q must be protected: %v %v", name, got, err)
		}
	}
	if seeded != 7 {
		t.Errorf("V8__seed.sql seeds 7 SYSTEM groups; found %d — F34's premise changed", seeded)
	}

	// ---- isSystemGroupByName, the SCIM-upsert-side predicate on the same column.
	byName := func(name string) bool {
		t.Helper()
		got, err := f.store.IsSystemGroupByName(f.ctx, name)
		if err != nil {
			t.Fatalf("isSystemGroupByName(%q): %v", name, err)
		}
		return got
	}
	// The seeded admin group, by name — the case BootstrapAdminDbTest names explicitly.
	if !byName("system:admin") {
		t.Error("isSystemGroupByName(system:admin) = false: the SCIM upsert would then be able to " +
			"hijack the seeded admin group by pushing a Group whose displayName is system:admin")
	}
	// A user-created group is not protected, whatever it is called…
	f.seed.Group("eng")
	if byName("eng") {
		t.Error("isSystemGroupByName(eng) = true, want false — a user-created group stays mutable")
	}
	// …including one that borrowed the reserved-looking prefix, because the COLUMN is the predicate.
	if byName("system:looks-official") {
		t.Error("isSystemGroupByName keyed on the NAME PREFIX, not on source — a source=LOCAL group " +
			"called system:* must stay mutable (F34)")
	}
	// A name no group has is false rather than an error.
	if byName("no-such-group") {
		t.Error("isSystemGroupByName(absent) = true, want false")
	}
	// And the plainly-named SYSTEM group is protected by name too: the two predicates agree.
	if !byName("engineering-ops") {
		t.Error("isSystemGroupByName disagreed with isSystemGroup on a source=SYSTEM group whose name " +
			"looks ordinary — the two guards must key on the same column")
	}
}

// The two `SELECT … FOR UPDATE` reads A11's guards #2 and #3 call. They are separate statements —
// one keyed on the id, one on the NAME and also returning the id — because the Kotlin keeps them
// separate (INV-A11-32 counts three mechanisms, not one shared helper).
func TestTheTwoLockingSourceReadsAgreeOnSourceAndOnAbsence(t *testing.T) {
	f := newCrudFixture(t)
	localID := f.seed.Group("engineering")
	systemID := f.systemGroup("protected-group")

	source, found, err := f.store.LockMutableGroupSource(f.ctx, f.db.Pool, localID)
	if err != nil || !found || source != "LOCAL" {
		t.Errorf("by id, LOCAL: got (%q,%v,%v)", source, found, err)
	}
	source, found, err = f.store.LockMutableGroupSource(f.ctx, f.db.Pool, systemID)
	if err != nil || !found || source != SystemSource {
		t.Errorf("by id, SYSTEM: got (%q,%v,%v)", source, found, err)
	}
	_, found, err = f.store.LockMutableGroupSource(f.ctx, f.db.Pool, 987654321)
	if err != nil || found {
		t.Errorf("by id, absent: got (%v,%v)", found, err)
	}

	id, source, found, err := f.store.LockMutableGroupSourceByName(f.ctx, f.db.Pool, "protected-group")
	if err != nil || !found || source != SystemSource || id != systemID {
		t.Errorf("by name, SYSTEM: got (%d,%q,%v,%v)", id, source, found, err)
	}
	_, _, found, err = f.store.LockMutableGroupSourceByName(f.ctx, f.db.Pool, "no-such-group")
	if err != nil || found {
		t.Errorf("by name, absent: got (%v,%v)", found, err)
	}
}

// The reads the management layer projects: a group carries its member count and its roles, a user
// carries its groups, and both lists are ordered by name / principal.
func TestGroupAndUserReadsJoinTheirRelationsAndOrderThem(t *testing.T) {
	f := newCrudFixture(t)
	eng := f.seed.Group("engineering")
	ops := f.seed.Group("aaa-ops")
	alice := f.seed.User("alice@example.com")
	bob := f.seed.User("bob@example.com")
	f.seed.GroupMember(eng, alice)
	f.seed.GroupMember(eng, bob)
	f.seed.GroupMember(ops, alice)
	f.seed.GroupRole(eng, f.seed.Role("zeta"))
	f.seed.GroupRole(eng, f.seed.Role("alpha"))

	group, err := f.store.GetGroupByName(f.ctx, "engineering")
	if err != nil || group == nil {
		t.Fatalf("getGroupByName: %v %v", group, err)
	}
	if group.MemberCount != 2 {
		t.Errorf("memberCount: got %d, want 2", group.MemberCount)
	}
	if len(group.Roles) != 2 || group.Roles[0].Name != "alpha" || group.Roles[1].Name != "zeta" {
		t.Errorf("roles must be ORDER BY r.name: got %+v", group.Roles)
	}

	// The re-read order matters: setGroupRoles returns these names and the console renders them.
	groups, err := f.store.ListGroups(f.ctx)
	if err != nil {
		t.Fatalf("listGroups: %v", err)
	}
	// Seven seeded SYSTEM groups plus query-approvers plus the two here.
	if len(groups) != 10 {
		t.Fatalf("listGroups: got %d groups, want 10", len(groups))
	}
	if groups[0].Name != "aaa-ops" {
		t.Errorf("listGroups must be ORDER BY name: first is %q", groups[0].Name)
	}

	user, err := f.store.GetUserByPrincipal(f.ctx, "alice@example.com")
	if err != nil || user == nil {
		t.Fatalf("getUserByPrincipal: %v %v", user, err)
	}
	if len(user.Groups) != 2 || user.Groups[0].Name != "aaa-ops" {
		t.Errorf("user groups must be ORDER BY g.name: got %+v", user.Groups)
	}
	if user.CreatedAt == "" {
		t.Errorf("createdAt must be rendered as a Java Instant string")
	}

	missing, err := f.store.GetUserByPrincipal(f.ctx, "nobody@example.com")
	if err != nil || missing != nil {
		t.Errorf("an unknown principal is (nil, nil): got %v %v", missing, err)
	}
}

// The group write half, including the two idempotent inserts the management layer depends on.
func TestGroupWritesRoundTripAndTheJoinInsertsAreIdempotent(t *testing.T) {
	f := newCrudFixture(t)
	userID := f.seed.User("alice@example.com")
	roleID := f.seed.Role("reader")

	created, err := f.store.CreateGroup(f.ctx, AppGroupInput{Name: "engineering", Description: ptrString("eng")})
	if err != nil {
		t.Fatalf("createGroup: %v", err)
	}
	if created.Source != "LOCAL" {
		t.Errorf("a group created here is LOCAL by construction, got %q", created.Source)
	}

	added, err := f.store.AddMember(f.ctx, created.ID, userID)
	if err != nil || !added {
		t.Errorf("addMember: %v %v", added, err)
	}
	added, err = f.store.AddMember(f.ctx, created.ID, userID)
	if err != nil || added {
		t.Errorf("a re-add is ON CONFLICT DO NOTHING ⇒ false, not an error: %v %v", added, err)
	}

	added, err = f.store.AddGroupRole(f.ctx, created.ID, roleID)
	if err != nil || !added {
		t.Errorf("addGroupRole: %v %v", added, err)
	}
	added, err = f.store.AddGroupRole(f.ctx, created.ID, roleID)
	if err != nil || added {
		t.Errorf("a re-add is ON CONFLICT DO NOTHING ⇒ false: %v %v", added, err)
	}

	updated, err := f.store.UpdateGroup(f.ctx, created.ID, AppGroupInput{Name: "eng"})
	if err != nil || updated == nil || updated.Name != "eng" {
		t.Fatalf("updateGroup: %v %v", updated, err)
	}
	if updated.Description != nil {
		t.Errorf("a nil description in the input clears the column, got %v", updated.Description)
	}
	absent, err := f.store.UpdateGroup(f.ctx, 987654321, AppGroupInput{Name: "ghost"})
	if err != nil || absent != nil {
		t.Errorf("updating an absent group is (nil, nil): got %v %v", absent, err)
	}

	// ⚠️ The delete CASCADES to group_member and group_role.
	deleted, err := f.store.DeleteGroup(f.ctx, created.ID)
	if err != nil || !deleted {
		t.Fatalf("deleteGroup: %v %v", deleted, err)
	}
	var members, roles int64
	if err := f.db.Pool.QueryRow(f.ctx,
		`SELECT (SELECT COUNT(*) FROM group_member WHERE group_id=$1),
		        (SELECT COUNT(*) FROM group_role  WHERE group_id=$1)`, created.ID).Scan(&members, &roles); err != nil {
		t.Fatalf("cascade check: %v", err)
	}
	if members != 0 || roles != 0 {
		t.Errorf("the delete must cascade: %d members, %d roles left", members, roles)
	}
	deleted, err = f.store.DeleteGroup(f.ctx, created.ID)
	if err != nil || deleted {
		t.Errorf("a second delete is false, not an error: %v %v", deleted, err)
	}
}

// ⚠️ `active: Boolean = true`, and Go's zero value is the opposite one. A body that omits `active`
// must decode to an ACTIVE user.
//
// 🔒 It matters beyond tidiness: a create with `active=false` also REVOKES that principal's existing
// credentials, so decoding an omitted `active` as false would tear down tokens and daemon sessions
// for a principal the caller only meant to register.
func TestAppUserInputDefaultsActiveToTrueWhenTheKeyIsAbsent(t *testing.T) {
	var in AppUserInput
	if err := json.Unmarshal([]byte(`{"principal":"alice@example.com"}`), &in); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !in.Active {
		t.Errorf("an omitted `active` must default to TRUE (kotlinx `active: Boolean = true`)")
	}
	if err := json.Unmarshal([]byte(`{"principal":"alice@example.com","active":false}`), &in); err != nil {
		t.Fatalf("unmarshal explicit false: %v", err)
	}
	if in.Active {
		t.Errorf("an explicit false must be honoured")
	}
	// `ignoreUnknownKeys = true` is encoding/json's default and INV-A1-4 requires it.
	if err := json.Unmarshal([]byte(`{"principal":"a","somethingElse":1}`), &in); err != nil {
		t.Errorf("an unknown key must be ignored, got %v", err)
	}
}

// INV-A1-4 on the two DTOs the management layer returns: `[]` never null, absent never null.
func TestIdentityDtosEncodeEmptyCollectionsAndOmitAbsentOptionals(t *testing.T) {
	user := AppUser{ID: 1, Principal: "alice@example.com", Source: "LOCAL", Active: true, CreatedAt: "2026-01-01T00:00:00Z"}
	got, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("marshal user: %v", err)
	}
	want := `{"id":1,"principal":"alice@example.com","source":"LOCAL","active":true,` +
		`"createdAt":"2026-01-01T00:00:00Z","groups":[]}`
	if string(got) != want {
		t.Errorf("AppUser:\n got %s\nwant %s", got, want)
	}

	group := AppGroup{ID: 2, Name: "engineering", Source: "LOCAL"}
	got, err = json.Marshal(group)
	if err != nil {
		t.Fatalf("marshal group: %v", err)
	}
	want = `{"id":2,"name":"engineering","source":"LOCAL","memberCount":0,"roles":[]}`
	if string(got) != want {
		t.Errorf("AppGroup:\n got %s\nwant %s", got, want)
	}

	// 🔒 A display name or principal carrying '<' '&' '>' must reach the console UNESCAPED — kotlinx
	// does not HTML-escape and encoding/json does, so the two runtimes would otherwise differ byte
	// for byte on any principal with an angle bracket in it.
	//
	// ⚠️ The suppression is a property of the TOP-LEVEL encoder, not of the DTO: types.MarshalWire's
	// own doc records that "encoding/json runs compact(escapeHTML) over whatever a Marshaler returns,
	// so the outer encoder always has the last word". A per-type MarshalJSON therefore cannot achieve
	// it alone, and the assertion below goes through the same helper httpapi.RespondJSON does.
	escaping := AppUser{
		ID: 1, Principal: "a<b&c", Source: "LOCAL", Active: true, CreatedAt: "2026-01-01T00:00:00Z",
		DisplayName: ptrString("A > B"),
	}
	got, err = types.MarshalWire(escaping)
	if err != nil {
		t.Fatalf("marshal escaping user: %v", err)
	}
	want = `{"id":1,"principal":"a<b&c","displayName":"A > B","source":"LOCAL","active":true,` +
		`"createdAt":"2026-01-01T00:00:00Z","groups":[]}`
	if string(got) != want {
		t.Errorf("AppUser through the wire encoder must not HTML-escape:\n got %s\nwant %s", got, want)
	}

	// ...and a bare json.Marshal of the SAME value re-escapes, which is the trap the note above
	// records. Pinned so nobody "simplifies" a response path to json.Marshal on the strength of the
	// DTO having its own MarshalJSON.
	got, err = json.Marshal(escaping)
	if err != nil {
		t.Fatalf("marshal escaping user with encoding/json: %v", err)
	}
	if string(got) == want {
		t.Errorf("expected a bare json.Marshal to HTML-escape — if it no longer does, "+
			"types.MarshalWire's reason for existing has changed: %s", got)
	}
}

func ptrString(s string) *string { return &s }
