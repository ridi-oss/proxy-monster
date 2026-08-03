package query_test

import (
	"testing"

	"github.com/ridi-oss/proxy-monster/controlplane/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
)

// UnmaskableGateDbTest.kt — 83 LOC, 1 case (06-query-decision.md §7, step 30).
//
// The unmaskable gate's control-plane half, against real MySQL metadata + real Cedar. The query is
// maskable on the text path but NOT on MySQL's binary result path, so the proxy needs a separate
// MASK-only capability bit: the production floor leaves it false, while an explicit `sql.unmaskable`
// permit makes it true WITHOUT changing the underlying MASK verdict.
//
// 🔒 INV-A6-6 — `unmaskablePermitted` is a CAPABILITY GRANT, not permission to skip masking. A proxy
// may relay an unmaskable binary result unmasked iff this is true AND its own local feature capability
// says that relay path is supported. Two independent conditions; the control plane owns exactly one,
// and this suite pins that it is fail-closed by default and MASK-only.
func TestUnmaskableGateDb(t *testing.T) {
	fx := newEnforcementFixture(t, dbtest.EngineMySQL)
	const preparedSQL = "SELECT rrn FROM users WHERE id = ?"

	decide := func() (action pb.EnfAction, unmaskable bool, why string) {
		d := gateDecide(fx, dbtest.FixturePrincipal, preparedSQL, nil)
		return d.Action, d.UnmaskablePermitted, reason(d)
	}

	// ⚠️ ONE FUSED CASE, as in the Kotlin: the `sql.unmaskable` permit created in part 3 persists on
	// the shared fixture, so the two false observations must be made before it exists.
	t.Run("unmaskable permission is fail-closed and populated only on the final MASK path", func(t *testing.T) {
		fx.SetTags("system:production")
		floorAction, floorBit, floorWhy := decide()
		if floorAction != pb.EnfAction_MASK {
			t.Fatalf("floor action = %v, want MASK (%s)", floorAction, floorWhy)
		}
		if floorBit {
			t.Error("no sql.unmaskable permit must refuse binary relay")
		}

		// The development preset ALSO grants result.read.unmasked (-200), so the final decision is
		// ALLOW. The wire bit deliberately remains false because the proxy never consults it for an
		// ALLOW — this is the "MASK-only" half of the capability, and it is what stops a dev datasource
		// from making the bit look permanently set.
		fx.SetTags("system:development")
		devAction, devBit, devWhy := decide()
		if devAction != pb.EnfAction_ALLOW {
			t.Fatalf("development action = %v, want ALLOW (%s)", devAction, devWhy)
		}
		if devBit {
			t.Error("the capability bit is MASK-only")
		}

		// Isolate the security-critical combination: keep the PII read MASKED, but permit the
		// datasource-level unmaskable relay. This is the exact branch the binary proxy consumes.
		fx.SetTags("system:production")
		fx.AddCedarPolicy("test-mysql-binary-unmaskable",
			`permit(principal, action == Action::"sql.unmaskable", resource == Datasource::"`+fx.DatasourceName+`");`)

		permittedAction, permittedBit, permittedWhy := decide()
		if permittedAction != pb.EnfAction_MASK {
			t.Fatalf("permitted action = %v, want MASK (%s)", permittedAction, permittedWhy)
		}
		if !permittedBit {
			t.Error("MASK + sql.unmaskable permit must surface the relay capability")
		}
	})
}
