package grpcsvc

// GrpcTempOverlayTest — 5 cases, pure (10-grpc.md §4). It targets [editorTempOverlay] directly, and
// 10-grpc.md §3.1 calls it "the cheapest possible signal on the two gates": an overlay column is read
// WITHOUT a Cedar grant and skips the uncovered-scan gate, so only genuine session temps may reach it.

import (
	"testing"

	enginepb "github.com/ridi-oss/proxy-monster/analyzer/probe/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/datasource"
	pb "github.com/ridi-oss/proxy-monster/controlplane/internal/pb"
	"github.com/ridi-oss/proxy-monster/controlplane/internal/query"
)

func tempCol(schema, table, column, sqlType string, ordinal int32) *pb.TempColumn {
	return &pb.TempColumn{Schema: schema, Table: table, Column: column, SqlType: sqlType, Ordinal: ordinal}
}

// TestTempOverlayMapsAGenuineSessionTemp is case 1: on the EDITOR channel a pg_temp_N column becomes
// a catalog row with IsTemp set, dataType AND sqlType both taken from the proxy's sql_type, nullable
// hard-coded true, and no classification.
func TestTempOverlayMapsAGenuineSessionTemp(t *testing.T) {
	got, err := editorTempOverlay(
		query.ChannelEditor,
		[]*pb.TempColumn{tempCol("pg_temp_3", "scratch", "id", "int4", 1)},
		enginepb.Engine_POSTGRES, "appdb",
	)
	if err != nil {
		t.Fatalf("editorTempOverlay: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("overlay = %v, want one row", got)
	}
	want := datasource.CatalogColumn{
		Catalog: "appdb", Schema: "pg_temp_3", Table: "scratch", Column: "id",
		DataType: "int4", SQLType: "int4", Ordinal: 1, Nullable: true, IsTemp: true,
	}
	if got[0] != want {
		t.Errorf("overlay row =\n  %+v\nwant\n  %+v", got[0], want)
	}
	if got[0].Classification != nil {
		t.Error("a temp is UNCLASSIFIED by construction; classification must stay nil")
	}
}

// TestTempOverlayDropsEverythingOffTheEditorChannel is the CHANNEL gate (INV-A10-16).
//
// 🔒 Temps are only legitimate on the editor path, where a persistent session holds the backend
// connection whose temps these are. A wire / approver-exec decision carrying temp_columns is a buggy
// or compromised proxy: DROP THEM ALL rather than grant the unmask on a channel that was never
// analyzed for it.
func TestTempOverlayDropsEverythingOffTheEditorChannel(t *testing.T) {
	temps := []*pb.TempColumn{tempCol("pg_temp_3", "scratch", "id", "int4", 1)}
	for _, ch := range []query.Channel{
		query.ChannelWire, query.ChannelWorkflowExecutor, query.ChannelWorkflowViewer, query.ChannelMCP,
	} {
		got, err := editorTempOverlay(ch, temps, enginepb.Engine_POSTGRES, "appdb")
		if err != nil {
			t.Fatalf("editorTempOverlay(%s): %v", ch, err)
		}
		if len(got) != 0 {
			t.Errorf("channel %s produced %d overlay rows, want 0", ch, len(got))
		}
	}
}

// TestTempOverlayDropsANonPgTempSchema is the SECOND gate (INV-A10-16).
//
// 🔒 An overlay entry names a schema read UNMASKED, so it must be an actual session-temp namespace.
// Without this a proxy could unmask a real table — public.users here — simply by mislabeling it a
// temp. Postgres reserves the `pg_` prefix, so no real schema is ever named pg_temp*.
func TestTempOverlayDropsANonPgTempSchema(t *testing.T) {
	got, err := editorTempOverlay(
		query.ChannelEditor,
		[]*pb.TempColumn{
			tempCol("public", "users", "rrn", "varchar", 1),
			tempCol("pg_temporary", "t", "c", "int4", 1), // prefix match: this one is KEPT
			tempCol("pg_temp_9", "t", "c", "int4", 1),
		},
		enginepb.Engine_POSTGRES, "appdb",
	)
	if err != nil {
		t.Fatalf("editorTempOverlay: %v", err)
	}
	for _, row := range got {
		if row.Schema == "public" {
			t.Fatal("public.users survived the pg_temp filter — a real table could be read unmasked")
		}
	}
	if len(got) != 2 {
		t.Fatalf("overlay = %v, want the two pg_temp* rows (the filter is a plain PREFIX test, not pg_temp_<N>)", got)
	}
}

// TestTempOverlayFilterIsCaseSensitive pins F31, the DEFECT, not the tidy behaviour.
//
// ⚠️ This filter is case-SENSITIVE while A5's freshness gate over the SAME request's search_path is
// case-INSENSITIVE. A `PG_TEMP_9` entry is therefore excluded from the fragments the gate requires
// while its temp columns are dropped here. Postgres folds unquoted identifiers to lower case so a
// correct proxy never produces this, and the divergence resolves fail-closed — but a Go port must pick
// one casing rule DELIBERATELY for both call sites rather than transliterate the mismatch. Changing
// this test is the deliberate act.
func TestTempOverlayFilterIsCaseSensitive(t *testing.T) {
	got, err := editorTempOverlay(
		query.ChannelEditor,
		[]*pb.TempColumn{tempCol("PG_TEMP_9", "scratch", "id", "int4", 1)},
		enginepb.Engine_POSTGRES, "appdb",
	)
	if err != nil {
		t.Fatalf("editorTempOverlay: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("overlay = %v, want 0 rows: the prefix test is case-SENSITIVE (F31)", got)
	}
}

// TestTempOverlayPinsTheMysqlCatalogSegment is case 5, and its Kotlin comment says why it exists at
// all: "MySQL never actually sends temps (they're invisible to information_schema), but if it did the
// catalog segment must be `def`."
//
// INV-A10-7 — a mismatched catalog segment silently makes every temp key un-matchable against the
// base-catalog keys, which is a broken feature rather than a loud failure.
func TestTempOverlayPinsTheMysqlCatalogSegment(t *testing.T) {
	got, err := editorTempOverlay(
		query.ChannelEditor,
		[]*pb.TempColumn{tempCol("pg_temp_1", "t", "c", "int", 1)},
		enginepb.Engine_MYSQL, "appdb",
	)
	if err != nil {
		t.Fatalf("editorTempOverlay: %v", err)
	}
	if len(got) != 1 || got[0].Catalog != "def" {
		t.Fatalf("overlay = %v, want the MySQL catalog segment to be pinned to \"def\"", got)
	}
}

// TestTempOverlayIsEmptyWithoutTemps covers the two short-circuits.
func TestTempOverlayIsEmptyWithoutTemps(t *testing.T) {
	got, err := editorTempOverlay(query.ChannelEditor, nil, enginepb.Engine_POSTGRES, "appdb")
	if err != nil {
		t.Fatalf("editorTempOverlay: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("overlay = %v, want empty", got)
	}
}
