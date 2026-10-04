package dbtest

import "testing"

// TestDefaultImagesTrackDbSupportJson is the guard that makes db-support.json the single source of
// truth in fact and not only in prose.
//
// TestDatabases.kt:84,136 and goproxy/internal/dbtest/dbtest.go:119-121 both hardcode their default
// images with a comment pointing at db-support.json; nothing checks that the pointer is still true.
// Adding "postgres:18" to db-support.json and forgetting to move the default is a silent narrowing —
// every local run keeps covering 17 while the docs claim 18 is supported. This test turns that into a
// failure.
//
// It needs no Docker: it reads a file.
func TestDefaultImagesTrackDbSupportJson(t *testing.T) {
	support, path, err := LoadDbSupport()
	if err != nil {
		t.Fatalf("locating db-support.json: %v", err)
	}
	t.Logf("read %s", path)

	// The storage list, not the target list, is what the control plane's OWN store must track:
	// db-support.json declares PostgreSQL only under "storage" because the store SQL uses RETURNING,
	// ON CONFLICT, jsonb and :: casts.
	pg, ok := NewestSeries(support.Storage, EnginePostgres)
	if !ok {
		t.Fatal("db-support.json declares no postgres storage engine")
	}
	if defaultPostgresImage != pg.Image {
		t.Errorf("defaultPostgresImage = %q, but the newest declared storage series is %s -> %q; "+
			"a plain `go test` is not covering the version db-support.json says is newest",
			defaultPostgresImage, pg.Series, pg.Image)
	}

	// MySQL is a TARGET engine only — it is never the control plane's store.
	my, ok := NewestSeries(support.Target, EngineMySQL)
	if !ok {
		t.Fatal("db-support.json declares no mysql target engine")
	}
	if defaultMySQLImage != my.Image {
		t.Errorf("defaultMySQLImage = %q, but the newest declared target series is %s -> %q",
			defaultMySQLImage, my.Series, my.Image)
	}

	// The images the constants name must also be images whose TAG declares the series, or
	// verifySeries silently degrades to "nothing to check" and a leg can run any version at all.
	for _, tc := range []struct{ name, img, series string }{
		{"postgres", defaultPostgresImage, pg.Series},
		{"mysql", defaultMySQLImage, my.Series},
	} {
		if got := imageSeries(tc.img); got != tc.series {
			t.Errorf("%s: imageSeries(%q) = %q, want %q — the version assertion would not fire",
				tc.name, tc.img, got, tc.series)
		}
	}
}

func TestCompareSeries(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"17", "16", 1},
		{"16", "17", -1},
		{"17", "17", 0},
		{"8.4", "8.0", 1},
		// The case a string comparison gets backwards, and the reason this is not sort.Strings.
		{"10", "9", 1},
		{"8.4", "8", 1},
	}
	for _, c := range cases {
		if got := compareSeries(c.a, c.b); got != c.want {
			t.Errorf("compareSeries(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestImageSeries(t *testing.T) {
	cases := map[string]string{
		"mysql:8.0":               "8.0",
		"postgres:16-alpine":      "16",
		"postgres:17":             "17",
		"postgres:latest":         "",
		"postgres":                "",
		"localhost:5000/postgres": "", // the colon belongs to a registry port, not a tag
	}
	for img, want := range cases {
		if got := imageSeries(img); got != want {
			t.Errorf("imageSeries(%q) = %q, want %q", img, got, want)
		}
	}
}

func TestProducesResultSet(t *testing.T) {
	cases := map[string]bool{
		"SELECT 1":                                  true,
		"  select id from users":                    true,
		"WITH x AS (SELECT 1) SELECT * FROM x":      true,
		"-- a leading comment\nSELECT 1":            true,
		"/* block */ SELECT 1":                      true,
		"(SELECT 1) UNION (SELECT 2)":               true,
		"SHOW TABLES":                               true,
		"INSERT INTO users VALUES (1)":              false,
		"CREATE TABLE t (id INT)":                   false,
		"DROP TABLE IF EXISTS users":                false,
		"UPDATE users SET region = 'KR'":            false,
		"INSERT INTO users VALUES (1) RETURNING id": true,
		"DELETE FROM users RETURNING id":            true,
	}
	for query, want := range cases {
		if got := ProducesResultSet(query); got != want {
			t.Errorf("ProducesResultSet(%q) = %v, want %v", query, got, want)
		}
	}
}
