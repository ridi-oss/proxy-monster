// cedar-diff asks the Kotlin and Go Cedar engines the same questions over every principal, action,
// resource and requester IP a store holds, and prints each disagreement. Point it at a running Kotlin
// control plane started with PM_CP_INTERNAL_TOKEN and at that control plane's store.
//
//	cedar-diff -kotlin http://127.0.0.1:18090 -token "$PM_CP_INTERNAL_TOKEN"
package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/ridi-oss/proxy-monster/cpgo/authz"
	"github.com/ridi-oss/proxy-monster/cpgo/bridge"
	"github.com/ridi-oss/proxy-monster/cpgo/store"
	"github.com/ridi-oss/proxy-monster/cpgo/store/db"
)

var actions = []string{
	"admin.datasources", "admin.policies", "admin.identity", "task.approve", "task.request", "task.read",
	"task.assume", "task.cancel", "task.delete", "grant.revoke", "token.mint", "token.list", "token.revoke",
	"audit.read", "result.read.unmasked", "result.read.masked", "result.cap", "datasource.connect",
	"native.invoke", "exception.unanalyzable", "exception.unmaskable",
}

var ips = []string{"", "203.0.113.10", "10.1.2.3", "198.51.100.7", "::1", "2001:db8::5", "not-an-ip"}

func main() {
	kotlinURL := flag.String("kotlin", "http://127.0.0.1:18090", "Kotlin control plane base URL")
	token := flag.String("token", os.Getenv("PM_CP_INTERNAL_TOKEN"), "the Kotlin child's PM_CP_INTERNAL_TOKEN")
	flag.Parse()
	ctx := context.Background()
	pool, err := store.Open(ctx, env("PM_DB_URL", "jdbc:postgresql://localhost:5432/proxymonster"),
		env("PM_DB_USER", "proxymonster"), env("PM_DB_PASSWORD", "proxymonster"))
	if err != nil {
		fail(err)
	}
	u, err := url.Parse(*kotlinURL)
	if err != nil {
		fail(err)
	}
	kotlin := bridge.New(u, *token)
	local := authz.Local{Engine: authz.New(pool), Kotlin: kotlin}

	q := db.New(pool)
	principals := must(q.CedarDiffPrincipals(ctx))
	principals = append(principals, "nobody@example.com")
	resources := []bridge.Resource{bridge.System, bridge.AuditLog}
	for _, p := range principals {
		resources = append(resources, bridge.AuditRecord(p))
		for _, kind := range []string{"", "SESSION", "USER", "EDITOR"} {
			resources = append(resources, bridge.Resource{Type: "Token", Principal: p, Kind: kind})
		}
	}
	for _, r := range must(q.CedarDiffRequests(ctx)) {
		resources = append(resources, bridge.Resource{Type: "ApprovalRequest", Principal: r.Principal, Approver: r.DecidedBy,
			DatasourceName: r.DatasourceName, RoleName: r.RoleName, ExecutedBy: r.ExecutedBy})
	}
	for _, g := range must(q.CedarDiffGrants(ctx)) {
		resources = append(resources, bridge.Resource{Type: "AccessGrant", Principal: g.Principal, ID: g.ID, RoleName: &g.Name})
	}
	datasources := must(q.CedarDiffDatasources(ctx))

	checked, mismatches, allows := 0, 0, 0
	for _, p := range principals {
		for _, ip := range ips {
			for _, a := range actions {
				for _, r := range resources {
					kok, kreason, kerr := kotlin.Authorize(ctx, p, a, r, ip)
					gok, greason, gerr := local.Authorize(ctx, p, a, r, ip)
					checked++
					if kok {
						allows++
					}
					if kerr != nil || gerr != nil || kok != gok || !authz.SameReason(kreason, greason) {
						mismatches++
						fmt.Printf("MISMATCH authorize principal=%s action=%s resource=%+v ip=%q kotlin=%v(%s, %v) go=%v(%s, %v)\n",
							p, a, r, ip, kok, kreason, kerr, gok, greason, gerr)
					}
				}
			}
			kc, kerr := kotlin.MayConnect(ctx, p, datasources, ip)
			gc, gerr := local.MayConnect(ctx, p, datasources, ip)
			checked += len(datasources)
			if kerr != nil || gerr != nil || !slices.Equal(kc, gc) {
				mismatches++
				fmt.Printf("MISMATCH may-connect principal=%s ip=%q kotlin=%v(%v) go=%v(%v)\n", p, ip, kc, kerr, gc, gerr)
			}
		}
	}
	for _, src := range append(must(q.CedarDiffPolicySources(ctx)), extraSources...) {
		kerrs, kerr := kotlin.Validate(ctx, src)
		gerrs := authz.Validate(src)
		checked++
		if kerr != nil || (len(kerrs) == 0) != (len(gerrs) == 0) {
			mismatches++
			fmt.Printf("MISMATCH validate source=%q kotlin=%v(%v) go=%v\n", src, kerrs, kerr, gerrs)
		}
	}
	fmt.Printf("checked %d decisions (%d authorize allows) over %d principals, %d actions, %d resources, %d IPs, %d datasources: %d mismatches\n",
		checked, allows, len(principals), len(actions), len(resources), len(ips), len(datasources), mismatches)
	if mismatches > 0 {
		os.Exit(1)
	}
}

// extraSources are policy sources beyond the store's, chosen to probe the validators' edges.
var extraSources = []string{
	`permit(principal, action == Action::"audit.read", resource);`,
	`permit(principal, action == Action::"audit.write", resource);`,
	`not cedar`,
	`permit(principal, action == Action::"audit.read", resource) when { context.nope == 1 };`,
	`permit(principal, action == Action::"audit.read", resource) when { context has requester_ip && context.requester_ip.isInRange(ip("10.0.0.0/8")) };`,
	`permit(principal, action == Action::"audit.read", resource) when { context.requester_ip.isInRange(ip("10.0.0.0/8")) };`,
	`permit(principal in Role::"analyst", action == Action::"result.read.masked", resource in Tag::"pii");`,
	`forbid(principal, action == Action::"result.read.unmasked", resource) when { resource is Column && resource.tagged };`,
	`permit(principal, action == Action::"context.tag::office", resource) when { context has requester_ip && context.requester_ip.isInRange(ip("10.0.0.0/8")) };`,
	`permit(principal, action == Action::"context.tag::office", resource) when { context.tags.contains("x") };`,
	`permit(principal, action == Action::"task.read", resource) when { resource is Request && resource.requester == principal };`,
	`permit(principal, action == Action::"task.read", resource) when { resource.requester == principal };`,
	`permit(principal, action == Action::"token.mint", resource) when { resource has kind && resource.kind == "USER" };`,
	`permit(principal, action == Action::"token.mint", resource) when { resource.kind == "USER" };`,
	`permit(principal, action in Action::"stmt.cat.read", resource);`,
	`@cap("5M") permit(principal, action == Action::"result.cap", resource);`,
	`@cap("100, 1MB/1h") permit(principal, action == Action::"result.cap", resource);`,
	`@cap("1") permit(principal, action == Action::"audit.read", resource);`,
	`permit(principal, action == Action::"result.read.unmasked", resource == Utility::"ds/SHOW_GRANTS");`,
	`permit(principal == User::"a", action == Action::"admin.policies", resource == System::"system");`,
	`permit(principal, action == Action::"admin.policies", resource == Datasource::"x");`,
	`permit(principal, action, resource) when { principal in Group::"g" };`,
	`permit(principal, action == Action::"audit.read", resource) when { datetime("2026-01-01") == datetime("2026-01-01") };`,
	`@cap("9223372036854775808") permit(principal, action == Action::"result.cap", resource);`,
}

func must[T any](v T, err error) T {
	if err != nil {
		fail(err)
	}
	return v
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "cedar-diff:", strings.TrimSpace(err.Error()))
	os.Exit(2)
}
