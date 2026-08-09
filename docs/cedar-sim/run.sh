#!/usr/bin/env bash
# Backs docs/approval-workflow.md Viewing the result as role R.
# Requires the cedar CLI matching the project's cedar-java (4.3.1):
#   cargo install cedar-policy-cli --version 4.3.1
set -u
cd "$(dirname "$0")"
CEDAR="${CEDAR:-$HOME/.cargo/bin/cedar}"; command -v "$CEDAR" >/dev/null || CEDAR=cedar

dec(){ # policies schema entities principal action resource ctx
  "$CEDAR" authorize --policies "$1" --schema "$2" --entities "$3" \
    --principal "$4" --action "Action::\"$5\"" --resource "$6" --context "$7" 2>&1 \
    | grep -oE 'ALLOW|DENY' | head -1; }
row(){ printf "  %-46s -> %-5s (want %s) %s\n" "$1" "$2" "$3" "$([ "$2" = "$3" ] && echo ok || echo FAIL)"; }

echo "### (A) now AND (B) later share this: the viewer HOLDS role R; R's own grants decide ###"
echo "# role-grants.cedar = pii-reader: masked pii anywhere, unmasked pii when segregated"
R=roles.cedarschema P=role-grants.cedar COL='Column::"users.ssn"'
row "read.unmasked from open net"   "$(dec $P $R entities-assumed.json 'User::"requester"' result.read.unmasked "$COL" ctx-open.json)"       DENY
row "read.unmasked from segregated" "$(dec $P $R entities-assumed.json 'User::"requester"' result.read.unmasked "$COL" ctx-segregated.json)" ALLOW
row "read.masked   from open net"   "$(dec $P $R entities-assumed.json 'User::"requester"' result.read.masked   "$COL" ctx-open.json)"       ALLOW
row "no assumed role -> unmasked"   "$(dec $P $R entities-none.json    'User::"requester"' result.read.unmasked "$COL" ctx-segregated.json)" DENY
echo "  => ssn: MASKED from open net, CLEARTEXT from segregated — identical for (A) and (B);"
echo "     the only difference is HOW the viewer gets R (view-time union vs a result-scoped grant)."

echo
echo "### why not a single 'meta' policy: Cedar can't reference request.role's condition -> LEAKS ###"
Rm=naive-model.cedarschema P=naive-c-leaks.cedar E=entities-naive.json
naive=$(dec $P $Rm $E 'User::"requester"' result.viewUnmasked 'ResultColumn::"req1-ssn"' ctx-open.json)
printf "  %-46s -> %-5s  %s\n" "naive single policy, ssn open net" "$naive" \
  "$([ "$naive" = ALLOW ] && echo 'LEAK (expected): no meta-authorization — hence A/B rely on R-membership' || echo unexpected)"

echo
echo "### audit.read — ONE action, own-record (condition) vs whole-log (collection, auditor-only) ###"
A=audit.cedarschema P=audit-policies.cedar E=audit-entities.json
ad(){ "$CEDAR" authorize --policies $P --schema $A --entities $E --principal "$1" --action 'Action::"audit.read"' --resource "$2" --context ctx-empty.json 2>&1 | grep -oE 'ALLOW|DENY' | head -1; }
row "alice reads her own record"    "$(ad 'User::"alice"' 'AuditRecord::"rec-alice"')" ALLOW
row "alice reads bob's record"      "$(ad 'User::"alice"' 'AuditRecord::"rec-bob"')"   DENY
row "alice reads the WHOLE log"     "$(ad 'User::"alice"' 'AuditLog::"all"')"          DENY
row "auditor reads any record"      "$(ad 'User::"bob"'   'AuditRecord::"rec-alice"')" ALLOW
row "auditor reads the WHOLE log"   "$(ad 'User::"bob"'   'AuditLog::"all"')"          ALLOW
