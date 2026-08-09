# Cedar partial evaluation — measured

Cedar answers "may **bob** approve request 42?" It does not answer "**who** may
approve request 42?"

Every caller in this repo asks the first question. Notifications were the first
thing to need the second one, which sent us looking at Cedar's partial
evaluation. The short version:

- Asking it in **reverse** — leave the principal unknown, get back the set of
  people — does not work. Three failure modes, two silent.
- Asking it **forward with unknowns** — keep the principal concrete, mark the
  facts we lack — does work, and is what
  [notifications.md](./notifications.md#who-can-approve) uses.

Everything below was measured by calling `cedar-java:4.3.1:uber`, the version
this repo pins, against its real native engine.

## What partial evaluation is

Leave part of a request unknown and Cedar returns a **residual**: the policy
simplified down to whatever still depends on the unknown. Like reducing
`2 + 3 + x` to `5 + x`.

The response is one of three things, and the third is the useful one:

- `Allow` / `Deny` — decided despite the hole
- a **residual** with `decision = null` — undecided, here is what is left

## The forward use — what we adopted

Keep the principal concrete and mark only what is genuinely missing. At routing
time we know who we are asking about; we do not know where they are:

```
principal    = User::"bob"                 // known — we loop over people
requester_ip = Unknown("requester_ip")     // genuinely unknown until Bob clicks
```

Against `approver AND NOT contractor AND ip in 10.0.0.0/8`:

| candidate                | result   | reading    |
| ------------------------ | -------- | ---------- |
| approver                 | residual | possible   |
| approver, but contractor | Deny     | impossible |
| not an approver          | Deny     | impossible |

Every term Cedar can settle still settles — including the negation, which is why
the contractor is correctly excluded. Only the part that truly depends on
missing facts stays open.

### Read the verdict, not the residual's contents

It is tempting to inspect which policies are unresolved and treat an undecided
_forbid_ as denying. Do not: it is both unnecessary and wrong.

Unnecessary, because Cedar already returns a definite `Deny` when a forbid fires
under every assignment of the unknowns. Anything short of `Deny` is a genuine
maybe.

Wrong, because an operator may express a restriction as a forbid conditioned on
the unknown axis — "may not approve from outside the office". That forbid is
undecided for _everyone_, so counting it as a denial skips every candidate,
including the ones who would be allowed. Measured: both approvers read `Allow`
in reality and both get skipped.

The correct question is satisfiability — could any assignment produce `Allow` —
and Cedar's verdict already answers it. `Allow` or a residual means notify;
`Deny` means skip.

### Trap: an omitted attribute is not an unknown one

```
emptyContext()                      ->  Deny, residual = false   // permit vanishes
{ requester_ip: Unknown }           ->  null, residual = isInRange(unknown(...), ...)
```

Cedar is right — "this key is absent" genuinely differs from "I don't know yet"
— but the effect is that a forgotten attribute silently drops people. Every axis
a policy might touch must be marked. Omitting the context map entirely is worse
still: the engine panics in Rust with `missing field 'context'`, surfaced as an
`AuthException`.

### Trap: one unknown un-decides `has` for every other key

A policy reading only `channel`, with `channel` supplied concretely both times:

```
{ channel: "workflow-viewer" }                          ->  Deny  (resolves)
{ channel: "workflow-viewer", requester_ip: Unknown }   ->  null  (undecided)
```

The residual shows why — Cedar models the context as one record and will not
reduce `has` while any unknown sits inside it:

```json
"has": { "left": { "Record": {
    "channel":      { "Value": "workflow-viewer" },
    "requester_ip": { "unknown": [...] }
}}}
```

`context has channel` is knowably true; no assignment of `requester_ip` could
change it. This is over-conservative, and it matters because Cedar's strict
validation _requires_ that guard — an unguarded read of an optional attribute
fails validation — so every context-conditioned policy in this repo has one. One
unknown therefore un-decides all of them at once.

Consequence: supplying more known attributes does not contain the blast radius.
The only lever is marking fewer things unknown.

## The reverse use — what we rejected

The tempting version is to leave the **principal** unknown and get everyone at
once:

```
policy:    permit(principal, action == Action::"task.approve", resource)
             when { principal in Role::"pii-approver" };

residual:  unknown("principal") in Role::"pii-approver"
```

That is close to a `WHERE` clause — one query instead of one call per person.
Boolean structure survives too: `&&`, `||`, `!`, and `in [set]` all come
through, and `principal in [roleA, roleB]` reduces to a single set membership
that would translate cleanly to SQL.

It does not work, for three reasons.

**It names nobody.** Supplying alice (in the role) and bob (not) returns the
identical residual. Cedar hands back a condition; turning it into
`SELECT principal FROM … WHERE …` is a compiler someone would have to write and
be right about.

**Only the first mention of `principal` is substituted.** Take an ordinary
policy — an approver who is not a contractor:

```
permit(principal, action == Action::"task.approve", resource)
  when { principal in Role::"pii-approver" && !(principal in Role::"contractor") };
```

The residual comes back as:

```
   unknown("principal") in Role::"pii-approver"      ← substituted
&& !( Var("principal")  in Role::"contractor" )      ← NOT substituted
```

The second mention stays a raw variable, in every multi-term case tried. A
reasonable guess is that the two are co-bound — that `Var` still refers to the
same unknown — but they are not. Re-parsing the residual with `Policy.fromJson`
and evaluating it for a concrete alice gives `Deny`, where the original policy
gives `Allow`: `unknown("principal")` stays a literal hole that no concrete
principal ever fills. The two occurrences are simply inconsistent, and a
consumer reading the bare `Var` as unconstrained would notify exactly the people
the policy forbids. **This looks like a genuine upstream bug and is worth
reporting.**

**Unmarked axes still collapse.** `resource.requester` in the self-approval
forbid was not marked unknown, so it folded to `false` and the forbid vanished —
`Deny`, no residual, no warning.

Two of those three fail silently and both lose recipients, which is the
direction a fail-closed system must not fail in.

The forward form sidesteps all of it: with the principal concrete there is no
substitution to get wrong, and the only unknowns are ones we chose and marked.

## Status

Two findings here look like genuine upstream bugs, both over-conservative
simplification: the first-occurrence substitution above, and `has` failing to
reduce for a concrete key. Both are worth reporting.

The feature is explicitly experimental upstream — no formal model, no
correctness proof, API expected to change.
[Type-aware partial evaluation](https://github.com/cedar-policy/rfcs/blob/main/text/0095-type-aware-partial-evaluation.md)
(RFC 0095) is the stable successor and worth re-measuring when it lands. The
forward use is narrow enough to be defensible today: it decides only who gets
told something is waiting, and every real authorization still runs the ordinary
full evaluation.

## What this is not

[Cedar Analysis / SymCC](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/)
is a separate, more mature toolkit — a Lean-verified symbolic compiler emitting
SMT. It answers questions about _policies_: are these two equivalent, is this
one shadowed, does this change grant anything new. It does not answer "who can
do X", so it is not an alternative here — though it is the right tool for
checking a policy edit before it ships.
