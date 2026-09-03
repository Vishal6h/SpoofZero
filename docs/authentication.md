# Email Authentication Readiness

Protected reference: `1ad4d20982e0dccde442a55ac77f4726e44607da`.

SpoofZero interprets authentication claims stored in an email. It does not run an
SPF validator, verify DKIM signatures, or perform a new DMARC evaluation. A PASS
is a reported domain-authentication outcome, not a safe-message verdict or proof
that the displayed person sent the message.

## Parsing and reporter selection

`auth_results.py` separates method results from quoted properties and nested
comments, handles folded headers and case differences, and retains raw reports,
method versions, identities, and parsing issues. Unknown result tokens remain
visible. Unsupported versions, ambiguous duplicate properties, and malformed
clauses cannot supply an interpreted PASS. Other intact clauses remain usable.

Supported results include SPF pass/fail/softfail/neutral/none/temperror/permerror,
DKIM pass/fail/none/temperror/permerror, and DMARC pass/fail/bestguesspass/none.
Additional registered policy/neutral/error values are also retained where
applicable. `bestguesspass` is explicitly heuristic, not equivalent to DMARC PASS.
Errors indicate an incomplete evaluation; they are not automatically failures.

Reports are retained in original order. Summary selection prefers an authserv-id
explicitly passed through `analyze_authentication(..., trusted_authserv_ids=[...])`,
then an exact match to the newest Received header's `by` host, then the first
report as an untrusted fallback. No uploaded field configures trust. The normal
pipeline supplies no trusted IDs. Headers from the selected named reporter may
be combined because receivers can write separate headers for separate checks.
Other reporters remain inspectable and cannot fill missing checks or overwrite
selected results. Same-reporter conflicts become `mixed`, rather than preferring
PASS. SPF MAIL FROM results take precedence over HELO-only results.

Multiple DKIM results retain each signing domain. Distinct, identified signatures
can yield an aggregate DKIM PASS when one passes; an aligned failed signature
cannot supply alignment for another passing signature. Conflicting results for
the same domain do not supply positive alignment evidence. Unknown signature
results remain visible as mixed evidence.

## Confidence and identity evidence

Receiver matching is a heuristic. Received and Authentication-Results headers can
both be forged in an uploaded EML. Configured/inferred reporter associations have
at most medium confidence; unmatched reporters have low confidence and missing
reports have none. Malformed selected reports reduce confidence. These labels do
not authenticate the header's origin or confirm receiver sanitization. This
boundary follows the trust considerations in [RFC 8601](https://www.rfc-editor.org/rfc/rfc8601.html).

The analyzer extracts SPF `smtp.mailfrom` / `envelope-from`, SPF HELO, DKIM
`header.d` / `d`, and DMARC `header.from` identities. It does not substitute
Return-Path for an authenticated MAIL FROM. DKIM-Signature `d=` declarations are
stored separately as unverified domains; they are never paired speculatively
with an unspecified DKIM PASS. HELO remains context, including for null MAIL FROM,
and is not promoted to a DMARC-aligned MAIL FROM PASS.

Visible From must contain one unambiguous mailbox. Duplicate/multi-author or
malformed From evidence produces unknown alignment. A reported DMARC header.from
does not replace the visible author. Identity domains are normalized with IDNA.

`domain_alignment.py` returns exact matching and relaxed organizational comparison
using tldextract 5.3.2's bundled Public Suffix List snapshot. Network refresh and
cache access are disabled. Private suffixes are included so unrelated tenants
such as alice.github.io and bob.github.io are not aligned. Multi-label suffixes,
wildcards, and exceptions are handled. Unknown suffixes have no guessed
organizational domain; exact matches are still useful. Bare public/private
suffixes do not establish organizational alignment.

These offline comparisons are investigative heuristics. They do not recover the
historical strict/relaxed policy or implement the DNS tree walk specified by
[RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html). Snapshot age, private-domain
boundaries, historical policy, and receiver behavior can affect interpretation.
SPF/DKIM alignment differences can also arise from legitimate sending services
and forwarding; they do not prove impersonation. Sender Reply-To/Return-Path
checks now avoid mismatch points for known organizational alignment. Unknown
suffix differences retain the earlier exact-domain mismatch behavior.

## Output and scoring compatibility

Existing `authentication.spf`, `dkim`, `dmarc`, `risk_score`, and `findings` remain.
Additive fields are `reports`, `selected_report_indices`, `evidence_confidence`,
`verification`, `dns_policy_context`, `alignment`, and `evidence_state`. Reports
contain properties and identities; comparisons retain both strict and relaxed
results and the source report index. Missing/unknown evidence is not a PASS.

Existing numeric weights remain: SPF fail 30, softfail 15; DKIM fail 30, none 10;
DMARC fail 40, with a 100-point cap. Conflicting summaries retain the strongest
applicable failure weight once. Distinct DKIM signatures with a usable PASS are
not charged as if every signature had failed. New neutral/error/unknown states
add uncertainty findings rather than invented failure points. Alignment findings
do not introduce a new score bonus or duplicate sender mismatch points.

Fusion keeps its weights and bonuses. PASS never discounts sender identity, AI,
reputation, attachment, or relay evidence. Reported PASS plus any of these
existing suspicious signals emits an AUTH_PASS_SUSPICIOUS_BEHAVIOR finding in
`final_assessment.authentication_context` and the existing dashboard reasons.
A partial PASS is explicitly qualified. Domain/IP reputation can flag URL hosts;
merely having a URL is not considered suspicious. This finding does not establish
account compromise, BEC, or the sender's intent.

Below 20 points, a behavioral warning produces REVIEW REQUIRED, and otherwise
inconclusive authentication produces INCONCLUSIVE instead of LIKELY SAFE. Higher
score thresholds are unchanged. Both new labels use the dashboard's existing
amber style. Legacy saved results without the new fields still render normally;
case snapshots are not migrated. Reanalyze into a new case to preserve a fresh
snapshot because existing raw-email deduplication remains unchanged.

## Present-day DNS versus message evidence

The existing `threat_intelligence` output holds live DNS/RDAP lookup context.
`authentication.dns_policy_context` explicitly says it did not supply or overwrite
recorded authentication results. Current records may differ from records at send
time. Neither present-day records nor parsed headers establish historical DNS
policy, original SMTP client authorization, cryptographic signature validity,
message harmlessness, or account compromise.

The offline regression suite covers statuses, malformed headers, report conflicts,
source confidence, identity/alignment edge cases, offline snapshot use, behavioral
warnings, case serialization, and dashboard compatibility. The original demo
continues to score 69/100 with 58.05% NLP probability. Model artifacts, VirusTotal,
attachments, geolocation, and campaign-correlation code remain unchanged.
