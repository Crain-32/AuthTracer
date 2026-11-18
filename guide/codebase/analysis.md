# Analysis: exposures, the diff, policies and Provided facts

This page covers what AuthTracer answers from the graphs once they are scanned and linked. It starts with the
[exposures](#exposures), what a caller needs to get each endpoint and field, which everything after builds on; then
the [diff](#the-diff) of two revisions and the [diagonal escalations](#diagonal-escalation) it looks for, the diff as
[SARIF annotations](#sarif-annotations) and as an [agent report](#the-agent-report); then [policies](#policies), and
the [Provided facts](#provided-facts) people give the scan, from the files to where each kind is applied. The graphs
these read are described on [fields.md](fields.md) and [system.md](system.md).

| Question | Entry point | Result |
|---|---|---|
| What does a caller need to get this field? | [`Exposures.of`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L143) | `List<Exposure>` |
| Is requirement B weaker than A? | [`Clauses.compare`](../../src/main/java/dev/crain/authtracer/diff/Clauses.java#L309) | `SAME`, `STRONGER`, `WEAKER`, `INCOMPARABLE` |
| Did this change weaken authorization? | [`GraphDiff.compare`](../../src/main/java/dev/crain/authtracer/diff/GraphDiff.java#L46) | [`DiffReport`](../../src/main/java/dev/crain/authtracer/diff/DiffReport.java#L17) |
| Where in the code is each change? | [`SarifReport.write`](../../src/main/java/dev/crain/authtracer/diff/SarifReport.java#L62), [`AgentReport.write`](../../src/main/java/dev/crain/authtracer/diff/AgentReport.java#L29) | SARIF JSON, text for an agent |
| Does every field and endpoint meet its policy? | [`Policies`](../../src/main/java/dev/crain/authtracer/diff/Policies.java#L51), through `Exposures.of` | `Exposure.violations` |

## Exposures

**Feature:** [`EXPOSURES`](features.md#exposures)

For every endpoint, and every field of its response, the checks a caller passes to get it, through every service on
the way, the fields its value comes from (its sources), the labels it inherits from them and the lineage that leads
there. The combined requirement reads as one line, `SCOPE_employees.read and ROLE_ADMIN`.

### How it works

1. **Callers.** [`GraphDiff.compare`](../../src/main/java/dev/crain/authtracer/diff/GraphDiff.java#L46) (both sides), the
   `exposures` and `policies` commands in [`DiffCommands`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L40),
   and the API's [`ExposureView.of`](../../src/main/java/dev/crain/authtracer/api/ExposureView.java#L43)
   (`GET /api/system/exposures`, `POST /api/exposures`) all call
   [`Exposures.of`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L143) on a system graph; one service's
   graph is wrapped with `SystemGraph.of`. It builds the [`Policies`](../../src/main/java/dev/crain/authtracer/diff/Policies.java#L51)
   once and attaches each exposure's violations (see [policies](#policies)).
2. **The path's checks.** For each Ingress of each service, `checks` reads the path in order
   (`ApplicationGraph.path`): a FIELD check is kept by the field it guards, and noted when it answers a denied caller
   rather than throwing; any other check is a request step unless it runs on some branches only (decision 0027); each
   Egress is kept for the fields that cross it. The endpoint itself is the first exposure, its field empty, with the
   request steps.
3. **The response's fields.** `responseFields` walks the response type's Field nodes by JSON path (`pets[].name`, a
   map's values as `pets.*.name`), enclosing fields first, leaving out what isn't written: GraphQL fields the schema
   doesn't have, fields outside the handler's `@JsonView`s, and masked values this endpoint never hands out
   (`notHandedOut`).
4. **Each field, back to its sources.** `trace` follows a field backwards:
   - it collects the field's labels (`Trace.label`) and, while the checks count, its field checks;
   - a declassified field (a Provided fact) is its own source, and the trace stops there;
   - the LOCAL flows into it on this path are followed, a MASKED one with `PathChecks.throwing` (the checks that
     answer a denied caller don't stand in front of what they answer with, decision 0076);
   - a field nothing on this path fills continues across a call (`acrossLinks`), a message (`acrossMessages`) or a
     listener's writes (`acrossWrites`), else it is a root source.
5. **Across a call** (`acrossLinks`). For each Egress on the path with a response, the links from it lead to the
   called endpoints; the NETWORK flows on that Egress say which of their fields this one came from. The called
   endpoint's request steps count only when the call relays the caller's token
   ([`Credentials.callerChecked`](../../scanner/src/main/java/dev/crain/authtracer/graph/Credentials.java#L38), decision 0021):
   with the service's own token, fixed credentials or none, they check the calling service. The trace continues in
   the called service on that endpoint's path, with its field checks. When one call may reach several endpoints,
   `join` makes their steps one step that asks what the weakest asks.
6. **Across a message** (`acrossMessages`, decision 0090). A field a listener received continues in each sender,
   where the send's payload was built; a message carries no caller (decision 0044), so nothing there counts.
7. **Across a listener's writes** (`acrossWrites`, decision 0098). A field nothing on this path fills, that a listener
   of this service writes from what it received, continues on the listener's path and from there to its senders and
   to what its own calls returned; again nothing on the way counts for this field's readers, but its sources and
   labels do.
8. **The exposure.** A field's steps are the request steps, then its enclosing field's steps (a nested field isn't
   sent without its parent), then what the trace found, each location once (`addStep`). The
   [`Exposure`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L61) holds them with the sources, labels, the
   fields that carried each label (`labelledBy`) and the lineage.
9. **One requirement.** `Exposure.clauses` turns the steps' requirements into
   [`Clauses`](../../src/main/java/dev/crain/authtracer/diff/Clauses.java#L23), a conjunction: `permitAll` and `anonymous`
   ask nothing, `authenticated`, `fullyAuthenticated`, `rememberMe` and `denyAll` are one clause each, an any-of
   authorities check is one `ANY` clause, an all-of check one per authority, and `and` joins its operands. An `or` is
   its weakest branch when every other branch implies it, one `ANY` when every branch is one, else `OPAQUE`, as are
   `not` and expressions the scan couldn't reduce. `Clauses.describe` writes them as one line, after `simplify` drops
   the clauses others imply.

### Relies on / relied on by

- **Relies on** [`REQUIREMENTS`](features.md#requirements) (each check's normalized requirement, with the role
  hierarchy already applied), [`FIELD_LINEAGE`](features.md#field_lineage), [`SYSTEM_GRAPH`](features.md#system_graph),
  [`CALL_CREDENTIALS`](features.md#call_credentials) (which calls carry the caller's checks),
  [`FIELD_CHECKS`](features.md#field_checks) and [`PROVIDED_FACTS`](features.md#provided_facts) (labels,
  declassification).
- **Relied on by** [`DIFF`](features.md#diff), [`POLICIES`](features.md#policies),
  [`EXPOSURES_VIEW`](features.md#exposures_view) ([`exposureRows.ts`](../../frontend/src/features/exposures/exposureRows.ts)),
  [`LINEAGE_VIEW`](features.md#lineage_view) and [`GRAPH_SERVER`](features.md#graph_server)
  ([`ExposureController`](../../src/main/java/dev/crain/authtracer/api/ExposureController.java#L29)).

### Tests

- [`ExposuresTests`](../../src/test/java/dev/crain/authtracer/diff/ExposuresTests.java#L24): field checks, nested fields,
  types nested twice, declassified fields, masked values, cycles.
- [`CrossServiceExposuresTests`](../../src/test/java/dev/crain/authtracer/diff/CrossServiceExposuresTests.java#L36) and
  [`CredentialsExposureTests`](../../src/test/java/dev/crain/authtracer/diff/CredentialsExposureTests.java#L31): checks
  across calls, the weakest of several endpoints, credentials that stop the caller's checks.
- [`MessageLineageFixtureTests`](../../src/test/java/dev/crain/authtracer/diff/MessageLineageFixtureTests.java#L24) and
  [`MessageFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/diff/MessageFormsFixtureTests.java#L24): across
  messages and listeners' writes.
- [`ClausesTests`](../../src/test/java/dev/crain/authtracer/diff/ClausesTests.java#L17): the strength order. Hand-built
  graphs come from [`TestGraphs`](../../src/test/java/dev/crain/authtracer/diff/TestGraphs.java#L22).
- Integration: [`AgenticRegressionTests`](../../src/integrationTest/java/dev/crain/authtracer/AgenticRegressionTests.java#L35)
  (`weakeningInEmployeeServiceShowsUpInProfileService`) and
  [`ReactiveServiceLinkTests`](../../src/integrationTest/java/dev/crain/authtracer/ReactiveServiceLinkTests.java#L21)
  (`payrollTotalInheritsEmployeeServicesChecksOnSalary`).

### Before changing it

- **A check on some branches only doesn't constrain the endpoint** (decision 0027), nor the field it guards when it
  is a field check (on the other branches the value isn't the guarded one); it stays on the path, shown as
  conditional.
- **Checks past a call count only when the call relays the caller's token** (decision 0021). Graphs scanned before
  credentials were recorded (`null`) keep counting them.
- **A field check counts only for its field and the fields under it**, never for the endpoint or its siblings.
- **Enclosing fields come first** in `responseFields`, so a field's parent's steps are known when the field is traced.
- **The strength order is `denyAll` > specific authorities > `fullyAuthenticated` > `authenticated` > nothing**, with
  `rememberMe` above `authenticated` beside `fullyAuthenticated` (decision 0105): it lets in remember-me sessions only,
  so `rememberMe` to `authenticated` lets in callers who signed in fully. A role anonymous callers hold
  (`ROLE_ANONYMOUS`) doesn't keep anyone out, and an opaque requirement is compared by its normalized structure, not
  its source text, so a role hierarchy that widens its operands shows as a change. An opaque `or` keeps its branches'
  clauses (`Clause.branches`): whoever meets one branch meets the `or`, so `X` to `X or authenticated` (a chain that
  may not be made, decision 0111) is a weakening however unreadable `X` is.
- **An opaque requirement is also compared by the code it stands for** (decision 0106): the scan gives each
  `EXPRESSION` that stands for code it doesn't read a digest of that code (`Requirement.code`, from `OpaqueCode`), and
  two with the same text but different digests can't be ranked, so changing a custom manager or the rules in a helper
  AuthTracer doesn't follow is CHANGED, for review. A graph with no digests compares by text, as before.
- **An exposure's key leaves route variables unnamed** (`Exposure.key`): renaming `{id}` to `{employeeId}` compares the
  endpoint with itself. A variable's pattern stays (`{:\d+}`, `{*}`): two mappings that differ in it are two
  endpoints. Two that still share a key are warned about, and the first is compared.

## The diff

**Feature:** [`DIFF`](features.md#diff)

Two revisions of a service, or of a system, compared exposure by exposure: each change classified as weakened,
changed, strengthened, new or removed, with the place in the code it comes from, plus the findings the new revision
has that the old one didn't. Weakened, diagonal escalations and new policy violations fail the check; changed
requirements and new findings need review.

### How it works

1. **Where it starts.** `diff` in [`DiffCommands`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L40)
   reads two graph files (`--base`, `--head`), or scans a project (`--project`) as it is and at `--base-ref` (a
   temporary git worktree, `scanRevision`) or `--base-project`; with `--context`, each side is relinked among the
   other services of a system graph (`withContext`). The Gradle task `authtracerDiff` runs it as the pull-request
   check.
2. **Comparing.** [`GraphDiff.compare`](../../src/main/java/dev/crain/authtracer/diff/GraphDiff.java#L46) computes both
   sides' exposures and indexes them by `Exposure.key`. For each exposure of the head: a policy violation the base
   exposure didn't have is a `POLICY_VIOLATION`; a new exposure goes to `newExposure` (next section); otherwise
   [`Clauses.compare`](../../src/main/java/dev/crain/authtracer/diff/Clauses.java#L309) of the two requirements makes it
   `WEAKENED`, `CHANGED` (can't be ranked, e.g. one role for another) or `STRENGTHENED`. A base exposure the head
   doesn't have is `REMOVED`, but a `HEAD` one (decision 0110: a twin only while HEAD's rules differ from GET's) is
   compared with the same route's `GET`, which HEAD runs under without a twin; a new `HEAD` twin likewise with the
   base's `GET` (`asGet`, found by `mutationTest`).
3. **Where each change is.** `locate` gives each change a
   [`DiffReport.Site`](../../src/main/java/dev/crain/authtracer/diff/DiffReport.java#L59): the first check on the head's
   path that the base didn't have (with its annotation when the mechanism is one, `@PreAuthorize`); else, when the
   first check the head no longer has is a template's, that template line (decision 0035); else the endpoint's
   handler.
4. **New findings.** `newFindings` reports each finding of the head (each service's, and the system's own as
   `(system)`) whose service, kind and message the base doesn't have, as a `NEW_FINDING` at the finding's location.
5. **The report.** [`DiffReport`](../../src/main/java/dev/crain/authtracer/diff/DiffReport.java#L17) sorts the changes by
   severity, kind, service, endpoint and field; each kind has its severity (`FAIL`, `REVIEW`, `INFO`). `failing` and
   `failed` decide the exit code (`--fail-on-review true` fails on review too); `markdown` writes the table, escaping
   each cell with [`Markdown.cell`](../../src/main/java/dev/crain/authtracer/diff/Markdown.java#L19), which the commands'
   other tables use too. `--report` writes the Markdown, `--json` the report for the UI's
   [`DiffView.tsx`](../../frontend/src/features/diff/DiffView.tsx), `--sarif` and `--agent-report` the two reports
   below.

### Relies on / relied on by

- **Relies on** [`EXPOSURES`](features.md#exposures), with their policy violations, and each graph's findings.
- **Relied on by** [`DIAGONAL_ESCALATION`](features.md#diagonal_escalation),
  [`SARIF_ANNOTATIONS`](features.md#sarif_annotations), [`AGENT_REPORT`](features.md#agent_report) and
  [`DIFF_VIEW`](features.md#diff_view).

### Tests

- [`GraphDiffTests`](../../src/test/java/dev/crain/authtracer/diff/GraphDiffTests.java#L25): each kind, where changes
  point, renamed route variables, the system's findings, escaped Markdown.
- [`CredentialsExposureTests`](../../src/test/java/dev/crain/authtracer/diff/CredentialsExposureTests.java#L31)
  (`switchingFromRelayToTheServicesOwnTokenFailsTheDiff`), [`PoliciesTests`](../../src/test/java/dev/crain/authtracer/diff/PoliciesTests.java#L33)
  (`theDiffFailsOnANewViolationOnly`), [`ViewFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ViewFixtureTests.java#L27)
  (`droppingSecAuthorizeFromATemplateWeakensTheField`).
- [`ProjectDiffTests`](../../src/test/java/dev/crain/authtracer/cli/ProjectDiffTests.java#L36) on the `projectdiffbase` and
  `projectdiffhead` fixtures; integration [`AgenticRegressionTests`](../../src/integrationTest/java/dev/crain/authtracer/AgenticRegressionTests.java#L35)
  and [`DiffProjectTests`](../../src/integrationTest/java/dev/crain/authtracer/cli/DiffProjectTests.java#L24) on the
  example services.

### Before changing it

- **"Weaker" means fewer callers kept out**, and only `Clauses.compare` decides it; a change to the order changes
  every diff.
- **A policy violation fails only when it is new**: one the base already had is not this change's doing.
- **A finding is the same finding when its service, kind and message are**: rewording a finding's message makes every
  existing one new in the next diff.
- **The order of the changes is fixed**, so the same two graphs give the same report and the same SARIF.

## Diagonal escalation

**Feature:** [`DIAGONAL_ESCALATION`](features.md#diagonal_escalation)

A new endpoint or field that reaches data already exposed elsewhere, but asks less than every route that reached it
before: a shortcut around the existing checks. It fails the check, and names the weakest existing route as an example.

### How it works

1. [`GraphDiff.compare`](../../src/main/java/dev/crain/authtracer/diff/GraphDiff.java#L46) hands each exposure the base
   doesn't have to `newExposure`.
2. An endpoint, or a field with no sources, is a `NEW_EXPOSURE`.
3. For each of the new field's sources (the roots [`Exposures`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L40)
   traced it to, across services), the base's field exposures with the same source are its existing routes. When the
   new one is weaker than all of them, it is a `DIAGONAL_ESCALATION`; when it is neither as strong as any of them nor
   weaker than them all (it can't be ranked), a `CHANGED` that needs review; otherwise the next source is tried, and
   with none left it is a `NEW_EXPOSURE`.
4. The example in the message is the weakest existing route (one no other is weaker than), preferring the changed
   service's own, then a `GET`, then fewer clauses.

### Relies on / relied on by

- **Relies on** [`DIFF`](features.md#diff) and [`FIELD_LINEAGE`](features.md#field_lineage): the sources, followed
  across calls, messages and writes.
- **Relied on by** the reports: SARIF rule `DIAGONAL_ESCALATION`, and the agent report's wording for several fields.

### Tests

- [`GraphDiffTests`](../../src/test/java/dev/crain/authtracer/diff/GraphDiffTests.java#L25):
  `aNewWeakerRouteToTheSameDataIsADiagonalEscalation`, `aNewRouteToTheSameDataThatCanNotBeRankedNeedsReview`,
  `aDiagonalEscalationNamesTheWeakestReadOfTheDataAsItsExample`, `aNewRouteAsStrongAsAnExistingOneIsFine`.
- [`CrossServiceExposuresTests`](../../src/test/java/dev/crain/authtracer/diff/CrossServiceExposuresTests.java#L36)
  (`aDiagonalEscalationsExampleIsARouteOfTheChangedServiceWhenItHasOne`) and
  [`AgenticRegressionTests`](../../src/integrationTest/java/dev/crain/authtracer/AgenticRegressionTests.java#L35)
  (`shortcutEndpointIsADiagonalEscalation`).

### Before changing it

- **Sources are root sources**: a declassified field is its own source, so a route to it is compared only with other
  routes to the declassified value.
- **The example is chosen for the person who made the change**: a route of their own service, and a read, before
  others.

## SARIF annotations

**Feature:** [`SARIF_ANNOTATIONS`](features.md#sarif_annotations)

The diff's changes that fail or need review as SARIF 2.1.0, each at the source line it comes from, so GitHub code
scanning (`upload-sarif`) and other tools annotate the pull request there (decision 0024).

### How it works

1. `diff --sarif <file>` in [`DiffCommands`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L40) passes the
   services whose source is at hand: `--sources service=dir,...`, and with `--project` the project.
2. [`SarifReport.write`](../../src/main/java/dev/crain/authtracer/diff/SarifReport.java#L62) skips informational changes,
   locates each change's site with [`SourceFiles`](../../src/main/java/dev/crain/authtracer/diff/SourceFiles.java#L34)
   (changes in code that isn't at hand are only logged), and writes one result per change: its kind as the rule,
   `error` for what fails and `warning` for what needs review, a message (`message`), the file and line, and a
   fingerprint (`fingerprint`) that stays the same across commits. The rules table gives each kind a name, a
   description and GitHub's `security-severity`.
3. **Finding the file.** `SourceFiles.of` lists a project's source roots (`src/<set>/java`, `kotlin`, `groovy`,
   `resources`, `webapp`, outside `build` and the like) and the enclosing git repository, whose relative paths code
   scanning matches.
4. **Finding the line.** `SourceFiles.locate`: a Provided fact or conflict is in the project's `authtracer.yaml`; a
   resource (a template's `sec:authorize`) at its path and recorded line; a class in its outer class's file (or the
   Kotlin or Groovy file that declares it), at the recorded line, else the method's declaration (an overload chosen
   by its parameter types, `parameterTypes`), else the class's; with an annotation, the annotation's line above the
   declaration (`annotated`), since that is the line a change to the check touches.

### Relies on / relied on by

- **Relies on** [`DIFF`](features.md#diff): each change's `Site`, from `locate` in
  [`GraphDiff`](../../src/main/java/dev/crain/authtracer/diff/GraphDiff.java#L34).
- **Relied on by** the pull-request check (`authtracerDiff -Psarif=...`).

### Tests

- [`SarifReportTests`](../../src/test/java/dev/crain/authtracer/diff/SarifReportTests.java#L24): results at their check,
  stable fingerprints, overloads, findings, Provided facts, repository-relative paths.
- [`SourceFilesTests`](../../src/test/java/dev/crain/authtracer/diff/SourceFilesTests.java#L22): annotations over
  several lines, Kotlin functions, outer classes, resources.

### Before changing it

- **Fingerprints must not move**: code scanning tracks one alert by them across commits. Policy violations add what
  the policy requires and new findings their kind and message, so two at one place differ; every other kind keeps the
  fingerprint it always had.
- **Graphs record lines only for statements**, so a method's line is found by reading its declaration in the source.
- **Paths are relative to the repository root, with `/`**, whatever the project's place in it.

## The agent report

**Feature:** [`AGENT_REPORT`](features.md#agent_report)

The diff written for the coding agent that made the change: only what fails the check, one item per place in the code,
with what it requires now, where the check is, and what to do (decision 0028). An agent's hook feeds it back when the
check fails.

### How it works

1. [`scripts/agent-check.sh`](../../scripts/agent-check.sh) runs `./gradlew authtracerDiff` with `-PagentReport`, and
   when the diff fails prints the report to stderr and exits 2, which agent hooks (a Claude Code Stop hook, for one)
   hand back to the agent.
2. `diff --agent-report <file>` in [`DiffCommands`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L40)
   calls [`AgentReport.write`](../../src/main/java/dev/crain/authtracer/diff/AgentReport.java#L29) with the services'
   sources and `--fail-on-review`.
3. `write` takes `DiffReport.failing`; with none, it says nothing got weaker. Otherwise it groups the changes by
   kind, place, endpoint and requirement, so the fields of one check are one item, writes each as a sentence
   (`sentence`) and its place as `path:line` with the annotation (`location`, through
   [`SourceFiles`](../../src/main/java/dev/crain/authtracer/diff/SourceFiles.java#L34)), and ends with what to do.

### Relies on / relied on by

- **Relies on** [`DIFF`](features.md#diff) and the same source lookup as [`SARIF_ANNOTATIONS`](features.md#sarif_annotations).

### Tests

- [`AgentReportTests`](../../src/test/java/dev/crain/authtracer/diff/AgentReportTests.java#L18) and, on the example
  services, [`AgenticRegressionTests`](../../src/integrationTest/java/dev/crain/authtracer/AgenticRegressionTests.java#L35).

### Before changing it

- **It is read by an agent, not a person at a table**: short sentences, only what fails, and one item per place, so
  the agent fixes each place once.
- **The script's exit codes are a contract with the hook**: 0 nothing weaker, 2 a report to act on, 1 the diff
  couldn't run.

## Policies

**Feature:** [`POLICIES`](features.md#policies)

Rules the organisation or a service sets in its Provided facts files, checked on every exposure: a field carrying a
label (`PII`) must require at least what the label's policy says wherever it is exposed (decision 0025), and an
endpoint matching a pattern must check a requirement on entry, and with `fresh` against a live authority source
(decision 0026). Each violation is on the exposure; the `policies` command fails on any, and the diff on new ones.

### How it works

1. **Where policies come from.** `policies:` in `authtracer.yaml` or the Org file, read by `policies` in
   [`ProvidedFacts`](../../scanner/src/main/java/dev/crain/authtracer/provided/ProvidedFacts.java#L34): `{label, requires,
   reason}` is a `POLICY` fact, `{endpoint, requires, fresh, reason}` an `ENDPOINT_POLICY` whose pattern must parse.
   Policies don't compete: every one is kept in the graph's `provided` facts.
2. **Collecting them.** [`Policies.of`](../../src/main/java/dev/crain/authtracer/diff/Policies.java#L112), called by
   [`Exposures.of`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L143), takes the Org's policies once
   however many graphs carry them, and each service's own with its service, each requirement parsed by
   [`SpelRequirements.standard`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpelRequirements.java#L99) into
   clauses.
3. **Label policies.** `violations` checks every policy whose label the exposure carries (inherited from its sources)
   and that applies to it (`appliesTo`: an Org policy everywhere; a service's own on its exposures, and wherever
   another service exposes a field of its that carries the label). The exposure's steps are grouped by the service
   they run in; `implied` asks that each of the policy's clauses be implied by one service's, after widening the
   clause through that service's role hierarchy (`widened`).
4. **Endpoint policies** apply to an endpoint's own exposure. A policy matches by method (a mapping for any method
   matches too) and path pattern, in the service that set it or anywhere for the Org's. `chain` collects the checks
   on the endpoint's path that aren't field checks or conditional, as entry checks, then follows the calls that relay
   the caller's token to the endpoints they reach; each check notes whether its service reads authorities live
   (decision 0007). Not implied by the entry checks is a violation "on entry"; with `fresh`, not implied by the live
   ones is another.
5. **Where it lands.** `Exposure.violations`; the `policies` command in
   [`DiffCommands`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L40) prints them and exits non-zero,
   `GraphDiff` makes new ones `POLICY_VIOLATION`s, and the UI's [`ExposureTable.tsx`](../../frontend/src/features/exposures/ExposureTable.tsx)
   shows them.

### Relies on / relied on by

- **Relies on** [`EXPOSURES`](features.md#exposures) (steps, labels and where they came from),
  [`PROVIDED_FACTS`](features.md#provided_facts), [`SYSTEM_GRAPH`](features.md#system_graph) (relayed calls) and
  [`AUTHORITY_SOURCE`](features.md#authority_source) (freshness, role hierarchy).
- **Relied on by** [`DIFF`](features.md#diff).

### Tests

- [`PoliciesTests`](../../src/test/java/dev/crain/authtracer/diff/PoliciesTests.java#L33): label and endpoint policies, a
  service's own policy and the Org's, role hierarchies, fresh checks on the chain.
- [`ProvidedFactsTests`](../../src/test/java/dev/crain/authtracer/provided/ProvidedFactsTests.java#L20) (reading them) and
  the integration test [`DataGovernanceTests`](../../src/integrationTest/java/dev/crain/authtracer/DataGovernanceTests.java#L21).

### Before changing it

- **A policy is a floor**: every policy that applies must hold, so a service's own can add to the Org's but never
  relax it.
- **A service's label policy follows its data**, not its endpoints: `labelledBy` records which service's fields
  brought the label.
- **Role clauses are widened per service** before comparing, because each service's checks were widened by its own
  hierarchy at scan time.

## Provided facts

**Features:** [`PROVIDED_FACTS`](features.md#provided_facts), [`FINDING_PROVIDED_CONFLICT`](features.md#finding_provided_conflict)

What people tell the scan that it can't infer: a field is sensitive (with labels) or declassified, a hand-rolled check
was reviewed, a requirement is enforced outside the code, and policies. Each service has its own `authtracer.yaml`, the
organisation one file for all; where they say different things about the same thing, the Org's wins, and the local
fact that lost is reported as a `PROVIDED_CONFLICT` finding.

### How it works

1. **Loading.** [`ProvidedFacts.load`](../../scanner/src/main/java/dev/crain/authtracer/provided/ProvidedFacts.java#L47) reads the
   local file and the Org file (YAML with `version: 1`, read with SnakeYAML's `SafeConstructor`): `facts:` (`kind` with
   `field`, `method` or `ingress`; `labels`, `requirement`, `reason`), `policies:`, and in the Org file
   `services.<name>.overrides` for one service. [`ProjectScans.project`](../../scanner/src/main/java/dev/crain/authtracer/scan/ProjectScans.java#L42)
   loads the project's `authtracer.yaml` with `--org-facts`; `scan` in
   [`CliRunner`](../../src/main/java/dev/crain/authtracer/cli/CliRunner.java#L38) takes `--facts` for class directories.
   [`ScanInput`](../../scanner/src/main/java/dev/crain/authtracer/scan/ScanInput.java#L20) carries them to the scan.
2. **Precedence.** `resolve` goes through local facts, then the Org's, then its overrides. Facts about the same thing
   ([`ProvidedFact.conflictKey`](../../scanner/src/main/java/dev/crain/authtracer/graph/ProvidedFact.java#L68): a field's
   sensitivity and declassification are one thing) compete: a later origin wins, and a local fact that loses is a
   `PROVIDED_CONFLICT` (`dropped`) at `authtracer.yaml`. Two different facts of one origin about one thing keep the
   first and report the second. Policies are all kept.
3. **Applied during the scan**, by kind:
   - `requirement`: `providedRequirements` in [`SpringSecurityModule`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L60)
     adds a "Provided requirement" location to every HTTP request its pattern (`GET /path/**` or `/path/**`) matches,
     before the filter chain's rule;
   - `check`: [`MethodSecurity.providedCheck`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L875)
     adds a "Provided check" location to the method its key names, and `handRolledChecks` no longer reports that
     method's code as an unrecognized check;
   - `sensitive` and `declassify`: `applyFieldFacts` in
     [`ApplicationScanner`](../../scanner/src/main/java/dev/crain/authtracer/scan/ApplicationScanner.java#L39), after every module,
     puts the labels on the Field ([`Field.withLabels`](../../scanner/src/main/java/dev/crain/authtracer/graph/Field.java#L80)) or
     declassifies it, then records every fact in the graph's `provided` list and the conflicts as findings;
   - policies are only recorded, for [`Policies`](../../src/main/java/dev/crain/authtracer/diff/Policies.java#L51).
4. **Used after the scan.** [`Exposures`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L40) passes labels
   down the lineage and stops at a declassified field; the linker's token and issuer findings skip Provided locations;
   [`SourceFiles`](../../src/main/java/dev/crain/authtracer/diff/SourceFiles.java#L34) places them in `authtracer.yaml`.
   A graph posted to the server has its facts checked by the rules the files are read with
   (`ProvidedFacts.validate`, from [`GraphValidation`](../../src/main/java/dev/crain/authtracer/api/GraphValidation.java#L23)).

### Relies on / relied on by

- **Relies on** [`APPLICATION_GRAPH`](features.md#application_graph): the field ids, method keys and Ingress routes
  facts name.
- **Relied on by** [`POLICIES`](features.md#policies), [`EXPOSURES`](features.md#exposures) (labels and
  declassification), [`CUSTOM_DECISIONS`](features.md#custom_decisions) and
  [`FINDING_UNRECOGNIZED_CHECK`](features.md#finding_unrecognized_check) (reviewed checks).

### Tests

- [`ProvidedFactsTests`](../../src/test/java/dev/crain/authtracer/provided/ProvidedFactsTests.java#L20): every kind,
  precedence and the conflicts it reports, overrides, malformed files.
- [`ProvidedFactsScanTests`](../../src/test/java/dev/crain/authtracer/provided/ProvidedFactsScanTests.java#L21): a declared
  check, a provided requirement and inherited sensitivity in a scan, on the `flows` and `handrolled` fixtures.
- [`SourceFilesTests`](../../src/test/java/dev/crain/authtracer/diff/SourceFilesTests.java#L22)
  (`aProvidedFactIsAtItsLineInTheProjectsFactsFile`) and
  [`GraphValidationTests`](../../src/test/java/dev/crain/authtracer/api/GraphValidationTests.java#L30).

### Before changing it

- **The Org wins, and the loss is never silent**: every local fact that loses is a finding the diff reports when new.
- **Facts that change requirements are enforced outside Spring Security**: the role hierarchy doesn't widen them,
  and a provided requirement comes before the filter chain's rule, with the request's filters after it.
- **Field facts are applied after every module**, whatever framework made the field, and name it by its id,
  `field:<class>.<property>`.
- **The YAML is read with `SafeConstructor`**, so a facts file can't construct arbitrary types.

## Files

| File | Role | Features |
|---|---|---|
| [`Exposures`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L40) | What each endpoint and field needs, through every service on the way, with sources, labels and lineage | EXPOSURES; `notHandedOut`, `PathChecks.throwing` FIELD_CHECKS |
| [`Clauses`](../../src/main/java/dev/crain/authtracer/diff/Clauses.java#L23) | Requirements as clauses, so two can be ranked | DIFF, POLICIES, EXPOSURES |
| [`GraphDiff`](../../src/main/java/dev/crain/authtracer/diff/GraphDiff.java#L34) | Compares two revisions' exposures and findings | DIFF; `newExposure` DIAGONAL_ESCALATION; `locate` SARIF_ANNOTATIONS, AGENT_REPORT; `compare` (of exposures) POLICIES |
| [`DiffReport`](../../src/main/java/dev/crain/authtracer/diff/DiffReport.java#L17) | The diff's changes, their severities, and its Markdown | DIFF |
| [`Markdown`](../../src/main/java/dev/crain/authtracer/diff/Markdown.java#L10) | Table cells for the diff's and the commands' Markdown | DIFF, COMMAND_LINE |
| [`SarifReport`](../../src/main/java/dev/crain/authtracer/diff/SarifReport.java#L30) | The diff as SARIF 2.1.0 | SARIF_ANNOTATIONS |
| [`SourceFiles`](../../src/main/java/dev/crain/authtracer/diff/SourceFiles.java#L34) | The source file and line of a place in the code | SARIF_ANNOTATIONS, AGENT_REPORT |
| [`AgentReport`](../../src/main/java/dev/crain/authtracer/diff/AgentReport.java#L20) | The diff for a coding agent's hook | AGENT_REPORT |
| [`Policies`](../../src/main/java/dev/crain/authtracer/diff/Policies.java#L51) | Label and endpoint policies, checked on every exposure | POLICIES |
| [`ProvidedFacts`](../../scanner/src/main/java/dev/crain/authtracer/provided/ProvidedFacts.java#L34) | Reads the facts files and resolves them by precedence | PROVIDED_FACTS; `resolve`, `dropped` FINDING_PROVIDED_CONFLICT; `policies` POLICIES; `validate` GRAPH_SERVER |
