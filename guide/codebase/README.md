# The codebase guide

For people changing AuthTracer: where each logic chain lives, from the detector that finds something in a service's
bytecode to the line of the UI that shows it, and which code each feature needs. It follows the code by what it gives
people, so it starts from AuthTracer's response and works back. The [onboarding guide](../onboarding.md) comes first:
the vocabulary, the setup, the test layers and a first change.

Every link leads to the code, with the class or method it names in the link text, and opens the file at the line it is
declared on. The line anchors are refreshed on demand with `scripts/guide-anchors.sh`, not on every commit, so one may
be a few lines off between refreshes; the name in the link is what counts.

## Features, and the code each needs

A **feature** is anything of value in AuthTracer's response: a kind of entry point or check in the graph, a finding
kind, the exposures, the diff, a view of the UI. The catalogue is the enum
[`Feature`](../../annotations/src/main/java/dev/crain/authtracer/annotations/Feature.java#L13), in the `annotations`
Gradle subproject. Each constant has an area, a one-sentence summary, and the features it relies on.

Code says which features it is needed for: take it away and they break, or say less.

- Java: [`@Supports`](../../annotations/src/main/java/dev/crain/authtracer/annotations/Supports.java#L19) on every
  top-level class, and on a method or nested class that serves a feature its class otherwise doesn't (where a finding
  is raised, typically).
- UI: a first line `// @supports PATHS_VIEW, UI` in every source file under `frontend/src`.

The code a feature needs is its own and that of every feature it relies on. Three ways to find it:

1. The **[feature index](features.md)**, generated from the annotations: each feature's summary, the pages that
   describe it, what it relies on and what relies on it, and its code grouped by package, with a diagram of how the
   features depend on each other.
2. In the IDE, **Find Usages** on a `Feature` constant lists every class and method tagged with it.
3. For the UI, `grep -rn "@supports.*PATHS_VIEW" frontend/src`.

## The pipeline

```
 project dir ─▶ build ─▶ scan ─▶ application graph ─▶ link ─▶ system graph ─▶ exposures ─▶ diff ─▶ reports
               (Gradle,  (SootUp,  (one per service)    ▲      (all services)      │       (two     (Markdown,
                Maven)   Spring)                        │                          │       revisions) SARIF, agent)
                                       Zipkin traces ───┘           policies ◀─────┘
                                                                         server (H2) ─▶ REST API ─▶ UI
```

| Stage | Starts at | Writes | Page |
|---|---|---|---|
| Build | [`ProjectScans.project`](../../scanner/src/main/java/dev/crain/authtracer/scan/ProjectScans.java#L42), or [`ArtifactScans.artifact`](../../scanner/src/main/java/dev/crain/authtracer/scan/ArtifactScans.java#L102) for a built jar | a [`ScanInput`](../../scanner/src/main/java/dev/crain/authtracer/scan/ScanInput.java#L20): classes, libraries, resources, facts | [scanning.md](scanning.md#scanning-a-project) |
| Scan | [`ApplicationScanner.scan`](../../scanner/src/main/java/dev/crain/authtracer/scan/ApplicationScanner.java#L63), then [`SpringSecurityModule.scan`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L79) | an [`ApplicationGraph`](../../scanner/src/main/java/dev/crain/authtracer/graph/ApplicationGraph.java#L21), through [`GraphBuilder`](../../scanner/src/main/java/dev/crain/authtracer/scan/GraphBuilder.java#L26) | [scanning.md](scanning.md), [call-paths.md](call-paths.md) |
| Link | [`Linker.link`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L114) | a [`SystemGraph`](../../scanner/src/main/java/dev/crain/authtracer/graph/SystemGraph.java#L18): links, network flows, observations, identities | [system.md](system.md) |
| Exposures | [`Exposures.of`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L143) | an `Exposure` per endpoint and response field, with its policy violations | [analysis.md](analysis.md) |
| Diff | [`GraphDiff.compare`](../../src/main/java/dev/crain/authtracer/diff/GraphDiff.java#L46) | a [`DiffReport`](../../src/main/java/dev/crain/authtracer/diff/DiffReport.java#L17), written as Markdown, [`SarifReport.write`](../../src/main/java/dev/crain/authtracer/diff/SarifReport.java#L62) or [`AgentReport.write`](../../src/main/java/dev/crain/authtracer/diff/AgentReport.java#L29) | [analysis.md](analysis.md) |
| Command line | [`CliRunner.run`](../../src/main/java/dev/crain/authtracer/cli/CliRunner.java#L91), [`DiffCommands.diff`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L52) | graph files, reports, an exit code | [delivery.md](delivery.md#the-command-line) |
| Server | [`GraphController.publish`](../../src/main/java/dev/crain/authtracer/api/GraphController.java#L47), [`GraphStore.save`](../../src/main/java/dev/crain/authtracer/store/GraphStore.java#L37) | snapshots in H2, served over `/api` | [delivery.md](delivery.md#the-server) |
| UI | [`App.tsx`](../../frontend/src/App.tsx), [`model.ts`](../../frontend/src/lib/model.ts) | the views | [delivery.md](delivery.md#the-ui-shell) |

## The pages

| Page | What it follows | Features |
|---|---|---|
| [scanning.md](scanning.md) | A project's build, the scan's foundations (SootUp, `ScanContext`, `GraphBuilder`), the graph model and its JSON, Groovy and Kotlin calls | `APPLICATION_GRAPH`, `PROJECT_BUILDS` |
| [call-paths.md](call-paths.md) | `SpringSecurityModule` as the scan's table of contents, and how each entry point's ordered steps are put together | `CALL_PATHS` |
| [entry-points.md](entry-points.md) | Every way in: one detector per kind, the `Ingress` it makes, how it is walked | `HTTP_ENDPOINTS` ... `GATEWAY_ROUTES` |
| [rules.md](rules.md) | The filter chain's configuration (Java, Kotlin, Groovy, XML) and the protocols' rules, as ordered checks | `REQUEST_RULES` |
| [requirements.md](requirements.md) | What each check asks for, normalized, and where the service's authorities come from | `REQUIREMENTS`, `AUTHORITY_SOURCE` |
| [method-checks.md](method-checks.md) | Method security and the proxies that apply it, checks decided by application code, hand-rolled checks | `METHOD_SECURITY`, `FIELD_CHECKS`, `CUSTOM_DECISIONS` |
| [fields.md](fields.md) | Response fields, where their values come from, server-rendered views, the fields side of field checks | `RESPONSE_FIELDS`, `FIELD_LINEAGE`, `VIEW_FIELDS` |
| [calls.md](calls.md) | Every call out: clients, message sends, infrastructure calls, and the credentials each carries | `SERVICE_CALLS`, `MESSAGE_SENDS`, `INFRASTRUCTURE_CALLS`, `CALL_CREDENTIALS` |
| [system.md](system.md) | Linking services, traces, identities, and the findings only several services show | `SYSTEM_GRAPH`, `TRACE_OBSERVATIONS`, `IDENTITIES` |
| [analysis.md](analysis.md) | Exposures, the diff and its reports, policies, Provided facts | `EXPOSURES`, `DIFF`, `POLICIES`, `PROVIDED_FACTS`... |
| [findings.md](findings.md) | Each finding kind: what it means, every place that raises it, its tests | `FINDING_*` |
| [delivery.md](delivery.md) | The command line, the server and its API, and each view of the UI | `COMMAND_LINE`, `GRAPH_SERVER`, `UI`, `*_VIEW` |
| [features.md](features.md) | Generated: every feature with its code | all |

## Three chains end to end

Each step links to the code; the page in brackets has the detail.

### A `@PreAuthorize` method, to the Exposures view

1. The `Scan` constructor builds [`MethodSecurity`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L56),
   which reads how method security is enabled and, for every application method,
   [`MethodSecurity.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L634) turns its
   annotations into [`AuthorizationLocation`](../../scanner/src/main/java/dev/crain/authtracer/graph/AuthorizationLocation.java#L30)s
   whose [`Requirement`](../../scanner/src/main/java/dev/crain/authtracer/graph/Requirement.java#L25) the SpEL reader
   [`SpelRequirements.parse`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpelRequirements.java#L114) reduces
   ([method-checks.md](method-checks.md#method-security), [requirements.md](requirements.md)).
2. [`Scan.walk`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L426) walks each entry
   point's handler with [`CallTraversal.walk`](../../scanner/src/main/java/dev/crain/authtracer/scan/CallTraversal.java#L141). Each
   method it enters goes to the `RequestPath` listener's
   [`enter`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1343), which asks
   [`MethodSecurity.checks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L238) for the method's
   checks: on the path when the call goes through the proxy, a `BYPASSED` finding when it is a call on `this`
   ([call-paths.md](call-paths.md#call-paths)).
3. [`PathTail.append`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/PathTail.java#L21) writes the steps as ordered
   [`Edge`](../../scanner/src/main/java/dev/crain/authtracer/graph/Edge.java#L23)s, and once every path is drawn,
   [`Scan.hierarchiesAndFactories`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L807)
   widens each requirement by the role hierarchy ([requirements.md](requirements.md)).
4. [`GraphJson.write`](../../scanner/src/main/java/dev/crain/authtracer/graph/GraphJson.java#L57) writes the graph; `scan
   --publish` sends it to [`GraphController.publish`](../../src/main/java/dev/crain/authtracer/api/GraphController.java#L47),
   and linking (the UI's link button, or the `link` command) joins it with the other services'
   ([`Linker.link`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L114), [system.md](system.md)).
5. [`Exposures.of`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L143) combines every check on the path,
   and those on the paths of the services it calls with the caller's token, into what a caller needs
   ([analysis.md](analysis.md)).
6. [`ExposureController.systemExposures`](../../src/main/java/dev/crain/authtracer/api/ExposureController.java#L40) serves
   them as [`ExposureView`](../../src/main/java/dev/crain/authtracer/api/ExposureView.java#L31)s, and the UI's
   [`ExposuresView`](../../frontend/src/features/exposures/ExposuresView.tsx#L14) groups alike endpoints
   ([`endpointGroups`](../../frontend/src/features/exposures/exposureRows.ts#L20)) into the table
   ([delivery.md](delivery.md#the-exposures-view)).

### A sensitive field, to a failed pull request

1. A `SENSITIVE` fact in `authtracer.yaml` (or the organisation's file) is read by
   [`ProvidedFacts.load`](../../scanner/src/main/java/dev/crain/authtracer/provided/ProvidedFacts.java#L47), and
   [`ApplicationScanner.applyFieldFacts`](../../scanner/src/main/java/dev/crain/authtracer/scan/ApplicationScanner.java#L181) labels
   the field ([`Field.withLabels`](../../scanner/src/main/java/dev/crain/authtracer/graph/Field.java#L80);
   [analysis.md](analysis.md)).
2. The scan records where every response field's value comes from:
   [`ValueFlow.returnShape`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ValueFlow.java#L166) reads the handler, and
   [`ResponseFields`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ResponseFields.java#L23) turns it into
   [`Flow`](../../scanner/src/main/java/dev/crain/authtracer/graph/Flow.java#L19)s; across services, the linker adds network flows
   ([fields.md](fields.md#field-lineage)).
3. [`Exposures.of`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L143) follows the flows from each response
   field back to its roots, so a field made from the sensitive one carries its label, and
   [`Policies.violations`](../../src/main/java/dev/crain/authtracer/diff/Policies.java#L159) checks it against the `POLICY`
   for that label.
4. `diff --project ... --base-ref main` scans both revisions
   ([`DiffCommands.diff`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L52),
   [`GitWorktree`](../../scanner/src/main/java/dev/crain/authtracer/scan/GitWorktree.java#L22) for the base) and
   [`GraphDiff.compare`](../../src/main/java/dev/crain/authtracer/diff/GraphDiff.java#L46) reports a new violation as
   `POLICY_VIOLATION`, a failing change; [`Clauses.compare`](../../src/main/java/dev/crain/authtracer/diff/Clauses.java#L309)
   decides whether any other exposure got weaker.
5. [`SarifReport.write`](../../src/main/java/dev/crain/authtracer/diff/SarifReport.java#L62) places the change on the
   pull request's lines, and the command exits 1 ([delivery.md](delivery.md#the-command-line)).

### A Kafka message, across two services

1. In the sender, the walk meets `KafkaTemplate.send(..)`:
   [`MessageSends`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSends.java#L31) makes an
   [`Egress`](../../scanner/src/main/java/dev/crain/authtracer/graph/Egress.java#L24) for the topic, and
   [`MessagePayloads.sent`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessagePayloads.java#L59) records what the
   payload carries ([calls.md](calls.md#message-sends), [fields.md](fields.md#field-lineage)).
2. In the receiver, [`MessageListeners`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageListeners.java#L31)
   makes an [`Ingress`](../../scanner/src/main/java/dev/crain/authtracer/graph/Ingress.java#L25) for the `@KafkaListener`, and its
   path is walked with no caller: [`NoCaller.mark`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/NoCaller.java#L59)
   turns the method checks on it into denials unless the code sets a SecurityContext
   ([entry-points.md](entry-points.md#message-listeners), [call-paths.md](call-paths.md#no-caller-nocaller)).
3. [`Linker.link`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L114) matches the send to the listener by
   protocol and topic ([`Routes.sameDestination`](../../src/main/java/dev/crain/authtracer/link/Routes.java#L60)), and
   matches the payload's fields with the listener's parameter, so what the receiver keeps and later serves traces back
   to the sender ([system.md](system.md#the-system-graph)).
4. With traces, the link is confirmed `NETWORK_OBSERVED`, and a traced message that matches no send or listener is an
   `UNMATCHED_CALL` finding ([system.md](system.md#trace-observations), [findings.md](findings.md#unmatched_call)).

## Keeping the guide true

[`CodebaseGuideTests`](../../src/test/java/dev/crain/authtracer/guide/CodebaseGuideTests.java#L39) runs with the unit
tests and fails when:

- a class under `src/main/java`, or a UI source file, doesn't say which features it supports;
- a feature has no code that supports it, or no page names it in a `Feature:` line;
- [features.md](features.md) differs from what the annotations say;
- a link in these pages leads to a file that isn't there, to a heading a page doesn't have, or names a member its file
  doesn't have (the last identifier in the link's code text), or carries an anchor into code that isn't a line's.

After changing tags, features or headings, rewrite the index and read its diff:

```
./gradlew test --tests '*CodebaseGuideTests' -PupdateGuide=true
```

**Tagging.** Name the features the code is needed for, most specific first; leave out those it serves only through
another feature. Code every scan needs supports `APPLICATION_GRAPH`. Where a class raises a finding but serves
something else, tag the method that raises it with `FINDING_<KIND>`.

**Adding a feature.** Add the constant to `Feature` after the features it relies on (an enum can't refer to a later
constant), tag the code, describe it in a section of the page that covers its area, starting with a line `Feature:`
and a link to the feature's heading in `features.md` (as every section here does), and rewrite the index. A new
finding kind also needs its text in the UI ([findings.md](findings.md#where-findings-go)).

**Writing links.** Relative to the page, with the class or `Class.member` in backticks as the link text, so the test can
check the member is there. Leave the line anchor off: the script adds it.

**Line anchors.** [`scripts/guide-anchors.sh`](../../scripts/guide-anchors.sh) (or `./gradlew guideAnchors`) points
every link to code at the line its class or member is declared on now, finding each name in the link's text inside the
one before it (`SpringSecurityModule.Scan.walk` is `walk` inside `Scan`), and lists any link whose member it can't
find. It takes about a second, and the tests don't need it, so run it when the code has moved enough to matter: after
a refactor, before sharing the guide. It also takes other Markdown files: `scripts/guide-anchors.sh BUGS.md`. The
logic is [`GuideAnchors`](../../src/test/java/dev/crain/authtracer/guide/GuideAnchors.java#L25).

## Where the code is

| Directory | What lives there | Page |
|---|---|---|
| [`annotations/`](../../annotations/src/main/java/dev/crain/authtracer/annotations) | `Feature`, `@Supports`, `@Might` (a deliberately deferred change) | this page |
| [`graph/`](../../scanner/src/main/java/dev/crain/authtracer/graph) | The model: nodes, edges, flows, findings, facts, the application and system graphs, their JSON | [scanning.md](scanning.md#the-graph-model) |
| [`scan/`](../../scanner/src/main/java/dev/crain/authtracer/scan) | The scanner, its context and builder, the call walk, Groovy calls | [scanning.md](scanning.md), [call-paths.md](call-paths.md) |
| [`scan/build/`](../../scanner/src/main/java/dev/crain/authtracer/scan/build) | Gradle and Maven projects | [scanning.md](scanning.md#scanning-a-project) |
| [`scan/flow/`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow) | Response fields and value flow | [fields.md](fields.md) |
| [`scan/spring/`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring) | The Spring module: one class per kind of entry point, rule, check or client | every scan page |
| [`link/`](../../src/main/java/dev/crain/authtracer/link) | The linker, route matching, traces, identities | [system.md](system.md) |
| [`diff/`](../../src/main/java/dev/crain/authtracer/diff) | Exposures, requirement strength, the diff, policies, reports | [analysis.md](analysis.md) |
| [`provided/`](../../scanner/src/main/java/dev/crain/authtracer/provided) | Provided facts | [analysis.md](analysis.md) |
| [`cli/`](../../src/main/java/dev/crain/authtracer/cli), [`api/`](../../src/main/java/dev/crain/authtracer/api), [`store/`](../../src/main/java/dev/crain/authtracer/store) | The command line, the REST API, the H2 store | [delivery.md](delivery.md) |
| [`scanner-image/`](../../scanner-image) | The scanner image: its command, Dockerfile and entrypoint | [delivery.md](delivery.md#the-scanner-image) |
| [`frontend/src/`](../../frontend/src) | The UI | [delivery.md](delivery.md) |
| [`src/fixtures/`](../../src/fixtures) | Small applications the unit tests scan | each page's Tests |
| [`src/conformance/`](../../src/conformance) | Each fixture's graph against Spring at runtime, and the differences understood | [onboarding](../onboarding.md#5-tests) |
| [`src/perfTest/`](../../src/perfTest) | Benchmarks of the scan, link, exposures, diff, JSON and UI size, and their baseline | [onboarding](../onboarding.md#5-tests) |
