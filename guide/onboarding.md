# Onboarding: working on AuthTracer

For engineers joining the project. It covers the vocabulary, how the code is laid out, how a scan becomes the
pictures in the UI, the test layers, and a first change from start to finish. To learn what AuthTracer does from the
outside first, follow the [tutorial](tutorial.md); to follow one feature's code from end to end, use the
[codebase guide](codebase/README.md).

## 1. The vocabulary

AuthTracer builds an **authorization graph** of Spring applications from their compiled bytecode, links the graphs of
several services into one system, and compares graphs to catch changes that weaken authorization.

| Term | Meaning | In the graph JSON |
|---|---|---|
| **Ingress** | A way into a service: an HTTP endpoint, a gRPC method, a message listener, a scheduled task... | node `"type": "ingress"` |
| **Egress** | A call out of a service: RestClient, WebClient, Feign, gRPC stub, a message send... and the credentials it carries | node `"type": "egress"` |
| **Authorization Location** | A place where a check runs: a filter-chain rule, `@PreAuthorize`, a field check, a hand-rolled check | node `"type": "location"` |
| **Requirement** | What a check asks for (`ROLE_ADMIN`, `authenticated`, an expression it can't reduce) | `location.requirement` |
| **Callpath** | The order the steps run in on one Ingress's path. `conditional` when only some branches reach a step | `edges[]` |
| **Link** | A call from one service's Egress to another's Ingress: **observed** in traces or **inferred** from URLs | system graph `links[]` |
| **Field** and **Flow** | Response fields, and where their values come from: **Direct** (copied), **Complex** (part of a structure), **Computed** (derived), **Masked** (what a denial handler derives from the value for the callers it denies) | nodes `"type": "field"`, `flows[]` |
| **Exposure** | What a caller needs to get an endpoint, or a field of its response, across every service on the way | computed by `diff.Exposures` |
| **Finding** | Something a person should look at: a check that isn't enforced, a bypass, configuration the scan can't read | `findings[]` |
| **Opaque** | Code the scan can't see through. It is shown, never guessed | node `"type": "opaque"` |
| **Provided fact** | What a person tells the scan: a field is sensitive, a hand-rolled check is reviewed, a policy | `provided[]` |
| **Observation** | How often a check granted or denied, and how often a link was called, from traces | system graph `observations[]` |

One rule runs through everything: **what can't be inferred is shown as such**. When the scanner can't tell, it says
so (an Opaque node, a finding, a "may match first" split) rather than picking the convenient answer.

## 2. Getting set up

| Tool | Version | Why |
|---|---|---|
| JDK | 25, installed locally (Gradle's toolchain looks for it) | AuthTracer and the example services |
| Node.js and npm | Node 22.13 or newer | Building the UI: `bootRun`, `bootJar`, `test` and `check` run `npm ci` and `npm run build` for you. The command line (`authtracer`) and the pull-request check (`authtracerDiff`) don't need it |
| An IDE | IntelliJ IDEA works well | Open the root `build.gradle` |
| Docker | With `docker compose` | The example services' Kafka and RabbitMQ (`scripts/brokers.compose.yaml`), for the system test and `scripts/demo.sh` |

The integration and system tests also scan and run the **example services**: `profile-service`, `employee-service`,
`identity-service` and `payroll-service`, in this repository's `examples/` folder. Unit tests don't need them.

```
./gradlew test                  # unit tests, about a minute
./gradlew bootRun               # the server and the UI on http://localhost:8080
```

## 3. The pipeline

```
 service bytecode ──scan──▶ application graph ──link──▶ system graph ──▶ exposures ──▶ diff / policies / UI
   (SootUp)                  (one per service)    ▲      (all services)
                                                  │
                         Zipkin traces (optional) ┘
```

1. **Scan** (`scan`): reads one service's classes and libraries with [SootUp](https://soot-oss.github.io/SootUp/),
   finds Ingress, checks, Egress and fields, and writes an `ApplicationGraph`. No service is run.
2. **Link** (`link`): joins application graphs into a `SystemGraph`. Egress calls are matched to Ingress routes
   statically, and confirmed (with counts, identities and check outcomes) from Zipkin traces when there are any.
3. **Exposures** (`diff.Exposures`): for every endpoint and response field, the combined requirement of every check on
   the way, across services, with the lineage it came from.
4. **Diff** (`diff`): compares two graphs' exposures and findings and classifies each change (WEAKENED,
   DIAGONAL_ESCALATION, POLICY_VIOLATION fail; CHANGED and new findings need review).
5. **Store and serve** (`store`, `api`): the server keeps graphs in H2 under `./data` and serves them, with the UI.

## 4. Where the code is

```
scanner/src/main/java/dev/crain/authtracer/   The scanner, a Gradle subproject with no server in it
  graph/      The model: nodes, edges, flows, findings, ApplicationGraph, SystemGraph, and their JSON (GraphJson)
  scan/       ApplicationScanner, ScanContext (the SootUp view plus helpers), GraphBuilder, CallTraversal
  scan/spring/  The Spring Security module: one class per kind of entry point, rule, check or client
  scan/flow/  Field-level value flow (ValueFlow, ResponseFields)
  scan/build/ Reads Gradle and Maven projects: classes, classpath, compiling when needed
  provided/   Provided facts: authtracer.yaml and the Org file, with Org precedence
src/main/java/dev/crain/authtracer/           The server and the command line, on top of the scanner
  link/       Linker, Routes (URL template matching), ZipkinTraces, Identities
  diff/       Exposures, Clauses (the strength order of requirements), GraphDiff, DiffReport, SARIF and agent reports, Policies
  store/ api/ H2 snapshots and the REST API
  cli/        The command line: scan, link, diff, exposures, policies, identities
annotations/    A Gradle subproject: the Feature catalogue and @Supports, which say what each class is needed for, and
                @Might, a deliberately deferred change, greppable
scanner-image/  A Gradle subproject: the scanner image, which scans built jars and wars with no network (ScanArtifacts,
                and src/main/docker's Dockerfile and entrypoint)
src/fixtures/   Small Spring applications the unit tests scan (Java, Kotlin, Groovy). Compiled, never run
src/test/       Unit tests, the scanner's among them: it is tested here, through the root project's dependency on it
src/integrationTest/  Scans the example services against golden graphs
src/systemTest/ Starts the brokers, Zipkin and the example services, drives traffic, links against live traces; runs
                the scanner image
frontend/       The UI: React, TypeScript, Vite, Tailwind, React Flow
scripts/        token.sh, traffic.sh (example traffic), agent-check.sh (the diff as a coding agent's hook), demo.sh,
                brokers.compose.yaml (the example services' Kafka and RabbitMQ), guide-anchors.sh (re-points the
                codebase guide's links at the lines their members are on now), scan-artifacts.sh (runs the scanner
                image as it must be run)
```

### How a scan works

`ApplicationScanner.scan(ScanInput)` builds a SootUp `JavaView` over the application's class directories and its
libraries, then hands a `ScanContext` and a `GraphBuilder` to each `FrameworkModule` that applies. There is one module
today, `SpringSecurityModule`, and its `scan` method is the table of contents for everything the scanner understands:

1. **Configuration first:** the XML namespace config, role hierarchies, the role prefix, the authority source (JWT
   claims, introspection, UserDetails), and whether the stack is servlet or reactive.
2. **Entry points:** `RequestMappings`, `FunctionalEndpoints`, `GrpcServices`, `MessageListeners`, `RSocketMappings`,
   `ScheduledTasks`, `JaxRsResources`, `ServletEndpoints`, the library endpoints (`ActuatorEndpoints`,
   `AuthorizationServerEndpoints`, ...). Each becomes an Ingress.
3. **Request rules:** `HttpSecurityRules` (and the gRPC, RSocket and message equivalents) turn the filter-chain DSL into
   the first checks on each Ingress's path, in the order Spring evaluates them.
4. **The call path:** `RequestFilters` puts the request's servlet filters, WebFilters and Spring MVC interceptors
   around the filter chain's rule and the handler, in the order Spring runs them, and `CallTraversal` walks from each
   of them and from the handler through the application's code. On the way,
   `MethodSecurity` and `Proxies` add method checks where a call goes through a Spring proxy, `HandRolledChecks` spots
   code that reads the Authentication and denies, `HttpClientEgress` and `MessageSends` add Egress, and `AsyncCalls`
   and `NoCaller` mark steps that run on another thread or without a caller.
5. **Fields:** `ResponseFields` and `ValueFlow` find the response's fields and where their values come from;
   `ViewFields` adds field checks.
6. **Findings** are added wherever the scan is unsure or sees a problem, and Provided facts are applied last.

Two things to know before changing anything there:

- **The graph shows what Spring does, not what the code seems to say.** Rule order, which rule matches first, whether
  a call goes through a proxy, and which thread it runs on all change what a check does. Every one of those is modelled
  because a real application got it wrong.
- **Library behaviour is read, not assumed.** When a module needs a fact about Spring itself (a default rule, which
  endpoints a library registers), it is checked against the library's bytecode with `javap`, and the version is noted
  in the code.

## 5. Tests

| Command | What it runs | Needs |
|---|---|---|
| `./gradlew test` | Unit: every analyzer against the fixture apps, the linker, diff, policies, reports, Provided facts, the API and store; and `scanner-image`'s command | Nothing else |
| `./gradlew integrationTest` | Scans the example services, and the Boot jars they build, against `src/integrationTest/resources/golden`, links them with recorded traces, replays the diff scenarios | `examples/profile-service`, `examples/employee-service`, `examples/payroll-service` (or `-PservicesDir=<dir>`) |
| `./gradlew systemTest` | Starts Kafka and RabbitMQ (docker compose), Zipkin and the four services on shifted ports, drives real traffic over every kind of link, scans and links against live traces. Builds the scanner image and runs it on the services' Boot jars, and the ways it refuses to run | All four services and Docker; about a minute |
| `npm test` (in `frontend/`) | The UI's grouping, layout and diff logic, and its views as a person uses them (Vitest; the views in jsdom with Testing Library) | Node |
| `npm run coverage` (in `frontend/`) | The same, with a coverage report in `frontend/coverage/`; fails below the thresholds in `vite.config.ts` | Node |
| `./gradlew coverageReport` | Merges the coverage of the Java suites that ran into `build/reports/jacoco/coverageReport` (run it after them: `./gradlew test integrationTest systemTest coverageReport`) | |
| `./gradlew coverageCheck` | Fails when the unit and integration tests cover less than 97% of the lines or 88% of the branches, or any class under 80% of its lines | The integration tests' needs |
| `./gradlew conformanceTest` | Boots each fixture in a mock web environment and asks Spring what its graph says: every endpoint gets a caller that meets all it needs (must get in), an anonymous one and one lacking each clause (must be denied); a disagreement fails unless `src/conformance/resources/known-differences.tsv` explains it; the report is `build/reports/conformance` | About ten minutes; not part of `check` |
| `./gradlew perfTest` | Benchmarks the scan (fixtures and the example services), the link, exposures, diff and JSON with JMH, and the UI's size, against `src/perfTest/resources/baseline.json`; fails on a regression; the report is `build/reports/perf/perf.md` | The example services for their scans (skipped without them); a quiet machine; about a minute and a half |

`./gradlew check` runs the unit tests, the UI tests, the integration tests and the coverage floor.

**Performance is a baseline, like the goldens.** The benchmarks are JMH's (`Benchmarks` in `src/perfTest`, no JMH
Gradle plugin: `PerformanceTests` runs each through JMH's `Runner`, in a JVM of its own with the task's flags). JMH
warms each up and measures the average time of one operation; its GC profiler measures what one operation allocates,
and `CpuTime` the process's CPU time per operation. Each is compared with the baseline: time and CPU time may grow 20%
and allocations 5% (each by more than a small floor) before it fails. Times are compared only on the machine the baseline
was recorded on, since another machine's differ anyway; allocations and the UI's size are compared anywhere. After a
change meant to cost more, or one that made something faster, record a new baseline from a full run on a quiet machine
(a benchmark run alone measures faster) and commit it with the change, so the baseline's history is the
performance's:

```
./gradlew perfTest -PupdatePerf=true
```

**Conformance asks Spring, not a golden.** A fixture's expected graph is written by whoever wrote the analyzer, so a
misreading of Spring can sit in both and pass. `conformanceTest` checks the graph against the application itself: a
fixture with an application class runs as it (through its main method when it has one), and one without is hosted in
a Boot application that scans its package (without Boot's default chains when it secures nothing itself, as the
scanner reads it). What the shared classpath leaves a fixture without, though it would have it in an application of
its own (a repository, a template, Boot's default user), gets a stand-in that does nothing, never a security bean; the
report says which. An answer that is neither a denial nor a handler's (a 404, a handler that failed before its checks)
and a fixture that still can't start are skipped with the reason. When a disagreement is understood rather than fixed
(a check whose denial returns normally, a field check that fails the whole response), list it in
`known-differences.tsv` with why; a summary line names entries that explained nothing. A fixture that leaves method
security to AspectJ (`ConformanceExpectations.WOVEN`) is checked twice: as compiled, and as `<fixture>+woven`, its
classes woven with AspectJ's weaver, scanned and booted from those (in a loader of their own, as mutants are).

Fields are asked too. For a response field whose requirement is stricter than its endpoint's, the expectations carry
its JSON path, requirement and how the graph says its checks answer a denied caller; `FieldProbes` sends a caller who
meets the endpoint and every such field (twice: the field's value must not change), and that caller without each of a
field's clauses, and `BodyFields` reads the field out of each JSON body. A field the graph keeps from a caller must be
withheld (left out, `null`, or a value other than the full caller's: masked); one it gives must be written. A whole
response denied where a check the graph says throws fails is draft decision 0100's case (`FIELD_RESPONSE_FAILED`, not
a failure). What can't be found reliably (a rendered page, a GraphQL result, a stream, a map's values, an empty array,
a value the full caller doesn't get) is `FIELD_INCONCLUSIVE`. Every JSON response with fields is also read for its
shape: what it writes, in an object the graph lists fields of, at a path the graph lists no field for, is
`FIELD_UNLISTED`, an exposure the graph doesn't show (a record component named `isbn` was the first). Known
differences match field probes by their label, `field <path>: <caller>` or `unlisted <path>: <caller>`.

**Mutation asks whether the diff notices.** `./gradlew mutationTest` changes each Java fixture the ways pull requests
weaken authorization (a method check dropped, one an `authtracer.yaml` rule describes too, a rule loosened, reordered or
moved behind an early `permitAll()`, a matcher narrowed or widened, method security off, a custom manager that grants
everyone), one change at a time. Each mutant is compiled, scanned and diffed against the fixture as it is, then booted
with the conformance harness and sent the same callers as the original. A mutant Spring now lets someone into is MISSED
when the diff is silent there, and fails unless `src/conformance/resources/known-missed.tsv` explains it; one where the
graph already disagreed with Spring before the change is BLIND (a conformance disagreement, not the diff's). Fields
are judged the same way: where a graph has fields that ask more than their endpoint, the callers include one meeting
every such field and that one without each field's clauses or with each alternative instead, each response is read
for those fields, and a field written for a caller it was withheld from before is a weakening of that field. The report,
with every caller's answer, is `build/reports/mutation`. `-Pfixtures=a,b`, `-Poperators=DROP_RULE,...` and
`-PmutantsPerOperator=n` keep a run short; `MutationScans.mutate(fixture, change)` gives a test the two graphs.

**Coverage is a floor, not a goal.** A test asserts what the code does for a real application's shape; code no
application can reach is deleted rather than tested.

**Fixtures** are the backbone of the unit tests. Each is a small application in its own package,
`src/fixtures/{java,kotlin,groovy}/fixtures/<name>`, with properties in `src/fixtures/resources/<name>` if it needs
any. A test scans it with `FixtureScans.scan("<name>")` and asserts on the graph:

```java
private final ApplicationGraph graph = FixtureScans.scan("threadhops");

@Test
void workHandedToAnotherThreadIsCheckedThereWithoutTheCaller() {
    assertThat(mechanisms(graph, "ingress:GET /submit")).contains("@PreAuthorize (other thread)");
}
```

**Goldens:** after a change that is meant to alter the example services' graphs, rewrite them with
`./gradlew integrationTest -PupdateGolden=true` and read the diff of `src/integrationTest/resources/golden/` before
committing. The golden diff is the review: every changed line should be one you expected.

## 6. Your first change: teaching the scanner something new

Say Spring gains a new kind of endpoint and the scanner doesn't see it yet. The usual steps:

1. **Write a fixture** that uses it the way a real application would, under `src/fixtures/java/fixtures/<name>`.
   Include the case that should be checked and one that shouldn't, so the test can tell them apart.
2. **Write the test first**, `src/test/java/dev/crain/authtracer/scan/spring/<Name>FixtureTests.java`, asserting the
   Ingress, its checks in order, and any finding. Run it and watch it fail:
   `./gradlew test --tests '*<Name>FixtureTests'`.
3. **Read the library's behaviour** from its bytecode (`javap -c -p` on the jar in `~/.gradle/caches`) rather than from
   memory or documentation: defaults and registration order are where the surprises are.
4. **Add the detector**: a class in `scan/spring/` in the style of its neighbours (`ScheduledTasks` and
   `SensitiveEndpoints` are short examples), wired into `SpringSecurityModule.scan`.
5. **If the UI needs to say something new** (a new finding kind or entry kind), add its text to
   `frontend/src/lib/format.ts` so the Legend and the Findings view explain it.
6. **Run everything**: `./gradlew test integrationTest`, and `systemTest` if linking or tracing changed. Update goldens
   only when the change is intended.

## 7. The UI

The UI is a React application in `frontend/`, built by Vite into the server's static resources, so
`./gradlew bootRun` serves it on http://localhost:8080. For UI work, run the dev server for instant reloads:

```
./gradlew bootRun                     # the API, in one terminal
cd frontend && npm run dev            # the UI on http://localhost:5173, proxying /api to :8080
```

| Path | What lives there |
|---|---|
| `src/lib/` | Graph types (`types.ts`), the `Model` over a system graph (`model.ts`), text helpers (`format.ts`), the API client, and the app state (`store.ts`, Zustand) |
| `src/components/ui/` | Small, shadcn-style primitives on Radix UI: buttons, badges, cards, selects, tooltips |
| `src/features/<view>/` | One folder per view. Pure logic (grouping, layout) sits in `.ts` files with tests next to them; rendering in `.tsx` |
| `src/features/paths/` | Request paths: alike paths merged into one card (`pathGroups.ts`), laid out in lanes (`pathLayout.ts`), drawn with React Flow |
| `src/features/lineage/` | Field lineage: classes as boxes, flows as arrows (`lineageLayout.ts`) |

The UI's one design rule: **merge what is alike so the differences stand out.** Endpoints whose paths end the same way
share a card, fields that ask nothing beyond their endpoint fold into one row, findings that differ in a word become
one finding with a blank. When adding a view, look for what repeats before drawing it.

Checks for UI changes: `npm run typecheck`, `npm run coverage` (`npm test` without the report), and a look at the page
in both themes (the toggle is at the bottom of the sidebar). Pure logic is tested in a `.test.ts` next to it, in Node;
a view in a `.test.tsx`, in jsdom, through what a person sees and clicks (`src/test/` has the graph builders, a stubbed
server, and the browser parts jsdom lacks).

## 8. Conventions

- **Dependencies:** the backend uses Spring and what Spring's BOM manages; anything else needs the maintainer's
  approval. The frontend may use well-known libraries, pinned to exact versions in `package.json`.
- **Comments say why**, in full sentences, and are kept short. A known gap that is left for later is an `@Might`
  annotation, not a TODO, so `grep -r @Might` lists them all.
- **Features:** every class says which features it is needed for with `@Supports(Feature.X)`, and every UI file with a
  first line `// @supports X`. `CodebaseGuideTests` fails on code that doesn't, and keeps
  [`codebase/features.md`](codebase/features.md) in step: rewrite it with
  `./gradlew test --tests '*CodebaseGuideTests' -PupdateGuide=true` after changing them. The guide's links carry line
  anchors that `scripts/guide-anchors.sh` refreshes on demand.
- **Decisions** are numbered (`decision 0062` in a comment). Each records what was decided and why, and the comment
  points at it so the reasoning can be found from the code.
- **Names** follow the vocabulary above: a check is an `AuthorizationLocation`, a way in is an `Ingress`, and so on.
  The UI uses the same words.
- **Commits** describe the behaviour, not the edit ("Work handed to another thread leaves the SecurityContext
  behind"), with the tests in the same commit.

## 9. Where to look when...

| You want to... | Start at |
|---|---|
| See why an endpoint needs what it needs | The UI's Exposures view, then `diff/Exposures.java` |
| Find out why a check isn't on a path | `CallTraversal`, then `Proxies` (is the call proxied?) and `AsyncCalls` (another thread?) |
| See why two services didn't link | `link/Routes.java` (template matching) and `Linker.protocol` (protocols are kept apart) |
| Change how a diff classifies a change | `diff/GraphDiff.java` and `diff/Clauses.java` (what "weaker" means) |
| Add a CLI option | `cli/CliRunner.java` (usage text) and `cli/DiffCommands.java` |
| Change the graph JSON | `graph/` records, `GraphJson`, then `frontend/src/lib/types.ts` |
