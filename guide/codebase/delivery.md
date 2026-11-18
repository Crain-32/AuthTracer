# Delivery: the command line, the server and the UI

How people get AuthTracer's answers. Everything the other pages describe ends up in one of three places: a file the
command line or the scanner image writes (and its exit code), a snapshot the server stores and serves over its REST
API, or a view of the UI. This page follows each from its entry point to what it writes or draws: first the command
line with its Gradle tasks and scripts, then the scanner image, then the server, then the UI's shell, and then one
section per view.

How to use them is in the [reference](../reference.md) and the [tutorial](../tutorial.md); this page is about how they
work. The overall picture:

```
 scan ──▶ graph.json ──(--publish)──▶ POST /api/graphs ──▶ GraphStore (H2, ./data)
 scanner image: /in/*.jar ──▶ /out/<service>.json, with no network
 link ──▶ system.json                 POST /api/system/link ──▶ Linker + Zipkin ──▶ GraphStore
 diff ──▶ report.md, diff.json, SARIF, agent report; exit code 1 when authorization got weaker
                                      GET /api/system, /api/system/exposures ──▶ UI: Model ──▶ views
 diff.json ──(Open file)──────────────────────────────────────────────────────▶ UI: Diff report
```

## The command line

**Feature:** [`COMMAND_LINE`](features.md#command_line)

Six commands (`scan`, `link`, `diff`, `exposures`, `policies`, `identities`) that read and write files, print a
Markdown report, and answer with an exit code a build can act on: `0` ok, `1` a verdict (authorization got weaker, a
policy is broken, an identity is over-scoped), `2` a usage mistake, `3` the command couldn't finish. The Gradle tasks
`authtracer` and `authtracerDiff` run it, and the scripts in `scripts/` drive it for a coding agent's hook and the demo.

**How it works**

1. [`AuthTracerCli.main`](../../src/main/java/dev/crain/authtracer/cli/AuthTracerCli.java#L22) calls
   [`AuthTracerCli.run`](../../src/main/java/dev/crain/authtracer/cli/AuthTracerCli.java#L31), which starts the same
   Spring application as the server, [`AuthTracerApplication`](../../src/main/java/dev/crain/authtracer/AuthTracerApplication.java#L16),
   with no web server, no banner, quiet logging and the `cli` profile. The profile turns on
   [`CliRunner`](../../src/main/java/dev/crain/authtracer/cli/CliRunner.java#L38) (it is `@Profile("cli")`, so the server
   never runs it) and [`application-cli.yaml`](../../src/main/resources/application-cli.yaml), which puts the
   datasource in memory so the command line never opens the server's H2 file. If the context can't start at all, `run`
   prints why and returns `3`.
2. [`CliRunner.run`](../../src/main/java/dev/crain/authtracer/cli/CliRunner.java#L91) runs as an `ApplicationRunner`
   during startup. It parses the arguments with
   [`CliArguments.parse`](../../src/main/java/dev/crain/authtracer/cli/CliArguments.java#L25) and dispatches on the
   command. A [`UsageException`](../../scanner/src/main/java/dev/crain/authtracer/UsageException.java#L11) becomes `2` and prints
   [`CliRunner.USAGE_TEXT`](../../src/main/java/dev/crain/authtracer/cli/CliRunner.java#L58); any other
   `RuntimeException` becomes `3` (its stack trace is logged at debug). The code is kept in a field that
   [`CliRunner.getExitCode`](../../src/main/java/dev/crain/authtracer/cli/CliRunner.java#L196) hands to
   `SpringApplication.exit`, and `main` passes it to `System.exit`.
3. [`CliArguments.parse`](../../src/main/java/dev/crain/authtracer/cli/CliArguments.java#L25) takes the first argument as
   the command unless it starts with `--`, then reads `--name value`, `--name=value`, and a bare `--flag` as `"true"`;
   anything else is a usage mistake. Commands read options through its helpers:
   [`required`](../../src/main/java/dev/crain/authtracer/cli/CliArguments.java#L99),
   [`CliArguments.file`](../../src/main/java/dev/crain/authtracer/cli/CliArguments.java#L106) (given, it must name an
   existing file), [`CliArguments.number`](../../src/main/java/dev/crain/authtracer/cli/CliArguments.java#L117) and
   [`CliArguments.list`](../../src/main/java/dev/crain/authtracer/cli/CliArguments.java#L126) (comma-separated, empty
   entries dropped).
4. **scan**: [`CliRunner.scan`](../../src/main/java/dev/crain/authtracer/cli/CliRunner.java#L122) builds a `ScanInput`
   in one of two ways. With `--project`, [`ProjectScans.project`](../../scanner/src/main/java/dev/crain/authtracer/scan/ProjectScans.java#L42)
   builds the Gradle or Maven project, names the service (`--service`, else `spring.application.name`, else the
   directory) and reads its `authtracer.yaml`. With `--classes`, the input is put together from the options:
   `--classes`, `--libraries` and `--resources` split on the platform's path separator, `--service` required, the
   revision [`ProjectScans.WORKING_TREE`](../../scanner/src/main/java/dev/crain/authtracer/scan/ProjectScans.java#L28) unless
   given, and the facts from [`ProvidedFacts.load`](../../scanner/src/main/java/dev/crain/authtracer/provided/ProvidedFacts.java#L47).
   Either way [`ProjectScans.defaultScanner`](../../scanner/src/main/java/dev/crain/authtracer/scan/ProjectScans.java#L34) scans
   it and [`GraphJson.write`](../../scanner/src/main/java/dev/crain/authtracer/graph/GraphJson.java#L57) writes `--out` (see
   [scanning](scanning.md)).
5. **scan --publish**: after the file is written,
   [`CliRunner.publish`](../../src/main/java/dev/crain/authtracer/cli/CliRunner.java#L144) POSTs the graph's JSON to
   `api/graphs` resolved under the URL given (so a server behind a proxy at `http://host/authtracer` works). Anything
   but `201`, or no answer, is `3`: the graph is on disk but not on the server.
6. **link**: [`CliRunner.link`](../../src/main/java/dev/crain/authtracer/cli/CliRunner.java#L172) reads every file of
   `--graphs` with [`GraphJson.read`](../../scanner/src/main/java/dev/crain/authtracer/graph/GraphJson.java#L65) (none is a usage
   mistake) and picks a trace source: a `--traces` file ([`ZipkinTraces.file`](../../src/main/java/dev/crain/authtracer/link/ZipkinTraces.java#L92)),
   else a `--zipkin` server ([`ZipkinTraces.api`](../../src/main/java/dev/crain/authtracer/link/ZipkinTraces.java#L44),
   `--lookback` minutes, default 60, at most 1000 traces), else none
   ([`ZipkinTraces.of`](../../src/main/java/dev/crain/authtracer/link/ZipkinTraces.java#L105) an empty list). A new
   [`Linker.link`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L114) joins them (see [the system](system.md))
   and the system graph goes to `--out`.
7. **diff**: [`DiffCommands.diff`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L52) gets a base and a
   head system graph in one of two ways.
   - From files: `--base` and `--head` through [`GraphJson.readAny`](../../scanner/src/main/java/dev/crain/authtracer/graph/GraphJson.java#L104),
     which takes an application graph as a system of one service.
   - From a project (the pull-request check): `--project` with `--base-ref` or `--base-project`, checked before
     anything is built. The head is the working tree, or `--head-ref` checked out by
     [`DiffCommands.scanRevision`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L204) into a temporary
     [`GitWorktree.checkout`](../../scanner/src/main/java/dev/crain/authtracer/scan/GitWorktree.java#L41), recorded as
     `<ref>@<commit>` unless `--revision` names it. The base is `--base-project` (revision `base`) or `--base-ref`
     checked out the same way, and it is always scanned under the head's service name. With `--context <system.json>`,
     [`DiffCommands.withContext`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L219) puts each of the two
     graphs among the context's other services and relinks statically, so a change shows where its effects land. The
     project joins `--sources` for SARIF.

   Then [`GraphDiff.compare`](../../src/main/java/dev/crain/authtracer/diff/GraphDiff.java#L46) makes the report (see
   [analysis](analysis.md)), and each output asked for is written: `--report` (its
   [`DiffReport.markdown`](../../src/main/java/dev/crain/authtracer/diff/DiffReport.java#L115)), `--json` (the report
   itself, which the UI's Diff report opens), `--sarif` ([`SarifReport.write`](../../src/main/java/dev/crain/authtracer/diff/SarifReport.java#L62))
   and `--agent-report` ([`AgentReport.write`](../../src/main/java/dev/crain/authtracer/diff/AgentReport.java#L29)). The
   Markdown is printed, and [`DiffReport.failed`](../../src/main/java/dev/crain/authtracer/diff/DiffReport.java#L99)
   (with `--fail-on-review true`, REVIEW counts too) decides `1` or `0`.
8. **exposures**: [`DiffCommands.exposures`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L112) prints a
   table of [`Exposures.of`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L143) for the graph, keeping
   only the rows whose field or one of whose sources contains `--field`. Always `0`.
9. **policies**: [`DiffCommands.policies`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L142) lists the
   exposures with policy violations, one row per violation, and returns `1` when there are any.
10. **identities**: [`DiffCommands.identities`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L178) lists
    the system graph's identities (from traces, see [the system](system.md)). It returns `1` only with
    `--fail-on-unneeded true` and an identity holding authorities its requests didn't need.

**Gradle tasks and scripts**

| What | How it drives the command line |
|---|---|
| [`authtracer`](../../build.gradle#L554) | A `JavaExec` of `AuthTracerCli` on the main runtime classpath without devtools, in the AuthTracer directory, so relative paths start there. The UI isn't on that classpath, so it needs no Node.js |
| [`authtracerDiff`](../../build.gradle#L575) | The same, with the arguments of `diff --project` made from Gradle properties when the task runs: `-PdiffProject` (required), `-PbaseRef`, `-PbaseProject`, `-PheadRef`, `-Pcontext`, `-PorgFacts`, `-Psarif`, `-PagentReport`, `-PfailOnReview`, and `-Preport` (default `build/reports/authtracer/diff.md`). Any non-zero exit fails the build |
| [`agent-check.sh`](../../scripts/agent-check.sh) | Runs `authtracerDiff` with the agent report in a temporary file. Passing exits `0`; failing with a report prints it to stderr and exits `2`, which a Claude Code `Stop` hook feeds back to the agent; anything else (no report written) exits `1` |
| [`demo.sh`](../../scripts/demo.sh) | Runs the command line from the boot jar (`PropertiesLauncher` with `-Dloader.main=...AuthTracerCli`, since the jar's main class is the server's): `scan --publish` for the four example services, then `curl -X POST /api/system/link`, then `diff --project --base-project --context --json --report` on two altered copies of employee-service, for the UI's Diff report |
| [`traffic.sh`](../../scripts/traffic.sh), [`token.sh`](../../scripts/token.sh) | Drive the example services as four users, so Zipkin holds traces for `link` to read. They don't call AuthTracer |

**Relies on / relied on by**

It is the delivery of most of the analysis features: [`PROJECT_BUILDS`](features.md#project_builds)
(`ProjectScans`, `GitWorktree`), [`PROVIDED_FACTS`](features.md#provided_facts) (`--facts`, `--org-facts`),
[`SYSTEM_GRAPH`](features.md#system_graph) and [`TRACE_OBSERVATIONS`](features.md#trace_observations) (`link`),
[`DIFF`](features.md#diff), [`SARIF_ANNOTATIONS`](features.md#sarif_annotations) and
[`AGENT_REPORT`](features.md#agent_report) (only the command line writes them),
[`EXPOSURES`](features.md#exposures), [`POLICIES`](features.md#policies) and [`IDENTITIES`](features.md#identities).
The server gets its graphs from `scan --publish`, and the UI's [Diff report](#the-diff-report-view) opens what
`diff --json` writes.

**Tests**

- [`AuthTracerCliTests`](../../src/test/java/dev/crain/authtracer/cli/AuthTracerCliTests.java#L27): the exit code through
  a real context, a usage mistake, and a context that can't start.
- [`CliArgumentsTests`](../../src/test/java/dev/crain/authtracer/cli/CliArgumentsTests.java#L14): the argument forms and
  helpers.
- [`CliRunnerTests`](../../src/test/java/dev/crain/authtracer/cli/CliRunnerTests.java#L35): each command and its exit
  codes, publishing (to a closed port, a refusing server, and a server under a path), link with a traces file and
  with Zipkin, every diff output.
- [`ProjectDiffTests`](../../src/test/java/dev/crain/authtracer/cli/ProjectDiffTests.java#L36): `diff --project` against a
  stand-in build that hands back the [`projectdiffbase`](../../src/fixtures/java/fixtures/projectdiffbase/) and
  [`projectdiffhead`](../../src/fixtures/java/fixtures/projectdiffhead/) fixtures, with a base project, a context and a
  base ref.
- [`DiffProjectTests`](../../src/integrationTest/java/dev/crain/authtracer/cli/DiffProjectTests.java#L24) (integration):
  the pull-request check on employee-service in a subdirectory of a git repository, as in a monorepo.

**Before changing it**

- **`1` is a verdict and nothing else.** A pull-request check reads `1` as "authorization got weaker", so whatever
  breaks (a build, a malformed file, a failed publish, a context that can't start) must be `3`. `2` is for how the
  command was called: a missing or malformed option, a file option naming no file, a path naming no project
  (`UsageException` is also thrown from `scan/build`). A file whose content is wrong is `3`, not `2`.
- `CliArguments.file` checks that a given file exists, so a mistyped facts path is a usage mistake rather than
  silently "no facts".
- The arguments reach Spring too, as command-line properties: `--authtracer.zipkin.lookback=an-hour` stops the context
  from starting (`3`), and `--logging.level.dev.crain.authtracer=DEBUG` shows the stack trace of a failure.
- Keep the `cli` profile's in-memory datasource: H2 locks its file, and the command line runs while the server is up.
- `diff --project` scans the base under the head's service name and names a temporary checkout after the project's
  directory, so a renamed directory or a worktree compares with itself rather than reporting every endpoint as new.
  The base option is checked before the head is built, so a forgotten `--base-ref` fails in a second, not after a build.
- `agent-check.sh` turns the command line's codes round on purpose: for an agent hook `2` means "fix this", so its
  own failures are `1`.

## The scanner image

**Feature:** [`SCANNER_IMAGE`](features.md#scanner_image)

The scanner without the server, in a container that scans only where nothing can reach out or be changed: the built
jars and wars read-only at `/in`, the graphs written to `/out`, no network, as the owner of `/out`, within a time and
a memory limit. It is for scanning after the build on any network; the graphs it writes are files for `link`, `diff`
or `scan --publish`'s server to take. A build plugin would call `ArtifactScans` itself instead.

**How it works**

1. **The image.** [`scanner-image`](../../scanner-image/build.gradle#L34) is a Gradle subproject: an `application` of
   [`ScanArtifacts`](../../scanner-image/src/main/java/dev/crain/authtracer/image/ScanArtifacts.java#L45) on the `scanner` and `annotations` jars, logging with
   `slf4j-simple`, without the root project's server, store or UI. [`dockerContext`](../../scanner-image/build.gradle#L44)
   copies `installDist`'s `lib/` and [`src/main/docker`](../../scanner-image/src/main/docker) into `build/docker`, and
   [`dockerImage`](../../scanner-image/build.gradle#L59) runs `docker build` there, tagging `authtracer-scanner:<version>`
   and `latest`. The [`Dockerfile`](../../scanner-image/src/main/docker/Dockerfile) starts from Temurin's Java 25 JRE,
   pinned by digest, copies the jars read-only, and sets no `USER` (GitHub's Docker actions run as root) and no
   `VOLUME` (an anonymous volume would quietly keep the graphs when `/out` isn't mounted).
2. **The entrypoint.** [`entrypoint.sh`](../../scanner-image/src/main/docker/entrypoint.sh) exits `2`, with the
   `docker run` line to use on stderr, when:
   - the container has a network: an interface other than `lo` that is up (`IFF_UP` in `/sys/class/net/*/flags`).
     Every network namespace has the kernel's fallback tunnels (`tunl0`, `sit0`, ...), down, and without `NET_ADMIN`
     nothing in the container can bring them up;
   - nothing is at `/in`, or `/out` isn't a mount point;
   - it runs as root, `/out` belongs to someone else, and `setpriv` can't become them (no `SETUID` capability). With
     the capability it runs itself again as `/out`'s owner, so the graphs are theirs. Root with a root-owned `/out`
     only warns: in rootless Docker or Podman, and Docker Desktop, root is the person running it;
   - it can't write to `/out` or `/tmp`.

   Then it runs Java under `timeout --kill-after=30s ${AUTHTRACER_TIMEOUT:-15m}`, with the heap at 60% of the
   container's memory (the rest is the JVM's own and the unpacked artifacts', whose tmpfs counts against the same
   limit) and `ExitOnOutOfMemoryError`. It passes `docker stop`'s TERM on (as PID 1, the shell would ignore it), and
   adds a line for `124` (timed out) and `137` (killed, most likely for memory).
3. **The scan.** [`ScanArtifacts.run`](../../scanner-image/src/main/java/dev/crain/authtracer/image/ScanArtifacts.java#L58) reads its settings from the environment, lists
   the `.jar` and `.war` files directly in `/in`, passes over what
   [`ArtifactScans.scannable`](../../scanner/src/main/java/dev/crain/authtracer/scan/ArtifactScans.java#L93) refuses, and
   for each one unpacks it into a fresh directory under `/tmp`, scans it ([scanning](scanning.md#scanning-a-built-artifact)),
   writes `<service>.json` and deletes the directory. The revision is `AUTHTRACER_REVISION`, else `GITHUB_SHA`'s first
   seven characters, else what the artifact records. [`ScanArtifacts.write`](../../scanner-image/src/main/java/dev/crain/authtracer/image/ScanArtifacts.java#L157) writes
   `.<service>.json.partial` and renames it, so a scan stopped by the time limit leaves no half a graph, and
   [`ScanArtifacts.fileName`](../../scanner-image/src/main/java/dev/crain/authtracer/image/ScanArtifacts.java#L177) keeps a service's name, which comes from the artifact, from
   naming a file outside `/out`. A second artifact of a service already written fails rather than replacing it.
4. **Exit codes.** `0` every artifact scanned; `2` run wrongly (the entrypoint's checks, nothing to scan,
   `AUTHTRACER_SERVICE` with several artifacts, a facts file that isn't there); `3` an artifact couldn't be scanned
   (the others were) or the heap ran out; `124` timed out; `137` killed.
5. [`scan-artifacts.sh`](../../scripts/scan-artifacts.sh) runs it as it should be run: `--network none --read-only
   --tmpfs /tmp:size=2g --cap-drop ALL --security-opt no-new-privileges --memory ${AUTHTRACER_MEMORY:-4g} --user`
   the caller, `/in` read-only, the output directory made first so it is the caller's, and the facts files the
   environment names mounted read-only.

**Relies on / relied on by**

Everything it scans goes through [`BUILT_ARTIFACTS`](features.md#built_artifacts), and from there the whole scan.
Nothing relies on it.

**Tests**

- [`ScanArtifactsTests`](../../scanner-image/src/test/java/dev/crain/authtracer/image/ScanArtifactsTests.java#L28)
  (`./gradlew :scanner-image:test`, part of `check`): which artifacts are scanned or passed over, where the graphs go,
  the revision from `GITHUB_SHA`, the exit codes, and file names from service names.
- [`ScannerImageTests`](../../src/systemTest/java/dev/crain/authtracer/system/ScannerImageTests.java#L24) (`systemTest`,
  which builds the image): the example services' Boot jars through `scan-artifacts.sh` give their golden graphs, and
  the image refuses a network, a missing `/out` and root it can't drop, and stops at its time limit.

**Before changing it**

- **The entrypoint's checks are the security.** The image is meant to be run anywhere, so it refuses rather than
  trusting the command it was run with. A new way in or out (another mount, a setting naming a URL) needs its own
  check, and a message saying how to run it.
- **The exit codes are a contract**, written in the entrypoint's header, `ScanArtifacts` and the
  [reference](../reference.md#scanner-image). `1` stays unused, as on the command line, where it is a verdict.
- **The image has no server in it.** `scanner-image` depends on `:scanner`, not the root project, which would bring
  Spring MVC, H2 and the UI with it.
- **`dockerImage` and `systemTest` take Docker from the PATH Gradle was run with**: a Gradle daemon keeps the PATH it
  started with, which may not have it.

## The server

**Feature:** [`GRAPH_SERVER`](features.md#graph_server)

A Spring Boot web application (`./gradlew bootRun`, or the boot jar) that stores every published graph and every link
in H2 under `./data`, links the newest graph of each service with Zipkin's recent traces on request, and serves graphs
and their exposures over a REST API at `/api`, with the UI as its static resources.

**How it works**

1. [`AuthTracerApplication.main`](../../src/main/java/dev/crain/authtracer/AuthTracerApplication.java#L18) starts it
   with [`application.yaml`](../../src/main/resources/application.yaml): port 8080 on `127.0.0.1` only (the API has no
   authentication), H2 in the file `./data/authtracer`, [`schema.sql`](../../src/main/resources/schema.sql) run on
   every start, and Jackson tolerant of graphs from older scanners (unknown properties are ignored, a `null`
   primitive reads as its default). [`AuthTracerProperties`](../../src/main/java/dev/crain/authtracer/AuthTracerProperties.java#L14)
   binds `authtracer.*`: [`AuthTracerProperties.Api`](../../src/main/java/dev/crain/authtracer/AuthTracerProperties.java#L19)
   (the body limit) and [`AuthTracerProperties.Zipkin`](../../src/main/java/dev/crain/authtracer/AuthTracerProperties.java#L29)
   (base URL, lookback, limit), which
   [`AuthTracerApplication.traceSource`](../../src/main/java/dev/crain/authtracer/AuthTracerApplication.java#L24) turns
   into a `ZipkinTraces.api` bean; [`AuthTracerApplication.linker`](../../src/main/java/dev/crain/authtracer/AuthTracerApplication.java#L30)
   adds the `Linker`.
2. Before a controller sees a posted graph,
   [`RequestBodyLimit`](../../src/main/java/dev/crain/authtracer/api/RequestBodyLimit.java#L34) caps its size (Tomcat's
   own limit covers forms only). [`RequestBodyLimit.shouldNotFilter`](../../src/main/java/dev/crain/authtracer/api/RequestBodyLimit.java#L52)
   lets everything but `POST /api/graphs` and `POST /api/exposures` through.
   [`RequestBodyLimit.doFilterInternal`](../../src/main/java/dev/crain/authtracer/api/RequestBodyLimit.java#L58) answers
   `413` when the declared length is over `authtracer.api.max-body-size` (64 MB). A chunked body, with no length, is
   read up to one byte past the limit and passed on as a
   [`RequestBodyLimit.ReadBody`](../../src/main/java/dev/crain/authtracer/api/RequestBodyLimit.java#L87) holding the bytes.
3. `POST /api/graphs`: [`GraphController.publish`](../../src/main/java/dev/crain/authtracer/api/GraphController.java#L47)
   binds an `ApplicationGraph`, checks it with
   [`GraphValidation.check`](../../src/main/java/dev/crain/authtracer/api/GraphValidation.java#L36) (`400` with the reason
   when it fails), and stores it with [`GraphStore.save`](../../src/main/java/dev/crain/authtracer/store/GraphStore.java#L37),
   answering `201` with the [`GraphStore.Snapshot`](../../src/main/java/dev/crain/authtracer/store/GraphStore.java#L28).
4. `GraphValidation.check` asks what linking and exposures will dereference: a service name that is not blank, has no
   `/` and fits the store's column ([`GraphValidation.MAX_SERVICE_LENGTH`](../../src/main/java/dev/crain/authtracer/api/GraphValidation.java#L28),
   255); an id on every node; a method and route on each Ingress, a method and URI template on each Egress; a field id
   of the form `field:<class>.<property>` with an owner and a JSON name; a scope and a requirement of a known kind
   (all the way down) on each Location; both ends on each edge; and each Provided fact through
   [`ProvidedFacts.validate`](../../scanner/src/main/java/dev/crain/authtracer/provided/ProvidedFacts.java#L255). For a system
   graph, its links and flows must join qualified ids (`service/node`).
5. `GET /api/graphs` ([`GraphController.list`](../../src/main/java/dev/crain/authtracer/api/GraphController.java#L62))
   lists the snapshots, newest first. `GET /api/graphs/{service}[?revision=]`
   ([`GraphController.graph`](../../src/main/java/dev/crain/authtracer/api/GraphController.java#L69)) answers
   [`GraphStore.latest`](../../src/main/java/dev/crain/authtracer/store/GraphStore.java#L54) or
   [`GraphStore.application`](../../src/main/java/dev/crain/authtracer/store/GraphStore.java#L59), or `404`.
6. `POST /api/system/link`: [`GraphController.link`](../../src/main/java/dev/crain/authtracer/api/GraphController.java#L86)
   takes [`GraphStore.latestApplications`](../../src/main/java/dev/crain/authtracer/store/GraphStore.java#L68) (the newest
   graph of each service; none is `422`), links them with the trace source wrapped so that a Zipkin it can't read
   gives no traces and a warning instead of a failure, stores the system graph (its revision lists every
   `service@revision`), and answers it.
7. `GET /api/system` ([`GraphController.system`](../../src/main/java/dev/crain/authtracer/api/GraphController.java#L110))
   answers [`GraphStore.latestSystem`](../../src/main/java/dev/crain/authtracer/store/GraphStore.java#L74), or `404`.
8. `GET /api/system/exposures`
   ([`ExposureController.systemExposures`](../../src/main/java/dev/crain/authtracer/api/ExposureController.java#L40))
   answers the newest system graph's exposures, or `404`. `POST /api/exposures`
   ([`ExposureController.exposures`](../../src/main/java/dev/crain/authtracer/api/ExposureController.java#L56)) does the
   same for the application or system graph in the body (read with `GraphJson.readAny` and validated; `400` with
   Jackson's or the validation's message), and stores nothing: the UI uses it for a stored service graph and for
   files.
9. [`ExposureView.of`](../../src/main/java/dev/crain/authtracer/api/ExposureView.java#L43) shapes each
   [`Exposures.of`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L143) row for the UI. For a field, `adds`
   is what it asks beyond its endpoint's exposure ([`Clauses.added`](../../src/main/java/dev/crain/authtracer/diff/Clauses.java#L329)):
   `""` for nothing more, `null` when that can't be written as an addition. Each step becomes a
   [`ExposureView.StepView`](../../src/main/java/dev/crain/authtracer/api/ExposureView.java#L39) in
   [`ExposureView.step`](../../src/main/java/dev/crain/authtracer/api/ExposureView.java#L64): its requirement as text
   (`permitAll`, or [`Clauses.describe`](../../src/main/java/dev/crain/authtracer/diff/Clauses.java#L341)), its scope, and
   for a field check the qualified id of the field it guards, which is how the lineage view puts checks on rows.
10. [`GraphStore`](../../src/main/java/dev/crain/authtracer/store/GraphStore.java#L23) keeps one table,
    `graph_snapshot`: id, kind (`APPLICATION` or `SYSTEM`), service, revision, time and the JSON. Nothing is ever
    replaced; "latest" is the highest id. A revision published twice reads as its newest snapshot.
11. The UI is the server's static content: the [`frontendBuild`](../../build.gradle#L330) task builds `frontend/` into
    `build/frontend/static`, which joins the classpath of `bootRun`, `bootJar` and the tests, and Spring Boot serves its
    `index.html` at `/`.

**Relies on / relied on by**

Relies on [`SYSTEM_GRAPH`](features.md#system_graph) (`Linker`), [`TRACE_OBSERVATIONS`](features.md#trace_observations)
(`ZipkinTraces.api`), [`EXPOSURES`](features.md#exposures) (`Exposures`, `Clauses`, `Policies`' violations) and
`GraphJson`. The [UI](#the-ui-shell) reads everything through it; `scan --publish` and `demo.sh` fill it.

**Tests**

- [`AuthTracerApplicationTests`](../../src/test/java/dev/crain/authtracer/AuthTracerApplicationTests.java#L39): publish,
  list, fetch and link end to end, the `127.0.0.1` default, and that the built UI and everything it loads is served.
- [`GraphControllerTests`](../../src/test/java/dev/crain/authtracer/api/GraphControllerTests.java#L37): bad graphs are
  `400` and not stored, revisions, Provided facts, an unreachable Zipkin linking statically.
- [`ExposureControllerTests`](../../src/test/java/dev/crain/authtracer/api/ExposureControllerTests.java#L44): field checks
  tied to their fields, requirements and lineage across services, `permitAll`, bodies that aren't graphs.
- [`GraphValidationTests`](../../src/test/java/dev/crain/authtracer/api/GraphValidationTests.java#L30),
  [`RequestBodyLimitTests`](../../src/test/java/dev/crain/authtracer/api/RequestBodyLimitTests.java#L21),
  [`NothingStoredTests`](../../src/test/java/dev/crain/authtracer/api/NothingStoredTests.java#L29) (the `404`s and the
  `422`) and [`GraphStoreTests`](../../src/test/java/dev/crain/authtracer/store/GraphStoreTests.java#L18) (latest per kind
  and service, a revision published twice, and a system revision too long for an old database's column).

**Before changing it**

- A stored graph that linking or exposures can't read breaks them for every service until its own is published again,
  which is why validation happens on the way in. When the linker or `Exposures` starts relying on a property, check it
  in `GraphValidation`.
- Qualified ids split at the first `/`, in the server and in the UI, so a service name must never contain one; node
  ids may (routes do).
- The status codes are read by the clients: `publish` expects exactly `201`; the UI says "No system graph stored yet"
  on `404` from `/api/system` and "No graphs stored yet" on `422` from the link.
- `schema.sql` runs on every start against databases created by earlier versions: keep it idempotent (`if not
  exists`, and the `alter` that widened `revision` for a system's list of services).
- Every publish and link adds a row; nothing prunes `./data`.
- The API has no authentication: keep the `127.0.0.1` default.

## The UI shell

**Feature:** [`UI`](features.md#ui)

A React application (TypeScript, Vite, Tailwind, React Flow, Zustand) in `frontend/`, served by the server. The shell
loads a graph (the newest system graph, a stored service graph, or a file), wraps it in a `Model` with the exposures the
server works out, and gives it to the view the sidebar or the address picks, with a details panel beside it. The
[onboarding guide](../onboarding.md#7-the-ui) covers working on it.

**How it works**

1. [`main.tsx`](../../frontend/src/main.tsx) mounts [`App`](../../frontend/src/App.tsx#L48) inside the tooltips'
   provider. The theme is set before that, by a script in [`index.html`](../../frontend/index.html), from the
   choice [`ThemeToggle`](../../frontend/src/components/ThemeToggle.tsx#L17) stored, else the system's preference.
2. On mount, `App` asks [`storedServices`](../../frontend/src/lib/api.ts#L53) for the service picker (failure reads
   "Server unavailable") and calls [`latest`](../../frontend/src/App.tsx#L66), which loads
   [`loadSystem`](../../frontend/src/lib/api.ts#L38): `GET /api/system`, then `GET /api/system/exposures`. A `404` reads
   "No system graph stored yet".
3. The header's other ways in: "Link stored graphs" ([`linkStored`](../../frontend/src/lib/api.ts#L49), `POST
   /api/system/link`, then `latest` again; `422` reads "No graphs stored yet"); a stored service graph
   ([`loadService`](../../frontend/src/lib/api.ts#L43): `GET /api/graphs/{service}`, then `POST /api/exposures`); and "Open
   file" or a drop on the page ([`openFile`](../../frontend/src/lib/api.ts#L61)). A file is told apart by
   [`kindOf`](../../frontend/src/lib/model.ts#L20): a system graph has `services`, an application graph `nodes`, a diff
   report `changes`. A diff report stays in the browser; a graph is sent to `POST /api/exposures`.
4. Every request goes through `request` in [`api.ts`](../../frontend/src/lib/api.ts), which turns a failure into a
   [`RequestError`](../../frontend/src/lib/api.ts#L5) carrying the status and the server's `detail`, `message` or `error`.
   Loads can overlap (the startup load, a file dropped meanwhile), so `App` counts them in `loads` and only the newest
   one's result or error counts; a file the person picks wins over a load still on its way.
5. [`Model`](../../frontend/src/lib/model.ts#L60) is built once per load. [`asSystem`](../../frontend/src/lib/model.ts#L35)
   makes an application graph a system of one service, and `complete` gives lists a graph leaves out as empty, as the
   server does. It indexes nodes by qualified id (`service/nodeId`), each Ingress's ordered edges
   ([`Model.path`](../../frontend/src/lib/model.ts#L117)), links from and to each node
   ([`Model.linksFrom`](../../frontend/src/lib/model.ts#L141), [`Model.linksTo`](../../frontend/src/lib/model.ts#L145)),
   observations ([`Model.observation`](../../frontend/src/lib/model.ts#L149),
   [`Model.linkObservation`](../../frontend/src/lib/model.ts#L153)), exposures by Ingress
   ([`Model.endpointExposure`](../../frontend/src/lib/model.ts#L166)) and every finding with its service
   ([`Model.findings`](../../frontend/src/lib/model.ts#L172), the linker's as "system (linker)"). Views ask it rather than
   scanning the graph, since they look things up once per row.
6. [`useUi`](../../frontend/src/lib/store.ts#L66) (Zustand) holds the model, the diff report, the view, the selection, the
   status line and each view's own state (paths, lineage, exposures). [`loadModel`](../../frontend/src/lib/store.ts#L50)
   starts every view afresh; [`show`](../../frontend/src/lib/store.ts#L52) closes the details when the view changes;
   [`showLineage`](../../frontend/src/lib/store.ts#L59) opens the lineage on one field and keeps the details open.
7. The view follows the address's hash (`#paths`, `#findings`, ...), so views can be linked to and Back works; a view
   opened from code gets its own history entry. [`ViewBody`](../../frontend/src/App.tsx#L284) picks the view; the Diff
   report and the Legend need no graph, the others show an empty state without one.
8. [`Stats`](../../frontend/src/App.tsx#L313) shows [`Model.stats`](../../frontend/src/lib/model.ts#L185) under the header:
   services, endpoints, the endpoints whose requirement is `none` ("No Authorization"), links (and how many traces
   observed) and findings. The sidebar's `VIEWS` table names each view and badges Findings with their count.
9. Clicking a step, an arrow, a field row or an exposure row sets the selection, and
   [`DetailsPanel`](../../frontend/src/features/details/DetailsPanel.tsx#L19) shows everything known about it:
   [`nodeDetails`](../../frontend/src/features/details/DetailsPanel.tsx#L139) per node type (an Ingress's handler and
   callers, a check's requirement, denial and observations, an Egress's credentials and token, a field's checks and
   flows), [`edgeDetails`](../../frontend/src/features/details/DetailsPanel.tsx#L263),
   [`linkDetails`](../../frontend/src/features/details/DetailsPanel.tsx#L275),
   [`flowDetails`](../../frontend/src/features/details/DetailsPanel.tsx#L288) and
   [`ExposureDetails`](../../frontend/src/features/details/DetailsPanel.tsx#L106), with the raw JSON underneath.
10. The view and the panel each sit in an [`ErrorBoundary`](../../frontend/src/components/ErrorBoundary.tsx#L17), so a
    graph this UI doesn't understand breaks one part, which tries again when the view, model or selection changes.

Shared pieces: [`format.ts`](../../frontend/src/lib/format.ts) has the text (requirements, code references, and the
words for scopes, denials, credentials, field sources, finding kinds and change kinds);
[`utils.ts`](../../frontend/src/lib/utils.ts) has `cn`, [`groupBy`](../../frontend/src/lib/utils.ts#L27) and
[`runsBy`](../../frontend/src/lib/utils.ts#L46), which the views fold alike rows with;
[`common.tsx`](../../frontend/src/components/common.tsx) has the badges and headers every view uses
([`RequirementBadge`](../../frontend/src/components/common.tsx#L40), [`ViewHeader`](../../frontend/src/components/common.tsx#L65),
[`EmptyState`](../../frontend/src/components/common.tsx#L78)); `components/ui/` holds the shadcn-style primitives on Radix
UI; [`types.ts`](../../frontend/src/lib/types.ts) mirrors the server's JSON.

**Relies on / relied on by**

Relies on the [server](#the-server) for everything but a diff report: the UI never works out exposures itself. Every
view below relies on the shell's `Model` and store.

**Tests**

[`App.test.tsx`](../../frontend/src/App.test.tsx) (every way in, the status messages, overlapping loads, hash routing,
details, a view that breaks), [`main.test.tsx`](../../frontend/src/main.test.tsx),
[`lib/api.test.ts`](../../frontend/src/lib/api.test.ts), [`lib/model.test.ts`](../../frontend/src/lib/model.test.ts),
[`lib/store.test.ts`](../../frontend/src/lib/store.test.ts), [`lib/format.test.ts`](../../frontend/src/lib/format.test.ts),
[`lib/utils.test.ts`](../../frontend/src/lib/utils.test.ts), the `components/*.test.tsx` and
[`DetailsPanel.test.tsx`](../../frontend/src/features/details/DetailsPanel.test.tsx). They run against
[`src/test/`](../../frontend/src/test/): graph builders (`graphs.ts`, `system.ts`), a stubbed server (`server.ts`),
and the browser parts jsdom lacks (`dom.ts`). On the server side, `AuthTracerApplicationTests.servesTheUi`.

**Before changing it**

- `types.ts` follows the records in `graph`, `api` and `diff`. Read tolerantly, as the server does: a missing list is
  empty, an unknown node type shows as its JSON, an unknown finding kind still shows.
- Keep one `useUi` selector per value in `App`, so typing in a view's filter doesn't re-render the shell.
- Every new load goes through the `loads` counter, or a slow answer overwrites what the person opened.
- The design rule is to merge what is alike so the differences stand out; each view below does it its own way.

## The request paths view

**Feature:** [`PATHS_VIEW`](features.md#paths_view)

Every Ingress's steps in the order they run, left to right, one lane per service, following calls into the services
they reach. Endpoints whose paths end the same way share one card and the steps they share are drawn once.

**How it works**

1. Data: the shell's `Model`, with [`Model.ingresses`](../../frontend/src/lib/model.ts#L121) per service,
   [`Model.path`](../../frontend/src/lib/model.ts#L117) for each one's ordered edges, `linksFrom` to follow calls,
   `endpointExposure` for what each endpoint requires, and observations for the checks and links.
2. [`PathsView`](../../frontend/src/features/paths/PathsView.tsx#L29) reads its state from the store (service, "Follow
   calls into services", open cards, search) and calls
   [`mergePaths`](../../frontend/src/features/paths/pathGroups.ts#L83) for the chosen services' ingresses, then filters the
   groups with [`matches`](../../frontend/src/features/paths/pathGroups.ts#L205) (every word in the endpoints, services or
   requirements).
3. [`pathTree`](../../frontend/src/features/paths/pathGroups.ts#L48) turns one Ingress into a chain of steps in time
   order; an Egress also points to the paths of the endpoints its links reach, up to
   [`MAX_DEPTH`](../../frontend/src/features/paths/pathGroups.ts#L8) (4) services deep and never back into one already on
   the way.
4. `mergePaths` interns the steps from the end: two steps become one node only when they are the same node with the
   same calls and the same next step (and the arrow to it is equally conditional), so every path drawn is a real one.
   Endpoints that share a node form one group (an endpoint reaching two groups joins them); endpoints with no step at
   all make one group per service; and [`shape`](../../frontend/src/features/paths/pathGroups.ts#L161) finds a
   single-service group that reads the same in another service, which becomes its twin, drawn once.
5. Each group is a `PathCard`. Its header lists the endpoints in [`drawOrder`](../../frontend/src/features/paths/pathLayout.ts#L166),
   folding more than three that read alike ([`runs`](../../frontend/src/features/paths/pathGroups.ts#L193): same service,
   requirement, check count, callers and first path segment) into one `RunLine`, else one `CardLine` each. Opened, a
   card with only bare endpoints is a list ([`isBare`](../../frontend/src/features/paths/pathGroups.ts#L185)); otherwise
   it draws a [`PathDiagram`](../../frontend/src/features/paths/PathDiagram.tsx#L28), only while open.
6. [`layout`](../../frontend/src/features/paths/pathLayout.ts#L30) places the steps. Columns follow time: a step comes
   after the one before it and after everything the services it called do. Rows: each run of new steps takes the
   first free row of its service's lane, keeping it free up to the step it joins. Called endpoints take rows in their
   callers' order ([`joinOrder`](../../frontend/src/features/paths/pathLayout.ts#L145)), and callers' lanes sit above the
   services they call.
7. `PathDiagram` turns the plan into React Flow nodes: a [`LaneNode`](../../frontend/src/features/paths/LaneNode.tsx#L11)
   per service (hover for where its authorities come from) and a [`StepNode`](../../frontend/src/features/paths/StepNode.tsx#L33)
   per step, whose text comes from [`stepSpec`](../../frontend/src/features/paths/stepSpec.ts#L26) (a check's short name
   from [`checkHead`](../../frontend/src/features/paths/stepSpec.ts#L98), credentials, denial, and granted/denied counts or
   why traces can't show them). Local arrows are grey smoothstep edges turning at
   [`stepPosition`](../../frontend/src/features/paths/pathLayout.ts#L135), dashed when on some branches only; calls are
   violet, labelled with the traced call count, "observed" or "inferred", dashed until a trace saw them, with an arrow
   back when a response returns. Clicking a step or an arrow selects it for the details panel.
8. [`ScaledFlow`](../../frontend/src/components/ScaledFlow.tsx#L19) draws the diagram read-only, shrunk to fit down to
   [`MIN_ZOOM`](../../frontend/src/components/ScaledFlow.tsx#L9) (four fifths) and scrolling sideways beyond, and only once
   it nears the visible part of the page ([`useInView`](../../frontend/src/hooks/useInView.ts#L5),
   [`useElementWidth`](../../frontend/src/hooks/useElementWidth.ts#L5)).
9. After the cards, [`OutsideRequests`](../../frontend/src/features/paths/PathsView.tsx#L202) lists the calls no request
   path makes ([`Model.offPathEgresses`](../../frontend/src/lib/model.ts#L131): token checks, configuration, discovery) and
   the services they reach.

**Relies on / relied on by**

[`CALL_PATHS`](features.md#call_paths) for the ordered edges and their `conditional` flag, the system graph's links
for following calls, and exposures for each endpoint's requirement. The [Legend](#the-legend-view) draws its steps with
`StepCard`.

**Tests**

[`pathGroups.test.ts`](../../frontend/src/features/paths/pathGroups.test.ts) (merging, twins, runs, filtering),
[`pathLayout.test.ts`](../../frontend/src/features/paths/pathLayout.test.ts) (columns, rows, lane order),
[`stepSpec.test.ts`](../../frontend/src/features/paths/stepSpec.test.ts) (how each step reads) and
[`PathsView.test.tsx`](../../frontend/src/features/paths/PathsView.test.tsx) (the view as a person uses it).

**Before changing it**

- Merge only steps whose whole future is the same, including whether the arrow after them is conditional: merging
  more draws paths that don't exist.
- A group's `key` (its endpoints, twins included) is what the store remembers as open; it changes when the grouping
  does.
- The diagram is only built for open cards that are near the screen: a system with hundreds of endpoints stays quick
  because of it.

## The field lineage view

**Feature:** [`LINEAGE_VIEW`](features.md#lineage_view)

Where one endpoint's response fields come from: one box per class with a row per field, sources on the left and the
response on the right, across services. Fields copied unchanged between two classes share one arrow, so the arrows
left are renames, computed and complex values, and the rows carry the field checks that guard them.

**How it works**

1. Data: the exposures in the `Model`. Each field's exposure carries its `lineage` (the flows back to its sources,
   qualified ids) and steps whose `guards` names the field a check guards, both made on the server by
   [`ExposureView.of`](../../src/main/java/dev/crain/authtracer/api/ExposureView.java#L43). Nodes come from
   `Model.node`, and [`Model.observedLink`](../../frontend/src/lib/model.ts#L158) says whether a trace confirmed the call a
   network flow crosses.
2. [`LineageView`](../../frontend/src/features/lineage/LineageView.tsx#L24) lists the endpoints and opens on the one with
   the most flows behind its fields (or the one `showLineage` asked for), with a field picker. Below the diagram it
   reuses [`ExposureTable`](../../frontend/src/features/exposures/ExposureTable.tsx#L22) for what a caller needs per field.
3. [`lineagePlan`](../../frontend/src/features/lineage/lineageLayout.ts#L100) builds the picture:
   [`graphOf`](../../frontend/src/features/lineage/lineageLayout.ts#L151) collects fields and each flow once;
   [`boxesOf`](../../frontend/src/features/lineage/lineageLayout.ts#L179) puts each field in its class's box, a box's depth
   being its longest distance to the response; [`bundlesOf`](../../frontend/src/features/lineage/lineageLayout.ts#L205)
   makes one arrow of two or more direct, same-name copies between the same two classes;
   [`guardsOf`](../../frontend/src/features/lineage/lineageLayout.ts#L263) puts each guarding check on its row; and
   [`describe`](../../frontend/src/features/lineage/lineageLayout.ts#L278) adds labels, "declassified" and a JSON name that
   differs. A class whose every field is copied in and out unchanged, with nothing on its rows, folds to one line until
   clicked.
4. Columns run by depth, right to left. [`arrange`](../../frontend/src/features/lineage/lineageLayout.ts#L229) orders the
   response's rows by the exposures' order, each earlier column's rows level with what they feed, and then (when there
   is more than one column) the response once more level with its sources and the rest again, to keep lines from
   crossing.
5. [`LineageDiagram`](../../frontend/src/features/lineage/LineageDiagram.tsx#L29) draws a
   [`RecordNode`](../../frontend/src/features/lineage/RecordNode.tsx#L33) per box, a
   [`BundleEdge`](../../frontend/src/features/lineage/BundleEdge.tsx#L10) per bundle (hover the label for the fields), and
   [`flowEdge`](../../frontend/src/features/lineage/LineageDiagram.tsx#L98) for every other flow: colored by Direct,
   Complex, Computed or Masked, labelled only when not direct, thick across services and dashed until a trace saw the
   call. Clicking a row selects the field; clicking an arrow selects the flow. It shares `ScaledFlow` with the paths
   view.

**Relies on / relied on by**

[`FIELD_LINEAGE`](features.md#field_lineage) and [`FIELD_CHECKS`](features.md#field_checks) through the server's
exposures; `ExposureView`'s `guards` exists for this view. The exposures view's details open it with "Show its
lineage", and the [Legend](#the-legend-view) draws its boxes with `RecordCard`.

**Tests**

[`lineageLayout.test.ts`](../../frontend/src/features/lineage/lineageLayout.test.ts) (bundles, folding, rows,
columns, cycles) and [`LineageView.test.tsx`](../../frontend/src/features/lineage/LineageView.test.tsx).

**Before changing it**

- A field's box is its id up to the last `.`, so `field:<class>.<property>` (which the server validates) is what puts
  fields in classes; a view's fields (`field:view:...`) read as the model path their template reads.
- The column loop is bounded by the number of boxes, so flows that go round between classes still end.

## The exposures view

**Feature:** [`EXPOSURES_VIEW`](features.md#exposures_view)

A table of what a caller needs for each endpoint and each of its response fields, through every service on the way,
with where each field comes from, its labels and the policies it breaks. A field that asks nothing beyond its endpoint
says so quietly, so the fields with checks of their own stand out.

**How it works**

1. Data: `Model.exposures`, the server's [`ExposureView`](../../src/main/java/dev/crain/authtracer/api/ExposureView.java#L31)
   rows (see [the server](#the-server)), computed by [`Exposures`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L40)
   as [analysis](analysis.md) describes.
2. [`ExposuresView`](../../frontend/src/features/exposures/ExposuresView.tsx#L14) filters with
   [`matchesFilter`](../../frontend/src/features/exposures/exposureRows.ts#L84) (every word in the service, endpoint,
   field, requirement, sources, labels, policy violations or the checks on the way); a matching field brings its
   endpoint's row along.
3. [`ExposureTable`](../../frontend/src/features/exposures/ExposureTable.tsx#L22) groups the rows with
   [`endpointGroups`](../../frontend/src/features/exposures/exposureRows.ts#L20) (one group per endpoint; the same
   field-less endpoint needing the same in several services is one row naming them) and
   [`alikeRuns`](../../frontend/src/features/exposures/exposureRows.ts#L47) (consecutive field-less endpoints of one
   service, requirement and first path segment). A run longer than
   [`MAX_ALIKE`](../../frontend/src/features/exposures/exposureRows.ts#L6) (3) is one `SummaryBody` row that opens on a
   click.
4. `GroupBody` draws an endpoint and its fields. What every field adds first
   ([`sharedAddition`](../../frontend/src/features/exposures/exposureRows.ts#L66), say a `@PostFilter` on their list) is
   shown once on the endpoint, and each field shows only what it adds [`beyond`](../../frontend/src/features/exposures/exposureRows.ts#L79)
   it. More than three fields that add nothing, carry no label and break no policy fold into one row.
5. `ExposureRow` shows "nothing more", `+ <what it adds>`, or the whole requirement when the server set `adds` to
   `null`; the sources; and label and policy badges. A click selects the exposure, and the details panel lists the
   checks in order with "Show its lineage".

**Relies on / relied on by**

[`EXPOSURES`](features.md#exposures) and [`POLICIES`](features.md#policies) through the server. The lineage view
reuses `ExposureTable`, and the details panel its [`Requires`](../../frontend/src/features/exposures/ExposureTable.tsx#L196).

**Tests**

[`exposureRows.test.ts`](../../frontend/src/features/exposures/exposureRows.test.ts) and
[`ExposuresView.test.tsx`](../../frontend/src/features/exposures/ExposuresView.test.tsx).

**Before changing it**

- `sharedAddition` and `beyond` split `adds` on `" and "`, the way `Clauses.describe` writes it; change one with the
  other.
- An endpoint with fields, or one that breaks a policy, never joins a run or a twin row: folding would hide it.
- Rows are rebuilt from the exposures on every render, so the selected row is recognized by service, Ingress and field,
  not by identity.

## The findings view

**Feature:** [`FINDINGS_VIEW`](features.md#findings_view)

Every finding of every service and of the linker, one card per kind with what the kind means, findings that differ in
a word or two merged into one message with a blank, and the Provided facts each scan applied.

**How it works**

1. Data: [`Model.findings`](../../frontend/src/lib/model.ts#L172) (each graph's findings with its service, then the system
   graph's as "system (linker)") and each graph's `provided` facts. See [findings](findings.md) for where they come
   from.
2. [`FindingsView`](../../frontend/src/features/findings/FindingsView.tsx#L38) orders the kinds present by
   [`ORDER`](../../frontend/src/features/findings/FindingsView.tsx#L17) (the kinds that most often mean an endpoint is more
   open than it looks first), then the rest of [`FINDING_KINDS`](../../frontend/src/lib/format.ts#L188), then kinds this UI
   has no words for. Each card shows the kind's text from `FINDING_KINDS` and a count.
3. [`findingGroups`](../../frontend/src/features/findings/findingGroups.ts#L19) merges findings of one service and kind
   whose messages have the same number of words and differ in at most
   [`MAX_VARYING`](../../frontend/src/features/findings/findingGroups.ts#L5) (2), with at least three shared words per
   varying one. [`MergedFindings`](../../frontend/src/features/findings/FindingsView.tsx#L141) shows the message once with
   its blanks marked, then a line per finding with what fills them and where it is.
4. Messages are shown with [`shortNames`](../../frontend/src/lib/format.ts#L23) (package names dropped), the full text on
   hover.

**Relies on / relied on by**

Every `FINDING_*` feature; the sidebar badges the view with `Model.findings().length`.

**Tests**

[`findingGroups.test.ts`](../../frontend/src/features/findings/findingGroups.test.ts) and
[`FindingsView.test.tsx`](../../frontend/src/features/findings/FindingsView.test.tsx).

**Before changing it**

- A new finding kind on the server shows without a UI change, but without words: add its text to `FINDING_KINDS` (the
  Legend lists the same text), and to `ORDER` if it means an endpoint is more open than it looks.
- The merge rule needs most of a message shared, or short messages of the same length would merge with anything.

## The identities view

**Feature:** [`IDENTITIES_VIEW`](features.md#identities_view)

The identities the traces showed (a set of authorities, since traces name no user): how many requests each made on
which endpoints, which of its authorities the checks on those requests needed, which they never did, and how often it
was denied.

**How it works**

1. Data: `Model.system.identities`, which the linker writes when it reads traces (see [the system](system.md)), so
   only a system graph linked with Zipkin has any: through "Link stored graphs" on the server, or `link --zipkin` or
   `--traces` on the command line.
2. [`IdentitiesView`](../../frontend/src/features/identities/IdentitiesView.tsx#L15) says where identities come from when
   there are none. Otherwise it draws a row per identity: requests (the endpoints on hover), needed authorities as
   green badges, unneeded ones as amber badges (with how many checks AuthTracer can't read might need them), and
   denials. A row with unneeded authorities is shaded; the type column appears only when the identities have more than
   one authentication type.
3. The command line's [`DiffCommands.identities`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L178)
   prints the same table, and can fail a build on an over-scoped identity.

**Relies on / relied on by**

[`IDENTITIES`](features.md#identities), and through it [`TRACE_OBSERVATIONS`](features.md#trace_observations).

**Tests**

[`IdentitiesView.test.tsx`](../../frontend/src/features/identities/IdentitiesView.test.tsx).

**Before changing it**

The row key is the authentication type and the authorities, which is what the linker keys identities by, so it is
unique.

## The diff report view

**Feature:** [`DIFF_VIEW`](features.md#diff_view)

A diff report opened from the JSON `diff --json` writes: whether the change passes, needs review or fails, and one row
per distinct authorization change with what changed in the requirement and where.

**How it works**

1. Data: no server call. `diff --json` writes the [`DiffReport`](../../src/main/java/dev/crain/authtracer/diff/DiffReport.java#L17)
   (`base`, `head`, `changes`); [`openFile`](../../frontend/src/lib/api.ts#L61) recognizes it by its `changes` and
   [`loadDiff`](../../frontend/src/lib/store.ts#L51) keeps it next to the loaded graph and switches to the view.
2. [`DiffView`](../../frontend/src/features/diff/DiffView.tsx#L18) shows the result (FAIL when any change fails, REVIEW
   when any needs review, else PASS) with the count of each severity.
3. [`changeGroups`](../../frontend/src/features/diff/delta.ts#L59) makes one row per distinct change: the same severity,
   kind and requirement delta on several endpoints or fields is one row; a new finding keeps its own row.
   [`deltaOf`](../../frontend/src/features/diff/delta.ts#L32) writes the delta as the top-level terms removed and added
   ([`terms`](../../frontend/src/features/diff/delta.ts#L5) splits on `and` outside parentheses), or before → after when
   they don't split that way.
4. `Places` lists where each change applies, an endpoint's fields after it; the last column gives the one reason all
   places share, or what the kind means ([`CHANGE_KINDS`](../../frontend/src/lib/format.ts#L228)).

**Relies on / relied on by**

[`DIFF`](features.md#diff) through the command line's `--json`, and [`DIAGONAL_ESCALATION`](features.md#diagonal_escalation)
and [`POLICIES`](features.md#policies) for some of the kinds it shows.

**Tests**

[`delta.test.ts`](../../frontend/src/features/diff/delta.test.ts) and
[`DiffView.test.tsx`](../../frontend/src/features/diff/DiffView.test.tsx).

**Before changing it**

- The file's shape is `DiffReport`'s record components as Jackson writes them, and `Change` leaves out what is empty
  (an endpoint's own change has no `field`, a new finding may have no `endpoint`). Change `types.ts` with them.
- `kindOf` checks `services`, then `nodes`, then `changes`: a diff report must never carry `services` or `nodes`.

## The legend view

**Feature:** [`LEGEND_VIEW`](features.md#legend_view)

What every shape, color, line and label in the other views means, drawn with the same components the views use, and
the text of every finding kind and change kind.

**How it works**

1. Data: none. [`ViewBody`](../../frontend/src/App.tsx#L284) shows it with or without a graph.
2. [`LegendView`](../../frontend/src/features/legend/LegendView.tsx#L43) draws the paths view's steps from sample
   `StepSpec`s ([`NODES`](../../frontend/src/features/legend/LegendView.tsx#L18)) with
   [`StepCard`](../../frontend/src/features/paths/StepNode.tsx#L44), lineage boxes with `Record`, which sizes sample rows
   with the layout's [`rowHeight`](../../frontend/src/features/lineage/lineageLayout.ts#L79) and
   [`boxHeight`](../../frontend/src/features/lineage/lineageLayout.ts#L83) and draws them with
   [`RecordCard`](../../frontend/src/features/lineage/RecordNode.tsx#L38), and arrows with `LineSample`.
3. The words come from [`format.ts`](../../frontend/src/lib/format.ts): `DENIALS`, `CREDENTIALS`, `NO_CALLER`,
   `FIELD_SOURCES`, [`SEVERITIES`](../../frontend/src/lib/format.ts#L240), and the `Terms` lists of `FINDING_KINDS` and
   `CHANGE_KINDS`.

**Relies on / relied on by**

The paths and lineage views' components and the shell's text. The views point here rather than repeating it.

**Tests**

[`LegendView.test.tsx`](../../frontend/src/features/legend/LegendView.test.tsx): every part drawn as the views draw it,
none of it clickable, and every key of `FINDING_KINDS` and `CHANGE_KINDS` listed.

**Before changing it**

When a view draws something new (a badge, a line style, a kind), add it here with the view's own component, so the
two can't drift.

## Files

### Java

| File | Role | Features |
|---|---|---|
| [`AuthTracerApplication`](../../src/main/java/dev/crain/authtracer/AuthTracerApplication.java#L16) | The Spring Boot application: the server's `main`, the context the command line starts too, the trace source and linker beans | `GRAPH_SERVER`, `COMMAND_LINE`; `traceSource`: `TRACE_OBSERVATIONS` |
| [`AuthTracerProperties`](../../src/main/java/dev/crain/authtracer/AuthTracerProperties.java#L14) | `authtracer.*`: the API's body limit and the Zipkin the server reads | `GRAPH_SERVER`; `Zipkin`: `TRACE_OBSERVATIONS` |
| [`UsageException`](../../scanner/src/main/java/dev/crain/authtracer/UsageException.java#L11) | A command asked for the impossible: exit code `2` | `COMMAND_LINE` |
| [`AuthTracerCli`](../../src/main/java/dev/crain/authtracer/cli/AuthTracerCli.java#L17) | The command line's `main`: one context per command, its exit code | `COMMAND_LINE` |
| [`CliArguments`](../../src/main/java/dev/crain/authtracer/cli/CliArguments.java#L23) | The command and its `--options` | `COMMAND_LINE` |
| [`CliRunner`](../../src/main/java/dev/crain/authtracer/cli/CliRunner.java#L38) | Dispatches commands, maps failures to exit codes; `scan`, `--publish` and `link` | `COMMAND_LINE`; `publish`: `GRAPH_SERVER`; `link`: `SYSTEM_GRAPH`, `TRACE_OBSERVATIONS` |
| [`ScanArtifacts`](../../scanner-image/src/main/java/dev/crain/authtracer/image/ScanArtifacts.java#L45) | The scanner image's command: every artifact in `/in` to a graph in `/out` | `SCANNER_IMAGE` |
| [`DiffCommands`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L40) | `diff` (files or a project against a base), `exposures`, `policies`, `identities` | `COMMAND_LINE`; `diff`: `SARIF_ANNOTATIONS`, `AGENT_REPORT`, `DIFF`; `exposures`: `EXPOSURES`; `policies`: `POLICIES`; `identities`: `IDENTITIES`; `scanRevision`, `withContext`: `DIFF` |
| [`GraphController`](../../src/main/java/dev/crain/authtracer/api/GraphController.java#L29) | Publish, list and fetch graphs; link the stored ones; the latest system graph | `GRAPH_SERVER`; `link`: `TRACE_OBSERVATIONS` |
| [`ExposureController`](../../src/main/java/dev/crain/authtracer/api/ExposureController.java#L29) | Exposures of the stored system graph or a posted graph | `GRAPH_SERVER` |
| [`ExposureView`](../../src/main/java/dev/crain/authtracer/api/ExposureView.java#L31) | An exposure as the UI shows it: what a field adds, which field a check guards | `EXPOSURES_VIEW`, `LINEAGE_VIEW`, `GRAPH_SERVER` |
| [`GraphValidation`](../../src/main/java/dev/crain/authtracer/api/GraphValidation.java#L23) | What a posted graph must have before it is kept | `GRAPH_SERVER` |
| [`RequestBodyLimit`](../../src/main/java/dev/crain/authtracer/api/RequestBodyLimit.java#L34) | `413` for a posted graph over the limit, declared or chunked | `GRAPH_SERVER` |
| [`GraphStore`](../../src/main/java/dev/crain/authtracer/store/GraphStore.java#L23) | Every graph and link as a JSON snapshot in H2 | `GRAPH_SERVER` |

### UI (`frontend/src`)

| File | Role | Features |
|---|---|---|
| [`main.tsx`](../../frontend/src/main.tsx) | Mounts the app with the tooltips' provider | `UI` |
| [`App.tsx`](../../frontend/src/App.tsx) | The shell: loading, sidebar, header, numbers, hash routing, details beside the view | `UI` |
| [`lib/api.ts`](../../frontend/src/lib/api.ts) | The server's API and opening files | `UI` |
| [`lib/model.ts`](../../frontend/src/lib/model.ts) | `Model`: a loaded system graph indexed by qualified id, with its exposures | `UI` |
| [`lib/store.ts`](../../frontend/src/lib/store.ts) | `useUi`: the app state and each view's own | `UI` |
| [`lib/types.ts`](../../frontend/src/lib/types.ts) | The server's JSON as types | `UI` |
| [`lib/format.ts`](../../frontend/src/lib/format.ts) | The text: requirements, code references, and the words for every kind | `FINDINGS_VIEW`, `DIFF_VIEW`, `LEGEND_VIEW`, `UI` |
| [`lib/utils.ts`](../../frontend/src/lib/utils.ts) | Class names, grouping, runs of alike items, route prefixes | `UI` |
| [`hooks/useElementWidth.ts`](../../frontend/src/hooks/useElementWidth.ts) | An element's width as it resizes | `PATHS_VIEW`, `LINEAGE_VIEW` |
| [`hooks/useInView.ts`](../../frontend/src/hooks/useInView.ts) | Whether an element has come near the visible page | `PATHS_VIEW`, `LINEAGE_VIEW` |
| [`components/common.tsx`](../../frontend/src/components/common.tsx) | Method and requirement badges, endpoint text, view headers, empty states | `UI` |
| [`components/ErrorBoundary.tsx`](../../frontend/src/components/ErrorBoundary.tsx) | One broken part instead of a broken page | `UI` |
| [`components/ScaledFlow.tsx`](../../frontend/src/components/ScaledFlow.tsx) | A read-only React Flow diagram, scaled to fit and drawn when near | `PATHS_VIEW`, `LINEAGE_VIEW` |
| [`components/ThemeToggle.tsx`](../../frontend/src/components/ThemeToggle.tsx) | Light and dark, remembered | `UI` |
| [`components/ui/badge.tsx`](../../frontend/src/components/ui/badge.tsx), [`button.tsx`](../../frontend/src/components/ui/button.tsx), [`card.tsx`](../../frontend/src/components/ui/card.tsx), [`input.tsx`](../../frontend/src/components/ui/input.tsx), [`select.tsx`](../../frontend/src/components/ui/select.tsx), [`switch.tsx`](../../frontend/src/components/ui/switch.tsx), [`tooltip.tsx`](../../frontend/src/components/ui/tooltip.tsx) | shadcn-style primitives on Radix UI | `UI` |
| [`features/details/DetailsPanel.tsx`](../../frontend/src/features/details/DetailsPanel.tsx) | Everything known about the clicked node, arrow or row | `UI` |
| [`features/paths/PathsView.tsx`](../../frontend/src/features/paths/PathsView.tsx) | The view: controls, cards, their header lines, calls outside requests | `PATHS_VIEW` |
| [`features/paths/pathGroups.ts`](../../frontend/src/features/paths/pathGroups.ts) | Paths as trees, merged into groups and twins; runs; filtering | `PATHS_VIEW` |
| [`features/paths/pathLayout.ts`](../../frontend/src/features/paths/pathLayout.ts) | Columns in time order, rows, lanes | `PATHS_VIEW` |
| [`features/paths/stepSpec.ts`](../../frontend/src/features/paths/stepSpec.ts) | How a step reads on the diagram | `PATHS_VIEW` |
| [`features/paths/PathDiagram.tsx`](../../frontend/src/features/paths/PathDiagram.tsx) | A group's lanes, steps and arrows as React Flow nodes and edges | `PATHS_VIEW` |
| [`features/paths/StepNode.tsx`](../../frontend/src/features/paths/StepNode.tsx) | One step as a card; the legend draws it too | `PATHS_VIEW`, `LEGEND_VIEW` |
| [`features/paths/LaneNode.tsx`](../../frontend/src/features/paths/LaneNode.tsx) | A service's band | `PATHS_VIEW` |
| [`features/lineage/LineageView.tsx`](../../frontend/src/features/lineage/LineageView.tsx) | The view: endpoint and field pickers, the diagram, the per-field table | `LINEAGE_VIEW` |
| [`features/lineage/lineageLayout.ts`](../../frontend/src/features/lineage/lineageLayout.ts) | Fields, boxes, bundles, guards, columns and rows | `LINEAGE_VIEW`, `LEGEND_VIEW` |
| [`features/lineage/LineageDiagram.tsx`](../../frontend/src/features/lineage/LineageDiagram.tsx) | Boxes and flows as React Flow nodes and edges | `LINEAGE_VIEW` |
| [`features/lineage/RecordNode.tsx`](../../frontend/src/features/lineage/RecordNode.tsx) | A class as a box of rows; the legend draws it too | `LINEAGE_VIEW`, `LEGEND_VIEW` |
| [`features/lineage/BundleEdge.tsx`](../../frontend/src/features/lineage/BundleEdge.tsx) | Fields copied unchanged as one arrow | `LINEAGE_VIEW` |
| [`features/exposures/ExposuresView.tsx`](../../frontend/src/features/exposures/ExposuresView.tsx) | The view: the filter and the count | `EXPOSURES_VIEW` |
| [`features/exposures/ExposureTable.tsx`](../../frontend/src/features/exposures/ExposureTable.tsx) | Endpoint and field rows, folded where alike; also in the lineage view and the details | `EXPOSURES_VIEW`, `LINEAGE_VIEW`, `UI` |
| [`features/exposures/exposureRows.ts`](../../frontend/src/features/exposures/exposureRows.ts) | Grouping, runs, shared additions, filtering | `EXPOSURES_VIEW` |
| [`features/findings/FindingsView.tsx`](../../frontend/src/features/findings/FindingsView.tsx) | Findings by kind, merged messages, Provided facts | `FINDINGS_VIEW` |
| [`features/findings/findingGroups.ts`](../../frontend/src/features/findings/findingGroups.ts) | Messages that differ in a word or two, as one with blanks | `FINDINGS_VIEW` |
| [`features/identities/IdentitiesView.tsx`](../../frontend/src/features/identities/IdentitiesView.tsx) | Identities and the grants they never used | `IDENTITIES_VIEW` |
| [`features/diff/DiffView.tsx`](../../frontend/src/features/diff/DiffView.tsx) | The result and a row per distinct change | `DIFF_VIEW` |
| [`features/diff/delta.ts`](../../frontend/src/features/diff/delta.ts) | Requirement deltas as terms; grouping changes | `DIFF_VIEW` |
| [`features/legend/LegendView.tsx`](../../frontend/src/features/legend/LegendView.tsx) | Every shape, line and word, drawn with the views' components | `LEGEND_VIEW` |
