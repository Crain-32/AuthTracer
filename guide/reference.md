# Reference

The command line, the Gradle tasks, the scanner image, the REST API and the Provided facts file. The
[tutorial](tutorial.md) shows them in use.

## Command line

Run from the AuthTracer directory as `./gradlew authtracer --args="<command> <options>"`.

| Command | What it does |
|---|---|
| `scan --project <dir> --out <file> [--publish <url>]` | Scans one service into its application graph. `<dir>` is a Gradle project or subproject, or a Maven project or module, in Java, Kotlin or Groovy; the scan compiles it with its own `gradlew` or `mvnw` if needed, and builds the sibling modules it depends on. The root of a multi-project Gradle build scans its one Spring Boot application (or its one Java project); with more than one, it stops and names them. Reads the project's `authtracer.yaml`. `--publish` also stores the graph on an AuthTracer server |
| `scan --classes <dirs> [--libraries <classpath>] [--resources <dirs>] --service <name> --out <file>` | Scans compiled classes without a build |
| `link --graphs <a.json,b.json,...> [--zipkin <url> \| --traces <file>] --out <file>` | Links application graphs into a system graph: statically (a URL to a route, a GraphQL operation, a gRPC method, a message's topic or queue), and from Zipkin traces when given (`--lookback <minutes>`, default 60): client and server spans confirm calls, producer and consumer spans confirm messages |
| `exposures --graph <file> [--field <text>] [--out <md>]` | What every endpoint and response field requires, across services, and where each field comes from |
| `policies --graph <file> [--out <md>]` | Fields and endpoints that require less than their policy (see Provided facts) |
| `identities --graph <system.json> [--fail-on-unneeded true]` | Per identity seen in the traces: the authorities its requests needed, and the ones they didn't |
| `diff --base <file> --head <file> [--json <file>] [--report <md>] [--sarif <file> --sources <service=dir,...>]` | Compares two saved graphs |
| `diff --project <dir> (--base-ref <git ref> \| --base-project <dir>) [--context <system.json>]` | The pull-request check: scans the base revision (in a temporary git worktree) and the working tree, and compares them. `--context` adds the other services so a change shows up where its effects land |

Common options: `--service <name>` and `--revision <rev>` override what the scan records (for `diff --project`, the
head's; the base is named after it), `--packages <a,b>` limits
it to packages, `--org-facts <yaml>` applies an Org facts file. The diff also takes `--agent-report <file>` (what failed
and where, for the coding agent that made the change) and `--fail-on-review true`.

**Exit codes:** `0` ok; `1` failed (diff: authorization got weaker; policies: something is exposed with less than its
policy requires; identities with the flag: an identity is over-scoped); `2` usage (an option missing or malformed, an
option the command doesn't take, a flag other than `true` or `false`, a path that names no project, a `--classes`,
`--libraries` or `--resources` entry that isn't there); `3` error (a build failed, a file it reads can't be read or
isn't what it should be, or `--publish` failed).

A scan that reads no application classes (packages that match nothing, an empty build output), or finds none of the
frameworks AuthTracer reads on the classpath, still writes its graph, with an `OPAQUE_CONFIG` finding that says so:
the diff shows it for review. And a diff whose head has no endpoint where its base had some fails, as `REMOVED` at
`FAIL` on "every endpoint": the head's scan most likely read nothing, and the diff can't vouch for what it didn't see.

### What fails a diff

| Change | Severity | Meaning |
|---|---|---|
| `WEAKENED` | FAIL | An endpoint or field asks for less than it did |
| `DIAGONAL_ESCALATION` | FAIL | A new way to the same data that asks less than every existing way |
| `POLICY_VIOLATION` | FAIL | Something now breaks a policy it didn't break before |
| `CHANGED` | REVIEW | Different, neither clearly weaker nor stronger |
| `NEW_FINDING` | REVIEW | A finding the base didn't have |
| `NEW_EXPOSURE`, `STRENGTHENED`, `REMOVED` | INFO | For the record |

REVIEW fails too with `--fail-on-review true`.

## Gradle tasks

| Task | What it does |
|---|---|
| `./gradlew bootRun` | The server and UI on http://localhost:8080; graphs are kept in `./data`. Builds the UI, so it needs Node.js 22.13+ (as do `bootJar`, `test` and `check`) |
| `./gradlew authtracer --args="..."` | The command line. Needs only the JDK |
| `./gradlew authtracerDiff -PdiffProject=<dir> -PbaseRef=<ref>` | The pull-request check; fails the build when authorization got weaker. Also `-PbaseProject`, `-Pcontext`, `-PorgFacts`, `-Psarif`, `-PagentReport`, `-PfailOnReview=true`, `-Preport` (default `build/reports/authtracer/diff.md`) |
| `./gradlew runZipkin` | A local Zipkin on port 9411, in memory |
| `./gradlew :scanner-image:dockerImage` | The [scanner image](#scanner-image), `authtracer-scanner`. Needs Docker |
| `./gradlew test`, `integrationTest`, `systemTest`, `check` | The tests (see the [onboarding guide](onboarding.md#5-tests)). `systemTest` starts the example services' Kafka and RabbitMQ in Docker |

### On GitHub

A workflow in the service's repository, with AuthTracer checked out next to it, annotates pull requests through code
scanning:

```yaml
on: pull_request
permissions:
  contents: read
  security-events: write
jobs:
  authtracer:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/checkout@v4
        with: { repository: <org>/AuthTracer, path: authtracer }
      - uses: actions/setup-java@v4
        with: { distribution: temurin, java-version: 25 }
      - run: ./gradlew authtracerDiff -PdiffProject=$GITHUB_WORKSPACE -PbaseRef=origin/${{ github.base_ref }} -Psarif=$GITHUB_WORKSPACE/authtracer.sarif
        working-directory: authtracer
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: authtracer.sarif, category: authtracer }
```

### As a coding agent's hook

`scripts/agent-check.sh <service project> [base ref]` runs the diff and exits 2 with the report on stderr when
authorization got weaker, which a Claude Code `Stop` hook turns into a request to fix it. In the service's
`.claude/settings.json`:

```json
{
  "hooks": {
    "Stop": [
      { "hooks": [ { "type": "command", "command": "~/AuthTracer/scripts/agent-check.sh \"$CLAUDE_PROJECT_DIR\" origin/main" } ] }
    ]
  }
}
```

## Scanner image

The scanner on its own, in a container with no network: the built Spring Boot jars and wars in one directory are
scanned into one `<service>.json` graph each in another, for `link`, `diff` or the server to take. Build it with
`./gradlew :scanner-image:dockerImage`, then:

```
scripts/scan-artifacts.sh build/libs build/authtracer
```

which runs it as it must be run:

```
docker run --rm --network none --read-only --tmpfs /tmp:size=2g --cap-drop ALL \
  --security-opt no-new-privileges --memory 4g --user "$(id -u):$(id -g)" \
  -v "$PWD/build/libs:/in:ro" -v "$PWD/build/authtracer:/out" authtracer-scanner
```

It scans every Boot jar and war directly in `/in` (a Gradle build's `-plain.jar` is passed over), unpacking each into
`/tmp` and never running it. It refuses to start, explaining how to run it, with a network, without `/out` mounted, or
as root when `/out` belongs to someone else and it can't become them; with the capability (no `--cap-drop ALL`), it
runs as `/out`'s owner, so the graphs are theirs. Create the output directory before running it.

| Environment | |
|---|---|
| `AUTHTRACER_REVISION` | The revision the graphs record. Else `GITHUB_SHA`'s first seven characters, in a GitHub workflow; else the commit in the artifact's `git.properties`, its `build-info.properties` version or its manifest's `Implementation-Version` |
| `AUTHTRACER_SERVICE` | The service's name, with one artifact. Else `spring.application.name`, the manifest's `Implementation-Title`, or the file's name without its version |
| `AUTHTRACER_TIMEOUT` | How long the scan may take: `15m` by default, in `timeout`'s form (`90s`, `30m`, `1h`) |
| `AUTHTRACER_FACTS`, `AUTHTRACER_ORG_FACTS` | The services' Provided facts (by default `authtracer.yaml` in `/in`) and the organisation's, as paths in the container. `scan-artifacts.sh` mounts the files they name read-only |
| `AUTHTRACER_MEMORY` | `scan-artifacts.sh` only: the container's memory, `4g` by default. The heap is 60% of it |

**Exit codes:** `0` every artifact scanned; `2` run wrongly (the message says how to run it), or nothing to scan; `3` an
artifact couldn't be scanned (the others were) or the heap ran out; `124` the scan took longer than
`AUTHTRACER_TIMEOUT`; `137` it was killed, most likely for going over `--memory`.

On GitHub, run it with `docker run` in a step (a `uses: docker://` step can't take `--network none`), after the build:

```yaml
      - run: ./gradlew bootJar
      - run: ./gradlew :scanner-image:dockerImage
        working-directory: authtracer
      - run: authtracer/scripts/scan-artifacts.sh build/libs build/authtracer
```

`GITHUB_SHA` is passed in, so the graphs record the commit the workflow built.

## REST API

| Endpoint | |
|---|---|
| `POST /api/graphs` | Stores an application graph (what `scan --publish` sends) |
| `GET /api/graphs` | The stored snapshots |
| `GET /api/graphs/{service}[?revision=]` | A service's latest graph, or the one at a revision |
| `POST /api/system/link` | Links the latest graph of every service, with Zipkin's recent traces, and stores the result |
| `GET /api/system` | The latest system graph |
| `GET /api/system/exposures` | The latest system graph's exposures |
| `POST /api/exposures` | Exposures of the graph in the request body; nothing is stored |

The Zipkin it reads is set in `application.yaml` (`authtracer.zipkin.base-url`, `lookback`, `limit`).

The API has no authentication, so the server listens on `127.0.0.1` only; to serve other machines, start it with
`--server.address=0.0.0.0` (or `SERVER_ADDRESS`) behind something that authenticates. A graph posted to
`/api/graphs` or `/api/exposures` may be at most `authtracer.api.max-body-size` (64 MB by default); a larger one is
answered with `413`. A graph that linking couldn't read (a missing route, a field id that isn't one, a policy without
a requirement) is answered with `400` and not stored. Every snapshot is kept: the `./data` directory grows with each
publish and link.

### What a check carries

Each Authorization Location in a graph (`"type": "location"`) has its `requirement` and, where they apply:

| Property | Meaning |
|---|---|
| `requirement.decidedBy` | The application code that decides it (`className`, `method`): a custom `AuthorizationManager`'s `authorize`, a SpEL bean's method (`@authz.canRead(#id)`), a lambda, a `PermissionEvaluator`'s `hasPermission`. When AuthTracer could read what that code decides, the requirement is that (`ROLE_ADMIN`, `permitAll`); when it couldn't, it is an `EXPRESSION` and an `OPAQUE_CONFIG` finding names the method |
| `freshness` | `LIVE` when that code reads a store or calls another service on every request, so what it decides is current rather than the token's or session's snapshot. Left out otherwise |
| `arguments` | The method's parameters a pre/post expression names (`#id`, `#p0`): `name`, the `parameter`'s index, and the `binding` the request puts in it (`path variable id`, `request body`, `the caller`) when the method is a handler or every call to it passes the same handler parameter. No `parameter` means Spring finds none of that name (no `@P`, and the class isn't compiled with `-parameters`): the variable is `null` when the check runs, and an `OPAQUE_CONFIG` finding says so |
| `claims` | The token claims a pre/post expression reads (`principal.claims['tenant']`, `principal.subject`): as fresh as the token |

A `requirement.kind` of `ANONYMOUS` admits only callers who haven't signed in (`anonymous()`, `isAnonymous()`); it
asks nothing of an outsider. Code that always grants is an `ALWAYS_GRANTED` finding, code that always denies an
`ALWAYS_DENIED` one.

### What an authorization server's graph carries

A service that serves Spring Authorization Server's endpoints has an `issuer`: `clients`, each registered client's id
and the scopes it can be granted (from its `RegisteredClient` builders, or Boot's
`spring.security.oauth2.authorizationserver.client.*` properties); `claims`, the claims its token customizers add; and
`unread`, what AuthTracer couldn't read that may give a token another scope (a client store of the application's, a
customizer that writes `scope`, a token generator of its own, clients registered at run time). When nothing is unread,
linking checks the services whose JWT decoders fetch its keys: a check for a scope none of its clients can be granted
is an `ALWAYS_DENIED` finding.

A call made with the service's own token from an OAuth2 client registration (`"credentials": "OAUTH2_CLIENT"`) carries
that `registration`: its `id`, the `clientId` and `grantType`, the `scopes` it asks for, and the provider's `tokenUri`
or `issuerUri`. When that URI reaches a scanned authorization server with nothing unread, linking judges the call by
the client the token is issued to, with a `TOKEN_REJECTED` finding when the server registers no such client, when the
registration asks for a scope the server doesn't grant that client (the token request is refused with `invalid_scope`),
or when a check on the called endpoint asks for a scope the token doesn't carry. The called endpoint's checks then evaluate the service, not its callers, so
they don't count toward what its callers need (a `BYPASSED` finding says so).

## Provided facts

What a person tells AuthTracer that it can't infer. A service's own facts live in `authtracer.yaml` at the root of its
project; organization-wide facts live in an Org file passed with `--org-facts`.

```yaml
version: 1
facts:
  - kind: sensitive            # labels a field; fields derived from it inherit the labels
    field: com.example.employee.Employee.ssn
    labels: [PII]
    reason: optional text
  - kind: declassify           # a derived field stops inheriting its sources' labels and requirements
    field: com.example.profile.ProfileView.salaryBand
  - kind: check                # a reviewed hand-rolled check counts as a check
    method: "com.example.LegacyController#export(long,org.springframework.security.core.Authentication)"
    requirement: "hasRole('ADMIN')"
  - kind: requirement          # enforced outside the code (a gateway, a VPN): the first step on matching endpoints
    ingress: "GET /internal/**"
    requirement: "Only reachable through the admin VPN"
rules:                         # checks of an authorization library AuthTracer doesn't know
  - annotation: com.example.security.RequiresPermission   # on a method or its class, enforced by its aspect
    requires: "hasAuthority('PERM_{value}')"              # {value}: the annotation's attribute, or its default
  - call: "com.example.security.Guard#require"            # a call to it (or an override) checks, and throws if denied
    requires: "hasAuthority('PERM_{arg0}')"               # {arg0}: the call's first argument
    combine: any               # an array or varargs value: any of the requirements it gives (default), or all
policies:
  - label: PII                 # every exposure of a PII field must require at least this
    requires: "hasRole('ADMIN')"
  - endpoint: "PUT /admin/**"  # matching endpoints must check this on entry...
    requires: "hasRole('ADMIN')"
    fresh: true                # ...and somewhere that reads authorities live, not from a token snapshot
```

The Org file has the same `facts` and `policies`, plus overrides only it can grant, per service:

```yaml
services:
  profile-service:
    overrides:
      - kind: declassify
        field: com.example.profile.ProfileView.salaryBand
        reason: Published in the handbook
```

**Precedence**, per subject: an Org override for the service, then an Org-wide fact, then the service's own. A local
fact that loses is dropped and reported as a `PROVIDED_CONFLICT` finding, so a service can't quietly declassify what
the organization marked sensitive. Two different facts about one subject from the same place keep the first, and the
second is reported the same way.

**Policies don't compete:** each is a floor, and every one that applies must hold, so a service's own policy can add to
the Org's but never relax it. An Org policy applies everywhere. A service's own label policy follows its data: it
applies to that service's endpoints and to any other service's that expose a field of it carrying the label. A
service's own endpoint policy applies to its own routes.

**Rules** turn every use of a library's annotation or call into a check, with the placeholders filled from the
annotation's attributes or the call's constant arguments. An argument that isn't a constant leaves that check opaque,
with an `OPAQUE_CONFIG` finding, and a rule that matches nothing in the code is reported the same way. A call rule's
own method isn't reported as a hand-rolled check.

Field ids are `<class>.<property>`; method keys are `<class>#<method>(<parameter types>)`, as they appear in a scanned
graph. Every fact that was applied is listed, with where it came from, in the Findings view.
