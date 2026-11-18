# The system: linking services, traces and identities

This page covers what happens after each service is scanned: how the [`Linker`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L53)
joins application graphs into one [`SystemGraph`](../../scanner/src/main/java/dev/crain/authtracer/graph/SystemGraph.java#L18)
([the system graph](#the-system-graph)), how Zipkin traces confirm the links and count each check's decisions
([trace observations](#trace-observations)), what the traces say about the identities that made the requests
([identities](#identities)), and the findings only the linker can raise
([unmatched calls](#a-traced-call-that-matches-nothing), [runtime-only checks](#a-check-only-the-traces-show),
[rejected tokens](#a-token-the-called-service-rejects)). What the system graph is then used for, the exposures, is on
[analysis.md](analysis.md); the fields that travel over links are on [fields.md](fields.md).

One `link` call does everything, in this order:

```
Linker.link
  Run.inferStatically      static links: each Egress against the other services' Ingress
  Run.observe (per trace)  observed links, link counts, check decisions, identities, findings
  Run.credentialFindings   calls whose credentials make the called checks evaluate the calling service
  Run.audienceFindings     relayed tokens the called service may reject for their audience
  Run.issuerFindings       scope checks no client of the issuing servers can meet
  Run.clientTokenFindings  a service's own token, judged against the checks on the path it calls
  Run.networkFlows         the fields that cross each link
```

Ids in a system graph are qualified, `service/nodeId` ([`SystemGraph.qualify`](../../scanner/src/main/java/dev/crain/authtracer/graph/SystemGraph.java#L48)),
and a link's key is `from -> to` ([`Observation.linkSubject`](../../scanner/src/main/java/dev/crain/authtracer/graph/Observation.java#L21)).

## The system graph

**Feature:** [`SYSTEM_GRAPH`](features.md#system_graph)

Several services' graphs joined by links: each call (Egress) matched to the endpoint, listener or method (Ingress) it
reaches in another scanned service, inferred from URL templates and confirmed by traces, with the fields that travel
over each link and the findings about calls between services.

### How it works

1. **Where linking starts.** Three callers build a system graph:
   - the command line, `link` in [`CliRunner`](../../src/main/java/dev/crain/authtracer/cli/CliRunner.java#L38)
     (`--graphs`, with `--zipkin <url>` or `--traces <file>`);
   - the server, `link` in [`GraphController`](../../src/main/java/dev/crain/authtracer/api/GraphController.java#L29)
     (`POST /api/system/link`), with the newest stored graph of each service and the
     [`TraceSource`](../../src/main/java/dev/crain/authtracer/link/TraceSource.java#L13) bean; when the trace store
     can't be read, it links statically only;
   - the diff, `withContext` in [`DiffCommands`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L40),
     which relinks a service's new graph among the others of `--context`, without traces.
2. **One graph per service.** [`Linker.link`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L114) keys the
   graphs by service name; of two graphs of one service, the later is linked.
3. **Which services a call can reach.** `Run.inferStatically` goes through every caller's Egress. A base URL whose
   host names a scanned service (`http://employee-service`, through discovery, or its first label does:
   `employee-service.default.svc.cluster.local`) reaches that service only; a bare host name (no dot, not
   `localhost`) that no scanned service has is outside the system and reaches none. Any other call reaches the
   services whose port matches (`portMatches`: the base URL's port, or its scheme's, against the service's
   `server.port`, Spring Boot's 8080 when it sets none, and its additional ports), so `https://api.example.com`
   reaches none of them.
4. **Which endpoints.** For each service it can reach, an Ingress is reached when:
   - the method matches ([`Routes.sameMethod`](../../src/main/java/dev/crain/authtracer/link/Routes.java#L172): `*` or
     unknown matches any);
   - for a message, the destination matches (`Routes.sameDestination`: the same name, or a Kafka `topicPattern`
     regular expression, decision 0044); for anything else the route does (`Routes.reaches`: the same template with
     variables unnamed, a literal where the route has a variable, a wildcard template such as a gateway route's over
     the routes under it (decision 0043), a wildcard route over the templates it matches), or the SOAP action does
     (`soapAction`, decision 0056);
   - the endpoint's params can be met by the call's query (`Routes.paramsMatch`);
   - the protocol is the same (`Run.protocol` on both sides: `http`, `graphql`, `grpc`, `rsocket`, `soap`,
     `websocket`, or the broker's kind `KAFKA`, `RABBIT`, `JMS`), and so is the SOAP namespace
     (`Routes.sameNamespace`).

   Of the endpoints reached, one with the call's exact template wins over those with variables (`/users/me` over
   `/users/{id}`, as Spring prefers), and `byQuery` keeps the only one that names request parameters when the query is
   known.
5. **A call AuthTracer can't read the target of** (`Egress.UNKNOWN_TARGET`, decision 0082) links to nothing. When it
   has a base URL, or is a message, `inferStatically` raises an `OPAQUE_CALLPATH` finding naming the services it may
   go to: those it can reach that have endpoints of its protocol.
6. **Each link** is recorded by `Run.link`: an [`Edge`](../../scanner/src/main/java/dev/crain/authtracer/graph/Edge.java#L23)
   `NETWORK_INFERRED`, or `NETWORK_OBSERVED` once a trace confirms it (an observed link replaces the inferred one),
   and the link's two `Ends`, which the findings and flows below read.
7. **Where it lands.** A [`SystemGraph`](../../scanner/src/main/java/dev/crain/authtracer/graph/SystemGraph.java#L18) with the
   services, links, flows, observations, identities and the system's own findings. The server stores it
   ([`GraphStore`](../../src/main/java/dev/crain/authtracer/store/GraphStore.java#L23)), the exposures follow its links
   (`SystemGraph.linksFrom`), and the UI draws it from [`model.ts`](../../frontend/src/lib/model.ts).

### Relies on / relied on by

- **Relies on** [`SERVICE_CALLS`](features.md#service_calls) and [`MESSAGE_SENDS`](features.md#message_sends): each
  Egress's method, base URL, URI template, query, client and credentials, as
  [`HttpClientEgress`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L77) and
  [`MessageSends`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSends.java#L31) record them; and on every
  entry point's route, params and method, and each graph's port.
- **Relied on by** [`EXPOSURES`](features.md#exposures) (checks and fields across services),
  [`POLICIES`](features.md#policies) (an endpoint's chain follows relayed calls),
  [`TRACE_OBSERVATIONS`](features.md#trace_observations), [`FINDING_TOKEN_REJECTED`](features.md#finding_token_rejected),
  [`GRAPH_SERVER`](features.md#graph_server) and the UI's [`PATHS_VIEW`](features.md#paths_view).

### Tests

- [`LinkerTests`](../../src/test/java/dev/crain/authtracer/link/LinkerTests.java#L35): templates, methods and ports
  (`infersLinksFromTemplateMethodAndPort`, `wrongPortIsNotALink`, `aCallToAnotherPortOfAServiceIsALinkToIt`), hosts
  (`aHostThatNamesAServiceIsThatService`), gateway routes, literal routes before variable ones, queries, protocols
  kept apart (`grpcAndHttpCallsOfOneServiceLinkByTheirOwnKeys`), and `theLastGraphOfAServiceIsTheOneLinked`. Its
  graphs are built in code.
- [`RoutesTests`](../../src/test/java/dev/crain/authtracer/link/RoutesTests.java#L7): template matching, params and
  message destinations.
- Integration: [`ExampleServicesLinkTests`](../../src/integrationTest/java/dev/crain/authtracer/ExampleServicesLinkTests.java#L26)
  and [`ReactiveServiceLinkTests`](../../src/integrationTest/java/dev/crain/authtracer/ReactiveServiceLinkTests.java#L21)
  link the golden graphs of the example services; the system test
  [`EndToEndSystemTests`](../../src/systemTest/java/dev/crain/authtracer/system/EndToEndSystemTests.java#L38)
  (`tracesConfirmEveryCrossServiceLink`) links them against live traces.

### Before changing it

- **Protocols are kept apart.** A GraphQL call is `POST /graphql` on the wire but names an operation, which only a
  GraphQL Ingress answers (decision 0031); a gRPC stub call an rpc (decision 0032); a message its broker's
  destination (decision 0044). Linking across protocols would give a call the checks of an endpoint it can't reach.
- **Route variables are unnamed** (`Routes.normalize`): `/a/{id}` and `/a/{employeeId}` are one template.
- **Conditions a query can't meet are no params**: headers, media types, API versions, the handler and the SOAP
  namespace (`CONDITIONS` in `Routes`) are left out of `paramsMatch`, and a variable in the query (`{p1}`) meets any
  value.
- **A bare host no scanned service has is outside the system**; falling back to ports there would link calls to
  external APIs. For the same reason a service with no `server.port` listens on 8080, not on any port.

## Trace observations

**Feature:** [`TRACE_OBSERVATIONS`](features.md#trace_observations)

With Zipkin traces, links are confirmed and counted, and Spring Security's authorization spans are matched back to
the checks on each request's path: how often each check granted and how often it denied, as
[`Observation`](../../scanner/src/main/java/dev/crain/authtracer/graph/Observation.java#L15)s of kind `LINK` and `LOCATION`.

### How it works

1. **Reading traces.** [`ZipkinTraces.api`](../../src/main/java/dev/crain/authtracer/link/ZipkinTraces.java#L44) queries
   `api/v2/traces` once per service, under the base URL's path (`under`), with the lookback and limit, and keeps each
   trace once. `ZipkinTraces.file` reads a file saved from that API, and `ZipkinTraces.of` stands for none. `parse`
   reads each span into a [`TraceSpan`](../../src/main/java/dev/crain/authtracer/link/TraceSpan.java#L16): ids, kind
   (`SERVER`, `CLIENT`, `PRODUCER`, `CONSUMER`), name, service and tags. The server's source is the
   `traceSource` bean in [`AuthTracerApplication`](../../src/main/java/dev/crain/authtracer/AuthTracerApplication.java#L16),
   configured by `authtracer.zipkin` ([`AuthTracerProperties`](../../src/main/java/dev/crain/authtracer/AuthTracerProperties.java#L14)).
2. **Walking a trace.** `Run.observe` indexes the spans by id and parent, then for every server or consumer span
   matches its checks (`observeChecks`), for every producer span the consumer spans under it (`observeMessage`), and
   for every client span the server spans under it (`observeCall`).
3. **A call.** `observeCall` finds the endpoint the server span served (`ingresses`: by the span's route template,
   else for a request denied before routing by its URL path, then the most specific as Spring routes;
   by the GraphQL operation the server ran, `graphQlOperations`, decision 0031; by the rpc for gRPC, `rpc`, decision
   0032) and the Egress the client span was (`egresses`: by method and template or URL; of several, `narrow` keeps
   those on the path of the request the calling service was serving). One endpoint and some Egress make an observed
   link for each Egress, and add one to its count. Endpoints the trace can't tell apart leave the static links
   standing.
4. **A message.** `observeMessage` reads the broker from the span tags (`messaging`: Kafka's `messaging.system`,
   RabbitMQ's own tags, JMS's `messaging.destination.temporary`), the destination the producer sent to (`sentTo`,
   the routing key for RabbitMQ's default exchange) and the one the consumer received from (`receivedFrom`), and
   links the send to the listener the same way.
5. **Checks.** `observeChecks` takes the endpoint the span served (only when the trace pins it to one), the checks on
   its static path, and the authorization spans its service made while serving it (`decisions`: `authorize request`,
   `authorize exchange` or `authorize method` with a decision tag, in time order, not past outgoing calls). Each
   decision matches a location of its scope (`scopeMatches`) whose requirement it states (`decisionMatches`: the same
   expression, or the same authorities once the role hierarchy widens them, or for a decision that names neither, an
   authority-less requirement), preferring one not matched yet in this request. Its outcome is counted on that
   location.
6. **Where it lands.** `observations` turns the counts into `LOCATION` observations (count, granted, denied) and `LINK`
   observations (count), and observed links are `NETWORK_OBSERVED` edges. The UI shows them on the request paths
   ([`PathDiagram.tsx`](../../frontend/src/features/paths/PathDiagram.tsx)) and in
   [`DetailsPanel.tsx`](../../frontend/src/features/details/DetailsPanel.tsx).

### Relies on / relied on by

- **Relies on** [`SYSTEM_GRAPH`](features.md#system_graph) (the links to confirm, `Routes` to match URLs) and on each
  graph's call paths: a decision is matched only to a check on its request's static path.
- **Relied on by** [`IDENTITIES`](features.md#identities), [`FINDING_UNMATCHED_CALL`](features.md#finding_unmatched_call)
  and [`FINDING_RUNTIME_ONLY_CHECK`](features.md#finding_runtime_only_check).

### Tests

- [`LinkerTests`](../../src/test/java/dev/crain/authtracer/link/LinkerTests.java#L35): `tracesConfirmLinksAndChecks`,
  `webFluxRequestDecisionsAreNamedAfterTheExchange`, `requestsDeniedBeforeRoutingMatchByUrlPath`,
  `roleChecksMatchThroughTheRoleHierarchy`, `grpcSpansLinkByTheirFullMethodName`,
  `graphQlCallsLinkByTheOperationTheServerRan`, `aCallIsTheOneOnThePathOfTheRequestItWasMadeFor`,
  `eachTracedCallIsCountedOnceEvenWhenTwoLibrariesSpanIt`, `tracedMessagesConfirmTheirLinks`,
  `tracedJmsMessagesConfirmTheirLinks`, `aFieldCheckIsCountedForEveryElementItGuards`.
- [`ZipkinTracesTests`](../../src/test/java/dev/crain/authtracer/link/ZipkinTracesTests.java#L24): the API query, files,
  tags.
- [`ExampleServicesLinkTests`](../../src/integrationTest/java/dev/crain/authtracer/ExampleServicesLinkTests.java#L26)
  (`everyRuntimeCheckMatchesTheStaticGraph`) with traces recorded from the example services in
  [`example-services-traces.json`](../../src/integrationTest/resources/zipkin/example-services-traces.json), and
  [`EndToEndSystemTests`](../../src/systemTest/java/dev/crain/authtracer/system/EndToEndSystemTests.java#L38) against
  live ones (`everyRuntimeDecisionMatchesAStaticLocation`, `observationsCountGrantsAndDenials`).

### Before changing it

- **The span names and tags are Spring's and Micrometer's, read from their code**: `authorize request` and `authorize
  exchange` (Spring Security 7.1.1's `AuthorizationObservationConvention`), the producer and consumer spans of Spring
  Kafka, Spring AMQP 4.1.1 and Spring JMS 7.0.9 with Micrometer 1.17.1. Check a new version's names before relying on
  them.
- **A guess would mismatch.** When the trace can't tell endpoints apart (a header it doesn't record), neither the call
  nor the checks are credited to one of them.
- **A field check repeats once per element it guards**, so a decision prefers a location not yet matched, then takes
  the first again.
- **Only local spans are a request's decisions**: `local` stops at client, server, producer and consumer spans, so a
  called service's decisions aren't counted on the caller.

## Identities

**Feature:** [`IDENTITIES`](features.md#identities)

For each identity the traces showed (an authentication type and its granted authorities), how many requests it made
and to which endpoints, which of its authorities the checks it passed needed, how often it was denied, and the grants
it never used: [`IdentityUsage`](../../scanner/src/main/java/dev/crain/authtracer/graph/IdentityUsage.java#L25) in the system
graph (decision 0023).

### How it works

1. **Per request.** For a server span, `observeChecks` in the [`Linker`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L53)
   asks [`Identities.request`](../../src/main/java/dev/crain/authtracer/link/Identities.java#L49) for the identity its
   decisions were made for: the `spring.security.authentication.authorities` and `.type` tags of the first decision
   that has them.
   An anonymous caller, or none at all (`n/a`), is no identity, and a message's consumer span has no caller.
2. **Granted.** `Identities.granted` reads Spring's printed list of authorities, unwrapping authority objects
   (`FactorGrantedAuthority [authority=..]`) and leaving out the `FACTOR_*` authorities Spring Security 7 grants per
   authentication factor.
3. **Per check.** For each decision, `Identity.check` counts a denial, or adds to what the identity needed: the
   authorities the decision says it asked for ([`Linker.askedAuthorities`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L96))
   that the identity holds, else those of the matched location's requirement. A granted check that names no
   authority the identity holds either way counts as unread, unless it asks for none (`permitAll`, `authenticated`
   and the like).
4. **Where it lands.** `Identities.usages` gives each identity its unneeded authorities, granted minus needed. The
   command line prints them (`identities` in [`DiffCommands`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L40),
   failing with `--fail-on-unneeded true` when an identity holds authorities nothing needed), and the UI's
   [`IdentitiesView.tsx`](../../frontend/src/features/identities/IdentitiesView.tsx) lists them.

### Relies on / relied on by

- **Relies on** [`TRACE_OBSERVATIONS`](features.md#trace_observations): the decisions and the locations they matched.
- **Relied on by** [`IDENTITIES_VIEW`](features.md#identities_view) and the `identities` command.

### Tests

- [`IdentitiesTests`](../../src/test/java/dev/crain/authtracer/link/IdentitiesTests.java#L12) and in
  [`LinkerTests`](../../src/test/java/dev/crain/authtracer/link/LinkerTests.java#L35)
  `identitiesKeepWhatTheirChecksNeeded`, `checksAuthTracerCantReadMightNeedAnything`,
  `grantedAuthoritiesAreReadFromSpringsListOfThem`, `aDecisionThatAsksForNoAuthoritiesNamesNone`.
- [`ExampleServicesLinkTests`](../../src/integrationTest/java/dev/crain/authtracer/ExampleServicesLinkTests.java#L26)
  (`testUsersHoldScopesTheirRequestsNeverNeeded`) and
  [`EndToEndSystemTests`](../../src/systemTest/java/dev/crain/authtracer/system/EndToEndSystemTests.java#L38)
  (`testIdentitiesShowWhatTheirRequestsNeverNeeded`).

### Before changing it

- **What a check needed is what the decision names first**: Spring names the roles a check was configured with,
  while the static requirement also lists the roles a RoleHierarchy lets in, so the requirement is only the fallback.
- **An identity is its type and its granted list**: two users with the same grants are one identity.

## A traced call that matches nothing

**Feature:** [`FINDING_UNMATCHED_CALL`](features.md#finding_unmatched_call)

`UNMATCHED_CALL`: a call or message between two scanned services that a trace shows, but that matches no Egress in
the caller or no Ingress in the called service. The scan missed a call site or an endpoint.

### How it works

1. `observeCall` in the [`Linker`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L53) raises it when the
   client span matches no Egress, or the server span no Ingress, naming the method and URI the client span recorded.
2. `observeMessage` raises it for a producer and consumer pair, naming the broker and destination.
3. Calls to or from services that weren't scanned are left out, and so are calls whose endpoint the trace can't pin
   to one when some Egress matches. The finding is the system's own (`SystemGraph.findings`), located at the calling
   service.

### Relies on / relied on by

- **Relies on** [`TRACE_OBSERVATIONS`](features.md#trace_observations). The diff reports a new one as a `NEW_FINDING`
  of the system (`(system)` in [`GraphDiff`](../../src/main/java/dev/crain/authtracer/diff/GraphDiff.java#L34)).

### Tests

- [`LinkerTests`](../../src/test/java/dev/crain/authtracer/link/LinkerTests.java#L35):
  `callsWithoutAStaticCounterpartAreFindings`, `aTracedCallToARouteTheCalleeDoesNotServeIsAFinding`,
  `aTracedMessageNoStaticSendOrListenerMatchesIsAFinding`, `servicesThatWereNotScannedAreLeftOutOfTheTraces`.

### Before changing it

- **Ambiguity is not a mismatch**: several endpoints the trace can't tell apart, with a matching Egress, keep the
  static links and raise nothing.

## A check only the traces show

**Feature:** [`FINDING_RUNTIME_ONLY_CHECK`](features.md#finding_runtime_only_check)

`RUNTIME_ONLY_CHECK`: Spring Security evaluated a check while serving a request, and the static graph has no location
on that endpoint's path that checks what the decision says. Either the scan missed a check, or it reads one
differently from Spring.

### How it works

1. `observeChecks` in the [`Linker`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L53) raises it for a
   decision with no candidate location of its scope whose requirement `decisionMatches`, naming the decision's
   details, the span name and the endpoint, located at the endpoint's handler.
2. Decisions are matched only when the trace pins the request to one endpoint, so the finding is never about a guess.

### Relies on / relied on by

- **Relies on** [`TRACE_OBSERVATIONS`](features.md#trace_observations) and the requirements the scan wrote
  ([`REQUIREMENTS`](features.md#requirements)): `decisionMatches` compares them with what Spring printed.

### Tests

- [`LinkerTests`](../../src/test/java/dev/crain/authtracer/link/LinkerTests.java#L35)
  (`aDecisionMatchesOnlyALocationThatChecksWhatItSays`, `theRouteOfEveryPathNamesNoEndpoint`), and the integration and
  system tests that expect none on the example services
  ([`ExampleServicesLinkTests`](../../src/integrationTest/java/dev/crain/authtracer/ExampleServicesLinkTests.java#L26),
  [`EndToEndSystemTests`](../../src/systemTest/java/dev/crain/authtracer/system/EndToEndSystemTests.java#L38)).

### Before changing it

- **Expressions are compared without whitespace and with one kind of quote** (`compact`), and authorities after the
  service's role hierarchy widens them (`widened`), as the static requirement was widened.

## A token the called service rejects

**Feature:** [`FINDING_TOKEN_REJECTED`](features.md#finding_token_rejected)

`TOKEN_REJECTED`: a call between services brings a token the called service may reject, for its audience or its
scopes, so the call fails however the caller is authorized (decision 0075).

### How it works

1. **Relayed tokens.** `Run.audienceFindings` in the [`Linker`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L53)
   goes through every link whose Egress relays the caller's token. When the called service's JWT validation checks
   audiences and the caller's doesn't guarantee one of them (it accepts any audience, or audiences the called service
   doesn't), the call is rejected unless the token also names one the called service accepts. Validators AuthTracer
   can't read on either side raise nothing.
2. **The service's own token.** `Run.clientTokenFindings` goes through every link whose Egress uses an OAuth2 client
   token with a known client registration. `issuing` finds the scanned authorization server the caller asks for
   tokens (the link from the registration's token endpoint, or its issuer's OpenID configuration, to an authorization
   server whose clients AuthTracer reads). Then:
   - a client id that server doesn't register gets no token;
   - scopes the client can't be granted get the token request refused (`invalid_scope`);
   - otherwise each non-field check on the called path that asks for a scope the token doesn't carry
     (`carrying` narrows what the called service grants to the token's scopes) denies the call.
3. Each finding is located at the Egress's call site, so the diff and SARIF point at the call.

### Relies on / relied on by

- **Relies on** [`CALL_CREDENTIALS`](features.md#call_credentials) (the Egress's credentials and registration),
  [`AUTHORITY_SOURCE`](features.md#authority_source) (each service's JWT validation and granted authorities, an
  authorization server's clients) and [`SYSTEM_GRAPH`](features.md#system_graph) (the links, including the calls
  [`IdentityProviderCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/IdentityProviderCalls.java#L33) adds to
  the authorization server).

### Tests

- [`TokenLinkTests`](../../src/test/java/dev/crain/authtracer/link/TokenLinkTests.java#L24) (audiences) and
  [`ClientTokenLinkTests`](../../src/test/java/dev/crain/authtracer/link/ClientTokenLinkTests.java#L32) (a service's own
  token).
- [`ExampleServicesLinkTests`](../../src/integrationTest/java/dev/crain/authtracer/ExampleServicesLinkTests.java#L26)
  (`payrollServicesOwnTokenCarriesWhatTheDirectoryAsks`).

### Before changing it

- **What AuthTracer can't tell is not judged**: an unread validator or an issuer whose clients aren't read raises
  nothing. A check no token at all could meet (`source.unmet` isn't empty) is the scan's to report, not the
  linker's.
- **Roles aren't judged and field checks aren't counted**: what a token customizer adds to the token isn't read, and
  a field check only hides its field.
- **Provided and Split locations are skipped**: they are enforced outside Spring Security, or stand for their parts.

### Other findings the linker raises

These are described with their feature elsewhere; they are raised here because only the system graph shows them.

| Finding | Raised by | When |
|---|---|---|
| [`OPAQUE_CALLPATH`](features.md#finding_opaque_callpath) | `Run.inferStatically` | A call whose target AuthTracer can't read may go to some scanned service |
| [`BYPASSED`](features.md#finding_bypassed), [`OPAQUE_CONFIG`](features.md#finding_opaque_config) | `Run.credentialFindings` | A call on a request path doesn't relay the caller's token, so the checks it reaches evaluate the calling service (decision 0021); `OPAQUE_CONFIG` when it carries no credentials AuthTracer can see |
| [`ALWAYS_DENIED`](features.md#finding_always_denied) | `Run.issuerFindings` | A resource server whose tokens all come from scanned authorization servers checks a scope none of their clients can be granted |

## Files

| File | Role | Features |
|---|---|---|
| [`Linker`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L53) | Links application graphs into a system graph: static links, traces, cross-service findings and flows | SYSTEM_GRAPH; `Run.observe`, `observations`, `decisionMatches` TRACE_OBSERVATIONS; `observeCall`, `observeMessage` FINDING_UNMATCHED_CALL; `observeChecks` FINDING_RUNTIME_ONLY_CHECK, IDENTITIES; `askedAuthorities`, `namesExpression` IDENTITIES; `audienceFindings`, `clientTokenFindings` FINDING_TOKEN_REJECTED; `inferStatically` FINDING_OPAQUE_CALLPATH; `credentialFindings` FINDING_BYPASSED, FINDING_OPAQUE_CONFIG, CALL_CREDENTIALS; `issuerFindings` FINDING_ALWAYS_DENIED; `networkFlows` FIELD_LINEAGE |
| [`Routes`](../../src/main/java/dev/crain/authtracer/link/Routes.java#L22) | Route templates against each other and against concrete paths; params, destinations, SOAP namespaces | SYSTEM_GRAPH |
| [`TraceSource`](../../src/main/java/dev/crain/authtracer/link/TraceSource.java#L13) | Where traces come from: a trace store or a saved file | TRACE_OBSERVATIONS |
| [`TraceSpan`](../../src/main/java/dev/crain/authtracer/link/TraceSpan.java#L16) | One span, in the shape of Zipkin's v2 API | TRACE_OBSERVATIONS |
| [`ZipkinTraces`](../../src/main/java/dev/crain/authtracer/link/ZipkinTraces.java#L30) | Trace sources speaking Zipkin's v2 JSON: the query API, or a file saved from it | TRACE_OBSERVATIONS |
| [`Identities`](../../src/main/java/dev/crain/authtracer/link/Identities.java#L24) | What each traced identity was granted, needed and never used | IDENTITIES |
