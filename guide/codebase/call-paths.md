# Call paths: the scan's table of contents, and each entry point's steps

This page covers two things. First, `SpringSecurityModule`, the one `FrameworkModule` today, whose `Scan` class is the
table of contents of a scan: the configuration its constructor reads, then the phases of `run()`, each linked to the
page that covers it. Second, the [`CALL_PATHS`](features.md#call_paths) feature in depth: how one entry point's ordered
steps are put together from its entry rules, its filters and interceptors, the walk through the application's code,
the branches and beans that make a step conditional, the threads work is handed to, and the entry points nobody calls.
It ends with the files this page owns.

Vocabulary is as in the [onboarding guide](../onboarding.md); [scanning.md](scanning.md) covers `ScanContext`,
`GraphBuilder` and the graph records this page writes into.

## SpringSecurityModule: the scan's table of contents

[`ApplicationScanner.scan`](../../scanner/src/main/java/dev/crain/authtracer/scan/ApplicationScanner.java#L63) asks each module
whether it [`applies`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L73): Spring Security's
`Authentication`, Spring MVC's `DispatcherServlet`, WebFlux's `DispatcherHandler` or gRPC's `BindableService` on the
classpath. An application without Spring Security is scanned too: every endpoint is then open, and the graph says so.
[`SpringSecurityModule.scan`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L79) makes one
`Scan` and calls its `run()`.

### The configuration: the `Scan` constructor

The constructor reads what every later phase needs, in this order. Each row's class is described on its page.

| # | What | Class | Page |
|---|---|---|---|
| 1 | The code that decides checks (decision 0064), held for the whole scan | [`DecisionCode.of`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L315) | [method-checks.md](method-checks.md) |
| 2 | Spring Security's XML namespace (decision 0036); a file it can't parse is an `OPAQUE_CONFIG` finding here | [`SecurityXml.load`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityXml.java#L185) | [rules.md](rules.md) |
| 3 | Which classes are beans | [`SpringBeans`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringBeans.java#L27) | this page |
| 4 | The role hierarchy | [`RoleHierarchies.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RoleHierarchies.java#L60) | [requirements.md](requirements.md) |
| 5 | Servlet or reactive | [`WebStack.reactive`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/WebStack.java#L57) | this page |
| 6 | The filters and interceptors requests pass (decisions 0070, 0071) | [`RequestFilters`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestFilters.java#L66) | this page |
| 7 | Where authorities come from, the filters that authenticate among them; written with `graph.authoritySource` | [`AuthenticationMechanisms.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthenticationMechanisms.java#L220), [`FilterAuthentication.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FilterAuthentication.java#L108) | [requirements.md](requirements.md) |
| 8 | `server.port`, and the other ports the service listens on, which the linker matches calls against | [`SpringSecurityModule.additionalPorts`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L892) | [system.md](system.md) |
| 9 | The role prefix, and the `AuthorizationManagerFactory` the request rules are built with | [`RoleHierarchies.rolePrefix`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RoleHierarchies.java#L80), [`AuthorizationManagerFactories.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthorizationManagerFactories.java#L83) | [requirements.md](requirements.md) |
| 10 | Security configuration for the stack that doesn't run: `NOT_ENFORCED` | [`WebStack.report`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/WebStack.java#L143) | this page |
| 11 | A `MethodSecurityExpressionHandler` bean (decision 0091), and the factory pre/post builds its checks with | [`ExpressionHandlers.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ExpressionHandlers.java#L77), [`SpringSecurityModule.prePost`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L280) | [method-checks.md](method-checks.md), [requirements.md](requirements.md) |
| 12 | Method security, proxy factories and which calls go through a proxy | [`MethodSecurity`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L56), [`Proxies`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/Proxies.java#L48), [`ProxyFactories`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProxyFactories.java#L49) | [method-checks.md](method-checks.md) |
| 13 | gRPC services, needed early because the HTTP rules name them | [`GrpcServices.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcServices.java#L163) | [entry-points.md](entry-points.md) |
| 14 | The filter chains' rules, and Spring gRPC's | [`HttpSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L51), [`GrpcSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcSecurityRules.java#L38) | [rules.md](rules.md) |
| 15 | Calls to other services | [`HttpClientEgress`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L77) | [calls.md](calls.md) |
| 16 | The walk, told which classes are beans | [`CallTraversal`](../../scanner/src/main/java/dev/crain/authtracer/scan/CallTraversal.java#L44) | this page |
| 17 | Response fields, value flow, message payloads, views | [`ValueFlow`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ValueFlow.java#L64), [`ResponseFields`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ResponseFields.java#L23), [`MessagePayloads`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessagePayloads.java#L38), [`ViewModels`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewModels.java#L45), [`ViewFields`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewFields.java#L45) | [fields.md](fields.md) |
| 18 | Other threads (decision 0048), lambda names, checks the code makes itself (decision 0066) | [`AsyncCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AsyncCalls.java#L66), [`EnclosingMethods`](../../scanner/src/main/java/dev/crain/authtracer/scan/EnclosingMethods.java#L32), [`ProgrammaticChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProgrammaticChecks.java#L56) | this page, [scanning.md](scanning.md), [method-checks.md](method-checks.md) |

### The phases: `Scan.run`

[`Scan.run`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L221) runs these in order.

| # | Phase | Code | Page |
|---|---|---|---|
| 1 | Every entry point with its handler: controllers, functional routes, SOAP, the config server, servlets, JAX-RS, listeners, WebSocket handlers, scheduled tasks, Stream functions, Data REST, Actuator, GraphQL, gRPC, STOMP, RSocket | [`Scan.entryPoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L303) | [entry-points.md](entry-points.md) |
| 2 | The rules each kind of entry point passes before its handler | [`EntryRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L937), [`MessageSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSecurityRules.java#L55), [`RSocketSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketSecurityRules.java#L53) | this page, [rules.md](rules.md) |
| 3 | Each Ingress once | [`RequestMappings.distinct`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestMappings.java#L359), [`MessageListeners.distinct`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageListeners.java#L91), [`RequestMappings.unique`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestMappings.java#L331) | [entry-points.md](entry-points.md) |
| 4 | Handlers that render one view with different models (decision 0081) | [`ViewModels.prepare`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewModels.java#L90) | [fields.md](fields.md) |
| 5 | **Each entry point's path** | [`Scan.walk`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L426) | this page, below |
| 6 | Gateway routes: the gateway's rules, then the forward | [`Scan.gatewayRoutes`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L685) | [entry-points.md](entry-points.md) |
| 7 | Library endpoints (H2 console, API docs, Eureka, GraphiQL, gRPC health and reflection), checked by the rules and filters alone | [`Scan.libraryEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L702) | [entry-points.md](entry-points.md) |
| 8 | What the service calls on its authorization server, config server and Eureka (decisions 0049, 0058) | [`IdentityProviderCalls.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/IdentityProviderCalls.java#L60), [`InfrastructureCalls.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/InfrastructureCalls.java#L35) | [calls.md](calls.md) |
| 9 | An authorization server's endpoints and the clients it issues tokens to; a resource server's metadata | [`Scan.authorizationServers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L747), [`RegisteredClients.read`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RegisteredClients.java#L96) | [entry-points.md](entry-points.md), [calls.md](calls.md) |
| 10 | STOMP subscriptions, which receive what senders broadcast | [`Scan.stompBroadcasts`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L770) | [entry-points.md](entry-points.md) |
| 11 | GraphQL field resolvers, each walked once | [`Scan.graphQlResolvers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L791) | [entry-points.md](entry-points.md) |
| 12 | What requests bind into the parameters checks name | [`MethodSecurity.bindArguments`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L1167) | [method-checks.md](method-checks.md) |
| 13 | Every check's requirement widened by the role hierarchy and built by its factory | [`Scan.hierarchiesAndFactories`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L807) | [requirements.md](requirements.md) |
| 14 | `hasPermission(..)`: decided by the evaluator, or denied without one (`ALWAYS_DENIED`, `ALWAYS_GRANTED`) | [`Scan.hasPermission`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L840), [`PermissionEvaluators`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/PermissionEvaluators.java#L32) | [method-checks.md](method-checks.md) |
| 15 | What callers who haven't signed in hold (decision 0063) | [`AnonymousAuthentication.apply`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AnonymousAuthentication.java#L140) | [requirements.md](requirements.md) |
| 16 | The custom code behind checks, as they now read | [`DecisionCode.report`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L128) | [method-checks.md](method-checks.md) |
| 17 | Authorities no mechanism grants | [`AuthenticationMechanisms.ungranted`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthenticationMechanisms.java#L375) | [requirements.md](requirements.md) |
| 18 | Split locations rebuilt from their changed parts | [`SpringSecurityModule.rebuildSplits`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1078) | this page |
| 19 | Library endpoints open to anyone that hand out secrets | [`SensitiveEndpoints.report`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SensitiveEndpoints.java#L109) | [entry-points.md](entry-points.md) |
| 20 | GraphQL field paths after their operation's tail, and the schema's fields | [`GraphQlFieldPaths.append`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlFieldPaths.java#L44), [`GraphQlFieldPaths.markSchemaFields`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlFieldPaths.java#L74) | [fields.md](fields.md) |
| 21 | Hand-rolled checks and authorities set in code, where requests reach | [`Scan.handRolledChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L873), [`HandRolledChecks.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HandRolledChecks.java#L148), [`FilterAuthentication.inCode`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FilterAuthentication.java#L167) | [method-checks.md](method-checks.md), [requirements.md](requirements.md) |
| 22 | Calls whose target can't be read (decision 0082) | [`HttpClientEgress.findings`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L229) | [calls.md](calls.md) |

Why this order:

- `entryPoints()` fills fields that `walk` reads: the SOAP transports, the Jersey checks, the Data REST event handlers,
  the Stream bindings, the GraphQL operations, and `dispatched` (the handlers the `DispatcherServlet`'s handler
  mappings serve, which decides whether interceptors run).
- Phases 13 to 18 rewrite locations already in the graph, so they run after every path is drawn: the hierarchy first,
  `hasPermission` next, then what anonymous callers hold "once the hierarchy has widened the role checks", and the
  Splits last, because they are made of parts the earlier phases changed.
- `handRolledChecks` runs last because it looks only at `reachable`, the methods every request walk entered.
- GraphQL field paths continue from each operation's `PathTail`, so they need the walks.

### What each part of the module is tagged with

`SpringSecurityModule` serves nearly every feature, so its parts carry `@Supports` with what they produce. The class
itself is `CALL_PATHS` and `APPLICATION_GRAPH`.

| Part | Features |
|---|---|
| `Scan(..)` constructor | `AUTHORITY_SOURCE`, `SYSTEM_GRAPH` (ports), `FINDING_OPAQUE_CONFIG` |
| `run()` | `INFRASTRUCTURE_CALLS` |
| `prePost`, `hierarchiesAndFactories`, `rebuildSplits` | `REQUIREMENTS` |
| `entryPoints` | `HTTP_ENDPOINTS`, `GRAPHQL_OPERATIONS`, `GRPC_METHODS`, `MESSAGE_LISTENERS`, `WEBSOCKET_MESSAGES`, `RSOCKET_ROUTES`, `SCHEDULED_TASKS`, `LIBRARY_ENDPOINTS` |
| `walk` | `RESPONSE_FIELDS`, `FIELD_CHECKS`, `VIEW_FIELDS`, `FIELD_LINEAGE`, `MESSAGE_SENDS` (besides the path itself) |
| `decisionCalls` | `CUSTOM_DECISIONS`, `SERVICE_CALLS` |
| `deniedValues` | `FIELD_CHECKS`, `FINDING_OPAQUE_CALLPATH` |
| `derivingCheck`, `serialized` | `FIELD_CHECKS` |
| `passed` | `FINDING_OPAQUE_CALLPATH` |
| `gatewayRoutes` | `GATEWAY_ROUTES` |
| `libraryEndpoints`, `withFilters` | `LIBRARY_ENDPOINTS` |
| `authorizationServers` | `LIBRARY_ENDPOINTS`, `FINDING_TOKEN_REJECTED` (the issuer's clients) |
| `stompBroadcasts` | `WEBSOCKET_MESSAGES`, `RESPONSE_FIELDS` |
| `graphQlResolvers` | `GRAPHQL_OPERATIONS` |
| `hasPermission` | `FINDING_ALWAYS_DENIED`, `FINDING_ALWAYS_GRANTED`, `CUSTOM_DECISIONS` |
| `handRolledChecks` | `FINDING_UNRECOGNIZED_CHECK`, `FINDING_AUTHORITIES_IN_CODE` |
| `additionalPorts` | `SYSTEM_GRAPH` |
| `jsonViews` | `RESPONSE_FIELDS` |
| `EntryRules` | `REQUEST_RULES` |
| `messageChecks` | `WEBSOCKET_MESSAGES`, `REQUEST_RULES` |
| `requestChecks` | `REQUEST_RULES`, `PROVIDED_FACTS` |
| `alternatives` | `GRAPHQL_OPERATIONS`, `HTTP_ENDPOINTS` (SOAP's paths), `REQUEST_RULES` |
| `providedRequirements` | `PROVIDED_FACTS` |
| `RequestPath` | `METHOD_SECURITY`, `CALL_PATHS` |
| `RequestPath.offThread` | `FINDING_ALWAYS_DENIED` |
| `RequestPath.pooled` | `FINDING_AUTHORITIES_IN_CODE` |
| `RequestPath.fieldChecks` | `FIELD_CHECKS` |
| `RequestPath.bypassed` | `FINDING_BYPASSED` |
| `RequestPath.onCallSite` | `SERVICE_CALLS`, `MESSAGE_SENDS`, `CALL_CREDENTIALS`, `CUSTOM_DECISIONS`, `FIELD_LINEAGE`, `FINDING_OPAQUE_CALLPATH` |

## Call paths

Feature: [`CALL_PATHS`](features.md#call_paths). Each Ingress's **Callpath**: its steps in the order they run, as
`LOCAL` edges in the graph's `edges[]`. Every edge carries the Ingress id as its `path`, an `order` from 1, the methods
`via` which the step was reached, and `conditional` when only some ways through the code reach it. The steps are the
filter chain's rules, filters, interceptors, method and field checks, Egress, Opaque steps for code the scan can't
follow, and Split locations that stand for checks only some branches or beans make.

### How it works

One entry point, from `run()` to its edges:

1. [`Scan.run`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L221) calls `walk` for each
   mapping (an Ingress and its handler method, see [entry-points.md](entry-points.md)).
2. [`Scan.walk`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L426) first settles the
   response: the view a handler renders, or the payload it returns with its `@JsonView`
   ([`jsonViews`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L921)), and adds the Ingress
   node with it. The response's fields are [fields.md](fields.md)'s.
3. [`EntryRules.checks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L942) gives the
   first steps, the rules the entry point passes before its handler, by its kind:

   | Entry point | Steps |
   |---|---|
   | gRPC on its own server | Spring gRPC's rules for the service ([`GrpcSecurityRules.locationsFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcSecurityRules.java#L84)) |
   | GraphQL operation that may also arrive over WebSocket | [`alternatives`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1051): the HTTP request's checks, or the handshake's and the WebSocket authentication's |
   | SOAP operation behind more than one dispatcher path | [`alternatives`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1051) over each path's checks |
   | STOMP message | [`messageChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1001): the handshake's HTTP rule, then the message rule |
   | RSocket route | The WebSocket handshake's rules if over one, then the setup's and the route's ([`RSocketSecurityRules.locationsFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketSecurityRules.java#L348)) |
   | Plain WebSocket handler | Its handshake's request checks |
   | Message listener, scheduled task | None: nobody sent a request |
   | Everything else | [`requestChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1035): Provided requirements whose pattern matches ([`providedRequirements`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1146)), then the filter chain's rule ([`HttpSecurityRules.locationFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L792)) |

   `alternatives` (decisions 0034, 0056) keeps the first way's checks when every way asks for the same. Otherwise each
   way's checks are conditional and a Split location `location:SPLIT:<kind>:<endpoint>` asks for any one way's, since
   an operation is as open as its weakest way in.
4. [`Scan.filters`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L581) decides whether the
   entry point comes in as an HTTP request (itself, or over a handshake or transport request). If it does,
   [`RequestFilters.around`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestFilters.java#L291) returns an
   `Around`: the filters before the chain's rule, those after it, the interceptors before the handler and those after.
   A listener, a task, a gRPC call on its own server, and a STOMP message or RSocket route that doesn't arrive over
   an HTTP request get `Around.NONE`. A servlet WebSocket handshake passes only the `MappedInterceptor` beans; gRPC through the servlet container is served by its own
   servlet, so `spring.mvc.servlet.path` doesn't prefix it. See [Filters and interceptors](#filters-and-interceptors).
5. [`Scan.aroundRule`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L599) finds the
   filter chain's rule among the steps (the first `HTTP_REQUEST` location that isn't Provided) and puts the filters'
   steps around it. [`Scan.passed`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L629)
   walks each filter's methods with
   [`FilterChainCalls.walk`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FilterChainCalls.java#L39), which splits
   what a filter does before `chain.doFilter(..)` from what it does after. A filter it can't resolve is an Opaque step
   and an `OPAQUE_CALLPATH` finding. What filters do after the chain is kept aside, last filter first, as the request
   unwinds.
6. Then come what Jersey checks itself (`@RolesAllowed`, [`JaxRsResources.jerseyChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/JaxRsResources.java#L67)),
   and the Data REST event handlers that run before the repository
   ([`DataRestRepositories.eventHandlers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DataRestRepositories.java#L127)).
7. The interceptors' `preHandle` steps, then the handler's walk:
   [`Scan.walkFrom`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L660) calls
   [`CallTraversal.walk`](../../scanner/src/main/java/dev/crain/authtracer/scan/CallTraversal.java#L141) with a new `RequestPath`
   listener, on the controller that inherits the handler when there is one. See [The walk](#the-walk-calltraversal).
8. Then the interceptors' `postHandle` and `afterCompletion`, the Data REST handlers that run after, and for a Spring
   Cloud Stream function the functions composed after it and its outputs, as Egress.
9. For an entry point nobody calls,
   [`NoCaller.mark`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/NoCaller.java#L59) turns the method checks the
   walk reached into denials. See [No caller](#no-caller-nocaller).
10. Checks on another thread are made conditional: they deny the work there, not the request. See
    [Other threads](#other-threads-asynccalls).
11. When the handler returns an authorization proxy, Jackson calls its getters as it writes the response:
    [`serialized`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1108) adds their field
    checks (decision 0014), in getter name order, and
    [`deniedValues`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L554) records what a
    denial handler hands denied callers instead (DENY-02, decision 0076; see [fields.md](fields.md)).
12. Then the view's checks (it renders after the handler returns), then the filters' code after
    `chain.doFilter(..)`.
13. [`decisionCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L525) puts, right
    after each check, the Egress that the code deciding it calls (a remote authorization manager, OPA; decision 0065),
    found in the bodies [`DecisionCode.deciders`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L398)
    returns.
14. [`distinct`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L984) keeps each node once,
    at its first place, unconditional when any way to it is (a filter Boot registers and a chain also adds).
15. [`Scan.tail`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L677) writes the edges:
    [`PathTail.append`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/PathTail.java#L21) chains the Ingress to the
    first step and each step to the next with
    [`Edge.local`](../../scanner/src/main/java/dev/crain/authtracer/graph/Edge.java#L48), numbering `order` from 1. The tail is kept
    per Ingress, so GraphQL's field resolvers can continue the path after it.

Gateway routes, library endpoints, authorization server endpoints and STOMP subscriptions get short paths of their own
from their phases (rules, filters, a forward), written through the same `tail`.

### The walk: CallTraversal

[`CallTraversal`](../../scanner/src/main/java/dev/crain/authtracer/scan/CallTraversal.java#L44) walks application code from an
entry method in statement order. Library code is a leaf: only application methods are entered. It knows nothing of
Spring Security; it reports what it visits to a `Listener`, which turns it into node ids.

1. [`CallTraversal.walk`](../../scanner/src/main/java/dev/crain/authtracer/scan/CallTraversal.java#L141) starts a `Walk` at the
   entry method, on its receiver (the subclass that inherits it, when given).
2. `Walk.visit` enters a method unless it is already being walked (recursion) or the walk is 40 deep (`MAX_DEPTH`). It
   names the method as [`EnclosingMethods.key`](../../scanner/src/main/java/dev/crain/authtracer/scan/EnclosingMethods.java#L72)
   does: a lambda or closure by the method it is written in, and called there it is no step of its own (decision
   0089). These names make each step's `via`.
3. `Listener.onEnter` gives the nodes at the method's entry (its pre checks).
4. For each statement with a call, [`Branches.onEveryReturn`](../../scanner/src/main/java/dev/crain/authtracer/scan/Branches.java#L76)
   says whether it runs on every way the method returns; if not, what the call reaches is conditional.
   `Listener.onCallSite` gives the nodes at the call itself (an Egress, a check the code makes, an Opaque step), then
   `Walk.call` follows it.
5. `Walk.call` picks the targets:
   - a virtual call on `this` with a known receiver runs the receiver's own override;
   - a virtual call on an application type that more than one bean may answer runs one of them: `Walk.dispatch`
     walks each as an alternative (everything it reaches conditional) and `Listener.onDispatch` gives what stands for
     them at the call;
   - otherwise every target [`CallTraversal.targets`](../../scanner/src/main/java/dev/crain/authtracer/scan/CallTraversal.java#L416)
     gives is walked.
6. After the method's calls, the calls that ran on some ways only are handed to
   [`Branches.alternatives`](../../scanner/src/main/java/dev/crain/authtracer/scan/Branches.java#L91), which lists, per way to a
   return, what those calls reached. `Listener.onBranches` makes what stands for them (a Split location), and the raw
   conditional nodes are taken out of what the calls around this one collected, so they see the Split instead.
7. `Listener.onExit` gives the nodes at the method's exit (its post checks).
8. `Walk.record` keeps each node once, at its first place; a node reached unconditionally anywhere is unconditional.

`CallTraversal.targets` knows these forms:

| Call | Targets |
|---|---|
| Static, `super.` or constructor | The concrete method up the application's superclass chain |
| Virtual or interface | The declared method and every application override (class hierarchy); an application interface nothing implements (a Spring Data repository) is its own target, so its annotations apply |
| `invokedynamic` (lambda, method reference) | The application method it refers to, followed **where the lambda is created** |
| `new` of a Groovy `Closure` | Its `doCall`, followed where it is created |
| Dynamic Groovy call | The method the receiver's static type has, and its overrides ([`GroovyCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/GroovyCalls.java#L27)) |
| `publishEvent(event)` | The `@EventListener` methods and `ApplicationListener`s that take the event's static type or a supertype: they run on the publisher's thread |
| A javac bridge | The method it bridges to |

### RequestPath: what becomes a step

`RequestPath`, the listener in `SpringSecurityModule`, decides what the walk's methods and calls add to the path. It
is `METHOD_SECURITY`'s meeting point with the path; [method-checks.md](method-checks.md) explains the checks
themselves.

| Callback | What it adds |
|---|---|
| `onEnter` | Records the method in `reachable`, opens a [`Proxies.frame`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/Proxies.java#L95) (which values are authorization proxies), and returns the method's pre checks from [`MethodSecurity.checks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L238). A call on `this` skips the proxy: its proxied checks are `BYPASSED` findings and only woven (AspectJ) checks run. A field check runs only on an authorization proxy, as the factory that made it applies it (`fieldChecks`, decisions 0014, 0088). Also notes whether the call moved to another thread |
| `onCallSite` | A hand-off of a lambda to another thread (noted for when the lambda is entered); what a listener writes of its message; a check the code makes with an `AuthorizationManager` ([`ProgrammaticChecks.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProgrammaticChecks.java#L92)); reflection, a method handle or a dynamic Groovy HTTP call as an Opaque step with an `OPAQUE_CALLPATH` finding; otherwise an Egress from [`HttpClientEgress.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L296), with what a message carries ([`MessagePayloads.sent`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessagePayloads.java#L59)) |
| `onExit` | The method's post checks, on the same terms as its pre checks |
| `onBranches` | A Split for checks only some of a method's branches make (`weakest`) |
| `onDispatch` | A Split for checks only some of the beans a call may run make (`weakest`) |

Every callback's result passes `RequestPath.offThread`, which rewrites checks on another thread (below).

### Branches, dispatch and Splits

A step is **conditional** when only some ways through the code reach it (decision 0027). Exposures doesn't count a
conditional request or method check against the endpoint
([`Exposures`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L40) skips `conditional` edges for them), so
whatever stands for the branches must say what every way asks:

1. [`Branches`](../../scanner/src/main/java/dev/crain/authtracer/scan/Branches.java#L32) reads the method's control flow graph. A
   statement runs on every return when it dominates each normal return. Only normal control flow counts: a catch block
   says nothing about which calls ran. The exception is a handler that catches a denial (`AccessDeniedException`,
   `AuthorizationDeniedException` or a supertype up to `Throwable`) and goes on to return: the call's checks were
   swallowed, so the call is one way and the handler another.
2. [`Branches.alternatives`](../../scanner/src/main/java/dev/crain/authtracer/scan/Branches.java#L91) follows every path from the
   start to a return, keeping apart the sets of nodes the conditional calls reach, so `flag ? a() : b()` gives `{a}`
   and `{b}`. Past 32 alternatives at one statement they collapse to what they share, which can only ask less.
3. `RequestPath.weakest` keeps only the method and request checks of each way (field checks guard their own values on
   any branch, and off-thread copies don't constrain the caller). When every way has some, it adds a Split location
   ([`GraphBuilder.split`](../../scanner/src/main/java/dev/crain/authtracer/scan/GraphBuilder.java#L76)) asking for the weakest
   way's checks: one requirement when all ways ask the same, else an `or` of them. When a way has none, each check is a
   `BYPASSED` finding there and no Split is made.
4. Split ids are stable across compiles: `location:SPLIT:<method>` for branches (with `:lambda@<line>` for a lambda),
   `location:SPLIT:<method>:calls:<called method>` for dispatch; their mechanisms read `Branches of ..` and
   `Implementations of ..`.
5. After the hierarchy, factories and `hasPermission` have changed the parts' requirements,
   [`rebuildSplits`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1078) recomputes each
   Split from its parts, innermost first.

### Filters and interceptors

[`RequestFilters`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestFilters.java#L66) (HTTP-17, decision 0070)
reads every filter and interceptor once, in its constructor, and `around` picks a request's.

1. **The chains' own filters.** `readChain` reads `addFilterBefore/After/At` and `addFilter` in each
   `SecurityFilterChain` bean method (and the helpers and lambdas it calls), after the `Customizer<HttpSecurity>`
   beans' in `@Order`: those are in every chain, Boot's default one too. Each gets the order of 7.1.1's
   `FilterOrderRegistration` (`servletOrders`, 100 apart; -1 before, +1 after the class it is placed at), and is
   before the rule when at or before `AuthorizationFilter`. WebFlux's `addFilterAt` uses `SecurityWebFiltersOrder`
   around `AUTHORIZATION`. A position Spring wouldn't know at startup is read as before the rule.
2. **Filters the container runs.** `readServletFilters` takes the `FilterRegistrationBean`s, the `@WebFilter` classes
   (as `ServletEndpoints.discovery` says: with `@ServletComponentScan`, in a war without Boot, or, maybe, with an
   `OPAQUE_CONFIG` finding, in a Boot war) and every other `Filter` bean, each at its order, for its URL patterns.
   `readServletContextFilters` adds what `ServletContextInitializer`s and a war's `WebApplicationInitializer`s add;
   `readWebXml` what web.xml maps (a web.xml it can't read is an `OPAQUE_CONFIG` finding). On WebFlux,
   `readWebFilters` takes the `WebFilter` beans. A filter ordered before `spring.security.filter.order` (-100) runs
   before the chain's rule; any other after the chain.
3. **Interceptors.** `readMappedInterceptors` takes the `MappedInterceptor` beans, which every handler mapping runs
   first; `readInterceptors` the `InterceptorRegistry` of each `WebMvcConfigurer` bean, sorted by `order(..)`, with
   their path patterns. Their `postHandle`s run after the handler in reverse, then their `afterCompletion`s in reverse.
4. **What runs.** `RequestFilters.code` says what Spring calls on an application class: a `OncePerRequestFilter`'s
   `doFilterInternal` (conditional when it overrides `shouldNotFilter`), a filter's `doFilter`, a `WebFilter`'s
   `filter`, an interceptor's three methods. A class that extends a library filter without these runs the library's,
   which calls the methods it overrides for some requests only, so they are conditional.
5. **Which apply to a request.** `around` matches URL patterns (`/*`, `/api/*`, `*.do`, exact) to the route with the
   servlet path in front: `YES`, `NO`, or `MAYBE` when a template variable or `**` may be what a pattern names, and a
   `MAYBE` filter is conditional. A chain's filters are conditional unless the request surely passes that chain
   ([`HttpSecurityRules.chainsFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L906)). A
   `OncePerRequestFilter` bean that both Boot and a chain run does its work the first time only.
6. **What can't be resolved.** A filter or interceptor value is resolved through locals, casts, bean methods, factory
   methods and lambdas (`resolve`). One picked on branches, or an interface with several implementations, is a `Pass`
   with `unresolved` text, which `passed` turns into an Opaque step and a finding.

[`FilterChainCalls.walk`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FilterChainCalls.java#L39) (decision 0070,
amended) splits one filter method: the statements reachable from its `chain.doFilter(..)` calls, through an exception
too (a `finally` block's copy), run after the handler. It walks the filter once with a `Sorting` listener that notes,
at each call site in the filter's own body, whether it is past the hand-on; a node also reached before stays before.

`RequestFilters` also serves `AUTHORITY_SOURCE`: `filters()`, `authenticating()` (library filters added by hand that
authenticate) and `beforeRule(..)` tell [`FilterAuthentication`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FilterAuthentication.java#L38)
which filters are ways in, and whether they authenticate in time for the rule ([requirements.md](requirements.md)).

### Other threads: AsyncCalls

The `SecurityContext` is thread-local. [`AsyncCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AsyncCalls.java#L66)
answers, for the walk, whether work moved to a thread without the caller's context, and whether the caller waits for it.

1. **What carries the context**, read once (`propagation`): a `TaskDecorator` that copies it, Spring Security's
   `DelegatingSecurityContext*` executors, `ContextPropagatingTaskDecorator`, or a strategy that isn't thread-local
   (`setStrategyName`, `setContextHolderStrategy`, a `SecurityContextHolderStrategy` bean).
2. **`@Async`** (decision 0048): with `@EnableAsync`, a call through the proxy to an `@Async` method or class runs on
   another thread. Spring puts the async advisor before the others, so even the method's own checks run there.
   [`AsyncCalls.hops`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AsyncCalls.java#L249) is true unless something
   carries the context; `@Async("name")` asks whether that executor bean does (decision 0084). A call on `this` stays.
3. **Hand-offs** (decision 0062): [`AsyncCalls.handsOff`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AsyncCalls.java#L320)
   looks from the statement that creates a lambda to the call that takes it: an executor's `execute`, `submit` or
   `schedule*`, `CompletableFuture`'s `*Async` (the common pool without an executor), a new or virtual `Thread`, or a
   Reactor operator that a `publishOn` or `subscribeOn` puts on a scheduler (decision 0084; also when another method
   schedules the pipeline, decision 0099). Reactor's hop doesn't apply when reactive method security, automatic context
   propagation or a copying schedule hook carries the context.
4. **Pools** (decision 0084, amended): when only a non-thread-local strategy carries the context, a pooled thread keeps
   the context of the request that created it ([`handsOffToPool`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AsyncCalls.java#L332),
   [`pooledAsync`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AsyncCalls.java#L387)).
5. **Waiting** (decision 0084): [`AsyncCalls.waiter`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AsyncCalls.java#L274)
   finds the method that waits for the result (`get()`, `join()`, `block()` and kin, outside a handler that catches
   the failure and without a recovering operator), following the future through returns, locals, collections, fields
   and lambdas run in place (decision 0099), up to the handler, whose `CompletionStage` or publisher Spring waits for.

`RequestPath` keeps a stack of the threads the walk is on (`onEnter` pushes a `HandOff`, `onExit` pops it) and
`offThread` rewrites each check that asks for the caller:

| Where the check runs | On the path | Finding |
|---|---|---|
| Another thread, nobody waits | A copy that denies everyone, `<id>:async` or `<id>:thread`, mechanism `(@Async)` or `(other thread)`; made conditional by `walk` | `ALWAYS_DENIED`, naming the executor or propagation that would carry the context |
| Another thread, the caller waits | A copy ending `-waited`, unconditional: the request fails with it | `ALWAYS_DENIED`, naming the method that waits |
| A pool's thread, with only the strategy carrying a context | The check as it is | `AUTHORITIES_IN_CODE`: it decides for whichever request created the thread |

An Egress that relays the caller's token becomes `NONE` on another thread ("the caller's token stays on its thread").

### No caller: NoCaller

[`NoCaller`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/NoCaller.java#L28) covers entry points nobody calls: a
message listener (decision 0044), a scheduled task (decision 0046) and a servlet WebSocket handler's messages (decision
0050). A WebFlux WebSocket session has its handshake's user in its Reactor Context, so it isn't one.

1. `walk` walks such a handler into its own `walked` set, so it can tell what *this* path runs.
2. [`NoCaller.mark`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/NoCaller.java#L59) does nothing when any walked
   method sets a `SecurityContext` (`setContext`, `setAuthentication`).
3. Otherwise each step that is a method or field check asking for the caller (`asksForCaller`: not a request rule, not
   `permitAll`, not already an off-thread copy) and that the handshake's request didn't reach is replaced by a copy
   `<id>:no-caller` that denies everyone, mechanism `(no caller)`. The check itself keeps its requirement for other
   paths. One `ALWAYS_DENIED` finding per check says why.

`NoCaller` also makes the off-thread copies above, and `isOffThread` tells them by their id suffix.

### Findings the path raises

| Kind | Raised in | When |
|---|---|---|
| [`OPAQUE_CALLPATH`](features.md#finding_opaque_callpath) | `Scan.passed`, `RequestPath.onCallSite` | A filter or interceptor the scan can't resolve; reflection, a method handle, a dynamic Groovy HTTP call |
| [`BYPASSED`](features.md#finding_bypassed) | `RequestPath.bypassed` | A call on `this` past the proxy; a field check off an authorization proxy; a branch or bean without the check |
| [`ALWAYS_DENIED`](features.md#finding_always_denied) | `RequestPath.offThread`, `NoCaller.mark` | A check on another thread, or with no caller |
| [`AUTHORITIES_IN_CODE`](features.md#finding_authorities_in_code) | `RequestPath.pooled` | A check on a pooled thread that keeps another request's context |
| [`NOT_ENFORCED`](features.md#finding_not_enforced) | `WebStack.report` | A chain or `@Enable..Security` for the stack that doesn't run |
| [`OPAQUE_CONFIG`](features.md#finding_opaque_config) | `RequestFilters.readWebXml`, the `Scan` constructor | A web.xml or security XML file the scan can't read |

### The web stack, and which classes are beans

[`WebStack.reactive`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/WebStack.java#L57) (decisions 0009, 0079)
decides Servlet or WebFlux as Spring Boot 4.1.1 does: `spring.main.web-application-type`, else what the main method
sets (`setWebApplicationType`, `SpringApplicationBuilder.web`), else Boot's deducers in order (Servlet when
`DispatcherServlet` is present). Without Boot, the stack the security configuration is for, else the classpath's. The
choice picks the chains and filters read, and [`WebStack.report`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/WebStack.java#L143)
raises `NOT_ENFORCED` for the other stack's chains, which never run.

[`SpringBeans`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringBeans.java#L27) knows which application classes
are beans: components, Spring Data repositories, the classes `@Bean` methods create (the created class when every return
is a `new`), and XML beans. `isBean` drives bean dispatch in the walk and which method checks a proxy applies;
`isProxied` and `isController` serve method security and the entry points; `beanMethods` and `beanMethodsOf` are used
across the module. [`SpringNames`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringNames.java#L13) holds the
Spring type names the scanner shares.

### Relies on / relied on by

- **Relies on** [`REQUEST_RULES`](features.md#request_rules) for the first steps
  ([`HttpSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L51) and its gRPC,
  message and RSocket kin, [rules.md](rules.md)); [`METHOD_SECURITY`](features.md#method_security) for what a method
  entered adds ([`MethodSecurity`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L56),
  [`Proxies`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/Proxies.java#L48),
  [method-checks.md](method-checks.md)); [`SERVICE_CALLS`](features.md#service_calls) and
  [`MESSAGE_SENDS`](features.md#message_sends) for Egress
  ([`HttpClientEgress`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L77),
  [calls.md](calls.md)); [`CUSTOM_DECISIONS`](features.md#custom_decisions) for checks the code makes
  ([`ProgrammaticChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProgrammaticChecks.java#L56)); and on
  `ScanContext`, `Locals`, `EnclosingMethods`, `GroovyCalls` and `GraphBuilder` ([scanning.md](scanning.md)).
- **Relied on by** every entry point feature, which requires `CALL_PATHS`; [`ValueFlow`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ValueFlow.java#L64)
  (`FIELD_LINEAGE`), which follows values with the same `CallTraversal`; [`GraphQlFieldPaths`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlFieldPaths.java#L33),
  which continues paths from their `PathTail`; [`HandRolledChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HandRolledChecks.java#L52)
  and `FilterAuthentication.inCode`, which look only at `reachable`; [`Exposures`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L40)
  ([analysis.md](analysis.md)), which reads each path's unconditional checks; and the UI's request paths
  ([`pathGroups.mergePaths`](../../frontend/src/features/paths/pathGroups.ts#L83), [delivery.md](delivery.md)).

### Tests

| Test | What it pins down |
|---|---|
| [`WalkFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/WalkFormsFixtureTests.java#L17) | Every-way calls, the 32-alternative collapse, bridges, abstract classes, events and listeners (`walkforms`) |
| [`BranchesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/BranchesFixtureTests.java#L18) | Branch Splits, guard clauses and catch blocks, a swallowed denial (`branches`) |
| [`DispatchFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DispatchFixtureTests.java#L20) | Bean dispatch Splits and `BYPASSED`, bean classes a bean method creates (`dispatch`) |
| [`LambdaNamesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/LambdaNamesFixtureTests.java#L16), [`LambdaCallsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/LambdaCallsFixtureTests.java#L15) | Lambdas named by their method and line, in Java, Kotlin and Groovy |
| [`InheritedMappingsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/InheritedMappingsFixtureTests.java#L16), [`OrdersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/OrdersFixtureTests.java#L16) | The receiver's own methods on `this`; checks and Egress in call order; self-invocation |
| [`EventListenerFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/EventListenerFixtureTests.java#L18), [`ReflectionCallsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ReflectionCallsFixtureTests.java#L18), [`GroovyCallsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/GroovyCallsFixtureTests.java#L16) | Listeners on the publisher's path; reflection as Opaque; Groovy's dynamic calls |
| [`FiltersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FiltersFixtureTests.java#L25), [`FilterFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FilterFormsFixtureTests.java#L14), [`FilterMatchFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FilterMatchFixtureTests.java#L14), [`FilterRegistrationsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FilterRegistrationsFixtureTests.java#L13), [`FilterSourcesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FilterSourcesFixtureTests.java#L16) | Filter order around the rule, URL patterns, registrations, initializers, web.xml, customizers, code after `chain.doFilter` (`filterunwinding`) |
| [`InterceptorsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/InterceptorsFixtureTests.java#L14), [`InterceptorFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/InterceptorFormsFixtureTests.java#L15), [`WebFiltersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/WebFiltersFixtureTests.java#L12) | Interceptor order and patterns; WebFlux's filters |
| [`AsyncFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AsyncFixtureTests.java#L22), [`ThreadHopFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ThreadHopFixtureTests.java#L19), [`ThreadHandOffFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ThreadHandOffFixtureTests.java#L20) | `@Async`, hand-offs, pools, Reactor schedulers, waiting callers, what carries the context |
| [`MessageListenerFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MessageListenerFixtureTests.java#L25), [`ScheduledTaskFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ScheduledTaskFixtureTests.java#L18), [`WebSocketHandlerFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/WebSocketHandlerFixtureTests.java#L19) | Checks with no caller |
| [`GraphQlFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GraphQlFixtureTests.java#L21), [`SoapFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/SoapFixtureTests.java#L26), [`SplitPolicyFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/SplitPolicyFixtureTests.java#L16) | Transport Splits; a Split rebuilt with pre/post's hierarchy |
| [`FieldsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FieldsFixtureTests.java#L12), [`DenialsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DenialsFixtureTests.java#L23), [`DecisionCodeFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DecisionCodeFixtureTests.java#L23) | Serialized proxies' checks; derived denial values; Egress from decision code |
| [`WebStackFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/WebStackFixtureTests.java#L16) | Servlet or reactive, and `NOT_ENFORCED` for the other stack |
| [`ExampleServicesScanTests`](../../src/integrationTest/java/dev/crain/authtracer/ExampleServicesScanTests.java#L25) (integration) | Every path of the example services against `src/integrationTest/resources/golden` |

The fixtures are under `src/fixtures/java/fixtures/<name>` (for example
[`threadhops`](../../src/fixtures/java/fixtures/threadhops/) and
[`filterunwinding`](../../src/fixtures/java/fixtures/filterunwinding/)); tests assert a path with
`mechanisms(graph, "ingress:GET /...")`, which lists its steps in order.

### Before changing it

- **The order is Spring's.** A path's `order` is when each step runs, which decides what a check sees. Filters sit
  around the chain's rule by their order, interceptors around the handler (`postHandle` and `afterCompletion` in
  reverse), filter code after `chain.doFilter(..)` at the end, last filter first. Keep a new step at the place Spring
  runs it.
- **Conditional means "doesn't constrain the endpoint".** Exposures skips conditional request and method checks. Anything that makes a
  check conditional must leave something unconditional that says what every way asks (a Split), or a finding when a
  way asks nothing. `CallTraversal.Walk.record` and `SpringSecurityModule.distinct` both keep a node's first place and
  make it unconditional when any way to it is; keep them alike.
- **Ids must not move between compiles.** Lambdas are named by the method they are written in and their line, Split ids
  by method keys, serialized getters sorted by name. Golden graphs and diffs compare ids.
- **Off-thread and no-caller copies are found by their id suffix** (`:async`, `:thread`, `-waited`, `:no-caller`);
  `NoCaller.isOffThread` and `asksForCaller` read them. Change the suffixes together.
- **A listener's walk has its own `walked` set** until `NoCaller.mark` has run: whether a `SecurityContext` is set must
  be decided for that path alone, then the methods join `reachable`.
- **When unsure, the weaker reading.** An unread `setOrder` puts a filter before Spring Security's; unread URL patterns,
  an unread `setEnabled` or a `MAYBE` match make it conditional; an unresolved filter is an Opaque step; a strategy the
  scan can't read is taken to carry the context.
- **Library behaviour is from bytecode, with versions.** `FilterOrderRegistration` and `SecurityWebFiltersOrder`
  (Spring Security 7.1.1), `ServletContextInitializerBeans` and `WebApplicationType.deduce()` (Boot 4.1.1),
  `MappedInterceptor` and `DeferredResultMethodReturnValueHandler` (Spring Framework 7.0.9), the async advisor placed
  before the others (`setBeforeExistingAdvisors(true)`). Re-read them with `javap` when the versions move.
- **Phase order in `run()` matters**: see [Why this order](#the-phases-scanrun).

## Files

| File | Role | Features |
|---|---|---|
| [`CallTraversal`](../../scanner/src/main/java/dev/crain/authtracer/scan/CallTraversal.java#L44) | Walks application code in statement order, through calls, lambdas, events and bean dispatch, for a listener | `CALL_PATHS` |
| [`Branches`](../../scanner/src/main/java/dev/crain/authtracer/scan/Branches.java#L32) | Which calls run on every return, and the ways through a method | `CALL_PATHS` |
| [`SpringSecurityModule`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L60) | The scan's table of contents; assembles each entry point's path; `RequestPath` turns the walk into steps | `CALL_PATHS`, `APPLICATION_GRAPH`, and per part as tabled above |
| [`RequestFilters`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestFilters.java#L66) | The filters and interceptors a request passes, in Spring's order | `CALL_PATHS`; `AUTHORITY_SOURCE` (`filters`, `authenticating`, `beforeRule`); `FINDING_OPAQUE_CONFIG` (`readWebXml`) |
| [`FilterChainCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FilterChainCalls.java#L26) | Splits a filter's steps at `chain.doFilter(..)` | `CALL_PATHS` |
| [`PathTail`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/PathTail.java#L15) | Writes a path's ordered edges and remembers where it ends | `CALL_PATHS` |
| [`AsyncCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AsyncCalls.java#L66) | Work on other threads, what carries the context there, who waits for it | `CALL_PATHS` |
| [`NoCaller`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/NoCaller.java#L28) | Checks on paths nobody calls, and the off-thread copies | `MESSAGE_LISTENERS`, `SCHEDULED_TASKS`, `WEBSOCKET_MESSAGES`, `CALL_PATHS`; `FINDING_ALWAYS_DENIED` (`mark`) |
| [`WebStack`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/WebStack.java#L38) | Servlet or reactive, as Boot picks | `REQUEST_RULES`, `CALL_PATHS`; `FINDING_NOT_ENFORCED` (`report`) |
| [`SpringBeans`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringBeans.java#L27) | Which classes are beans, and the `@Bean` methods | `METHOD_SECURITY`, `CALL_PATHS`, `APPLICATION_GRAPH` |
| [`SpringNames`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringNames.java#L13) | Spring type names the scanner shares | `APPLICATION_GRAPH` |
