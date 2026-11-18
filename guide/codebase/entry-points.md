# Entry points

Every way into a service: the detector that finds it, the Ingress it becomes, and where `SpringSecurityModule` walks
it. The first section is the path every kind shares: the `Mapping` record, the order of the scan's phases, the rules
each kind passes first, and how Ingress ids are written. Then comes one section per entry-point feature, in the
catalogue's order: HTTP endpoints, GraphQL operations, gRPC methods, message listeners, WebSocket messages, RSocket
routes, scheduled tasks, library endpoints and gateway routes. After those is the finding for library endpoints that
answer anyone. The [Files](#files) table at the end lists every class with its role.

What happens once a request is in (the filter chain's rules, the walk through the handler's code, the response's
fields) is described in [rules.md](rules.md), [call-paths.md](call-paths.md) and [fields.md](fields.md).

## The shared path

A detector returns one of three things, and `SpringSecurityModule`'s inner `Scan` class handles each in its own way:

| What a detector returns | Made for | What the scan does with it |
|---|---|---|
| A [`RequestMappings.Mapping`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestMappings.java#L45): an Ingress and the method that handles it | Controllers, functional routes, JAX-RS, servlets, SOAP, Data REST, Actuator, a config server, GraphQL, gRPC, listeners, Stream functions, WebSocket, STOMP, RSocket, scheduled tasks | [`Scan.entryPoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L303) collects them and [`Scan.walk`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L426) walks each one: rules, filters, the handler's code, the response |
| A plain [`Ingress`](../../scanner/src/main/java/dev/crain/authtracer/graph/Ingress.java#L25), with no application handler | The H2 console, library servlets, Eureka, API docs, GraphiQL, gRPC reflection and health | [`Scan.libraryEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L702) gives each one its request rules and filters, and nothing else |
| An Ingress with its own fixed check, or with the Egress it forwards to | The authorization server's and resource server's endpoints; gateway routes | [`Scan.authorizationServers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L747), [`Scan.gatewayRoutes`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L685) |

### The Mapping

| Component | Meaning |
|---|---|
| `ingress` | The node: its id, method, route, and its response when `functional` |
| `handler` | The method the walk starts from |
| `functional` | The Ingress already carries its response, so the handler's return type isn't read and no view is rendered. It is set for every kind except controllers, JAX-RS resources and GraphQL operations |
| `transport` | The HTTP request the entry point arrives in, when it isn't one itself. Request rules and filters match the transport, not the Ingress: `POST /graphql`, the SOAP dispatcher's path, gRPC through the servlet container, the WebSocket and STOMP handshake, RSocket over WebSocket |
| `webSocket` | A second way in: the WebSocket handshake a GraphQL operation can also arrive through (decision 0034) |
| `receiver` | The controller a handler runs on when it inherits the handler from a base class, so `this` calls run the controller's methods |

### The order of the phases

1. The constructor of [`Scan`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L86) runs
   [`GrpcServices.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcServices.java#L163) before it builds
   the request rules: [`HttpSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L51)
   takes [`GrpcServices.serviceNames`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcServices.java#L84), which
   it needs for `GrpcRequest.toAnyService()`.
2. [`Scan.entryPoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L303) calls the
   detectors in this order: controllers, functional routes, SOAP, the config server, servlets, JAX-RS, listeners,
   WebSocket handlers, scheduled tasks, Stream functions, Data REST, Actuator, GraphQL, gRPC, STOMP, RSocket. Their
   findings go into the graph at once. The handlers of controllers, functional routes and GraphQL operations are
   recorded as `dispatched`: the DispatcherServlet serves them, so its interceptors run around them.
3. [`Scan.run`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L221) makes the ids unique,
   in three steps:
   [`RequestMappings.distinct`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestMappings.java#L359) splits
   handlers of one path and method by their conditions;
   [`MessageListeners.distinct`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageListeners.java#L91) splits
   several consumers of one topic by handler;
   [`RequestMappings.unique`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestMappings.java#L331) drops repeats
   and gives any other clash a `handler=` param.
4. [`ViewModels.prepare`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewModels.java#L90) sees the mappings
   that may render a view (not functional, no transport), then `Scan.walk` runs for each mapping in turn.
5. After the walks: [`Scan.gatewayRoutes`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L685),
   [`Scan.libraryEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L702), the
   infrastructure calls (see [calls.md](calls.md)),
   [`Scan.authorizationServers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L747),
   [`Scan.stompBroadcasts`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L770) and
   [`Scan.graphQlResolvers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L791).
6. After the role hierarchy, anonymous callers and Splits have changed the requirements:
   [`SensitiveEndpoints.report`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SensitiveEndpoints.java#L109), then
   [`GraphQlFieldPaths.append`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlFieldPaths.java#L44) and
   [`GraphQlFieldPaths.markSchemaFields`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlFieldPaths.java#L74).

### The rules each kind passes first

[`EntryRules.checks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L942) picks the rules
by the Ingress's kind, in this order. "Request checks" means
[`requestChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1035): Provided
requirements whose pattern matches, then
[`HttpSecurityRules.locationFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L792).

| Kind | Checks before the handler |
|---|---|
| gRPC on its own server (the transport, if any, is gRPC) | [`GrpcSecurityRules.locationsFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcSecurityRules.java#L84) for the service class |
| GraphQL with a WebSocket path | `alternatives`: the request checks of `POST /graphql`, or those of the handshake plus the `AuthenticationWebSocketInterceptor` check. One set when both ask the same; otherwise each becomes conditional and a Split asks for either |
| SOAP with more than one dispatcher path | `alternatives` over the request checks of each path |
| STOMP `MESSAGE` and `SUBSCRIBE` | `messageChecks`: the handshake's request checks, then [`MessageSecurityRules.locationsFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSecurityRules.java#L465) |
| `RSOCKET` | The handshake's request checks when over WebSocket, then [`RSocketSecurityRules.locationsFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketSecurityRules.java#L348) |
| `WEBSOCKET` | The handshake's request checks |
| Listeners and scheduled tasks ([`NoCaller.applies`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/NoCaller.java#L49)) | None: a broker or a scheduler runs them |
| Everything else | The request checks of the transport, else of the Ingress |

### Inside `walk`

1. The response: a view's model for a controller that renders one, the Ingress's own for a functional mapping, else
   [`Payloads.returnedBy`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/Payloads.java#L49) with the handler's
   `@JsonView`. The Ingress is added to the graph with it, and `SensitiveEndpoints.note` and
   [`MessagePayloads.received`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessagePayloads.java#L76) see it.
2. `EntryRules.checks`, then the request's filters around the rule and its interceptors around the handler, from
   [`Scan.filters`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L581). Only entry points
   that come in as an HTTP request, or over one's connection, have filters: listeners, tasks, gRPC on its own server,
   and STOMP and RSocket messages without a handshake have none.
3. Then, in this order: Jersey's `@RolesAllowed` check, Data REST's before-handlers, the interceptors' `preHandle`,
   the handler's walk ([`CallTraversal.walk`](../../scanner/src/main/java/dev/crain/authtracer/scan/CallTraversal.java#L141), from
   the `receiver`), `postHandle`, Data REST's after-handlers, a Stream composition's other functions and its outputs.
4. The path of an entry point nobody calls (a listener, a task, a servlet WebSocket handler's messages) is walked into
   a set of its own, and
   [`NoCaller.mark`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/NoCaller.java#L59) replaces its method checks with
   ones that deny, unless the path sets a SecurityContext. The serialized proxies' field checks, the view's checks and
   the filters' code after `chain.doFilter(..)` follow, and the path is stored as the Ingress's tail.

### Ingress ids

An id is `ingress:` + method + space + route, then `?` and the params when there are any
([`Ingress.of`](../../scanner/src/main/java/dev/crain/authtracer/graph/Ingress.java#L45),
[`Ingress.withParams`](../../scanner/src/main/java/dev/crain/authtracer/graph/Ingress.java#L94)). The rules and the linker match
the route; the params tell handlers apart.

| Kind | Example ids (after `ingress:`) | Made by |
|---|---|---|
| Controller | `GET /users/{id}`, `* /legacy` (no method given), `GET /user/messages?use_case=delegation` | `RequestMappings.detect` |
| Handlers of one path told apart by conditions | `GET /users?version:2`, `POST /orders?consumes:application/json` | `RequestMappings.distinct` |
| Functional route | `GET /x/{id}`; a predicate AuthTracer can't read gives `* /api/**` | `FunctionalEndpoints.register` |
| JAX-RS | `GET /api/orders/{id}` (variable regexes dropped) | `JaxRsResources.detect` |
| Servlet | `GET /legacy/**` for `/legacy/*`; `service(..)` gives `*` | `ServletEndpoints.servlet` |
| SOAP | `SOAP getCountry?namespace:http://x`, `SOAP http://x/GetCountry` (an action) | `SoapEndpoints.detect` |
| Data REST | `GET /persons`, `PUT /persons/{id}`, `GET /persons/search/findByName` | `DataRestRepositories.detect` |
| GraphQL | `QUERY employee`, `MUTATION hire`, `SUBSCRIPTION changes` | `GraphQlMappings.detect` |
| gRPC | `GRPC fixtures.grpc.Greeter/SayHello` | `GrpcServices.detect` |
| Listener | `KAFKA orders`, `RABBIT payroll`, `JMS audit`; `?payload=Order` for a class's handlers; `?handler=Billing.onOrder` for two consumers | `MessageListeners` |
| Stream function | `KAFKA orders` (by the binder); a Supplier `SCHEDULED Config.ticks` | `StreamFunctions.detect` |
| WebSocket handler | `WEBSOCKET /ws` | `WebSocketHandlers` |
| STOMP | `MESSAGE /app/chat`, `SUBSCRIBE /topic/chat`, `SUBSCRIBE /user/queue/replies` | `StompMappings` |
| RSocket | `RSOCKET profile.{name}` | `RSocketMappings.detect` |
| Scheduled task | `SCHEDULED ReportJob.nightly` | `ScheduledTasks.ingress` |
| Actuator | `GET /actuator/health/{*path}`, `POST /actuator/loggers/{name}` | `ActuatorEndpoints.detect` |
| Library endpoints | `GET /h2-console/**`, `* /eureka/**`, `GET /v3/api-docs`, `GET /graphiql`, `GRPC grpc.health.v1.Health/Check` | each class's `library` |
| Authorization server | `POST /oauth2/token`, `GET /.well-known/oauth-protected-resource/**` | `AuthorizationServerEndpoints`, `ResourceServerMetadata` |
| Gateway route | `* /api/**`, `GET /users/**` | `GatewayRoutes.detect` |
| Any other clash | `...?handler=fixtures.soap.Countries#getCountry` | `RequestMappings.unique` |

A GraphQL field resolver is walked as `FIELD Person.salary`, but that Ingress is never added to the graph: its steps
join the operations that reach its type.

## HTTP endpoints

Feature: [`HTTP_ENDPOINTS`](features.md#http_endpoints). Every HTTP request a service's own code answers: annotated
controllers (Spring MVC and WebFlux), functional routes, JAX-RS resources on Jersey, servlets, Spring Web Services'
SOAP operations, and the repositories Spring Data REST exports. Each is an Ingress with the checks on its path and
the fields of its response.

**How it works**

1. [`Scan.entryPoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L303) calls each
   detector below and adds its findings to the graph.
2. [`RequestMappings.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestMappings.java#L106): for each
   controller bean (`SpringBeans.isController`), the class's path prefixes
   ([`RequestMappings.prefixes`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestMappings.java#L181), taken from
   an interface or superclass when the class has none) and its handler methods (`handlerMethods`: its own, then those
   it inherits from the application's superclasses and interfaces). Kotlin's `$suspendImpl` copies, bridges and
   synthetic methods are skipped.
   [`RequestMappings.mappingInfo`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestMappings.java#L250) reads
   `@RequestMapping`, its shortcuts, or a composed annotation (`aliasedPaths` follows `@AliasFor`). A method without its
   own mapping takes the one of the method it overrides or implements, as for an OpenAPI-generated interface.
   `RequestMappings.combine` joins the class's own mapping to it as Spring's `RequestMappingInfo#combine` does: the
   methods and params of both (a class-level `method = POST` adds POST to a `@GetMapping`), its headers, and its
   `consumes`, `produces` and version where the handler has none. Each prefix, path and HTTP method gives one Ingress;
   `params` become the Ingress's params. `routes` keeps a trailing slash, as `PathPattern#combine` does: Spring 7
   matches none optionally, so `/users/` is a path of its own that a rule for `/users` doesn't reach.
3. [`FunctionalEndpoints.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FunctionalEndpoints.java#L256) reads
   every `@Bean` method that returns a `RouterFunction`, WebFlux's or Spring MVC's. Gateway Server MVC's beans are
   skipped (`gateway`). `interpret` steps through the bean's Jimple keeping symbolic values (`Builder`, `Routes`,
   `Predicate`, `Lambda`, `HandlerClass`, `Unread`). `call` handles `RequestPredicates`, static `route(..)` and
   `nest(..)`, the builder's calls (`builderCall`) and the Kotlin `router { }` and `coRouter { }` DSLs (`dslCall`). It
   follows application helpers that build routes and static predicate constants (`constant`), up to `MAX_HELPERS`
   deep. [`FunctionalEndpoints.register`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FunctionalEndpoints.java#L768)
   makes one Ingress per alternative of a route's predicate, and `response` reads the body type from `bodyValue(..)`,
   `body(publisher, Type.class)` or Kotlin's `bodyValueAndAwait`. A route's filters (a builder's `filter(..)` and
   `before(..)`, for every route it builds, and `RouterFunction#filter(..)`, outermost first) become the `Mapping`'s
   `filters`, which `Scan.walk` walks after the interceptors and before the handler; one it can't follow (`filter`:
   a lambda, a method reference or a `HandlerFilterFunction` class of the application's) is an OPAQUE_CONFIG finding.
4. [`SoapEndpoints.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SoapEndpoints.java#L88): the dispatcher's
   paths come first ([`SoapEndpoints.transports`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SoapEndpoints.java#L140)
   from `servletPaths`). They are a `ServletRegistrationBean` of a `MessageDispatcherServlet`, else an
   `AbstractMessageDispatcherServletInitializer` (`initializerPaths`), else Boot's `spring.webservices.path`
   (`/services/**`). Each `@Endpoint` method's `@PayloadRoot` is `SOAP <localPart>` with its namespace as a param, and
   each `@SoapAction` or `@Action` is `SOAP <action>`. The transport is a `POST` to the first path; with several
   paths, `EntryRules` makes each path an alternative way in.
5. [`ServletEndpoints.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ServletEndpoints.java#L140): `@WebServlet`
   classes, and `ServletRegistrationBean` beans
   ([`ServletEndpoints.registration`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ServletEndpoints.java#L260),
   through one application helper). `servlet` makes one Ingress per `doGet`, `doPost`, ... the servlet or an
   application superclass overrides, at each URL pattern
   ([`ServletEndpoints.route`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ServletEndpoints.java#L428);
   decision 0112: an extension `*.do` is `/**/*.do`, the default servlet `/` is `/**`, and `defaultServlet` reports
   one mapped to `/` where Boot maps the DispatcherServlet). A library's servlet becomes a library endpoint instead
   (see [Library endpoints](#library-endpoints)). `discovery` says who registers `@WebServlet` and `@WebFilter`
   classes: Boot's embedded server with `@ServletComponentScan`, or the container a war is deployed to, which reads
   them itself unless web.xml is metadata-complete. A Boot war (a `SpringBootServletInitializer`) may run as an
   executable jar instead, whose embedded server doesn't: its classes are registered with an OPAQUE_CONFIG finding
   (`warFinding`), its filters as ones that may not run.
6. [`JaxRsResources.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/JaxRsResources.java#L71): with a Jersey
   `ResourceConfig` (a subclass or a bean), the classes it registers (`register`, `registerClasses`, `packages`; every
   `@Path` class when it names none). Routes join `spring.jersey.application-path` (else `@ApplicationPath`), the
   class's `@Path` and the method's. When `RolesAllowedDynamicFeature` is registered,
   [`JaxRsResources.jerseyCheck`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/JaxRsResources.java#L162) makes
   Jersey's `@RolesAllowed` check, which `walk` puts after the request rule and the filters around it.
7. [`DataRestRepositories.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DataRestRepositories.java#L138):
   when Data REST is on (`active`), each repository the detection strategy exports (`exported`) is a collection at its
   pluralized domain type (Evo Inflector, as Data REST does) or its `@RepositoryRestResource(path)`. `crudMethod` picks
   the CRUD methods in Data REST's order; each query method is `GET .../search/<name>`. The
   `@RepositoryEventHandler` methods for each request
   ([`DataRestRepositories.eventHandlers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DataRestRepositories.java#L127))
   are walked before and after the repository method; an item's `PUT`, `PATCH` and `DELETE` run `findById` first.
   Query methods of the application's interfaces the repository extends are searches too. Decision 0114: each
   association of the domain type (a field with JPA's relationship annotations, MongoDB's references or Spring Data's
   `@Reference`) to another exported type is a resource under the item (`associations`): `GET .../{id}/<property>`
   (and `/{propertyId}` for a collection) runs the owner's `findById`, not the linked repository; `PUT`, `PATCH` (and
   `POST` for a collection) look each linked URI up with the linked repository's `findById`, then run the owner's
   `save`, with the link events' handlers; `DELETE` runs `findById` and `save`. `configuredBasePath` reads a
   `RepositoryRestConfigurer`'s constant `setBasePath(..)` and reports what else it sets about the resources.
8. [`Scan.withHead`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L382)
   (decision 0110): Spring MVC, WebFlux, a servlet's `doHead` and Jersey run a `GET` handler for `HEAD` too, while a
   rule for `GET` doesn't match `HEAD`. For each `GET` mapping of those (`headServed`) with no `HEAD` mapping of its
   own, it asks the rules about both methods (`HttpSecurityRules.quietly`, which undoes what asking adds to the graph);
   when `HEAD` gets something else and `GET` doesn't let everyone in, `HEAD` is an Ingress of its own, with no
   response, and a BYPASSED finding.
9. `Scan.walk` (see [the shared path](#inside-walk)) gives each one its request checks, its filters, its interceptors
   (for `dispatched` handlers only), its handler's call path and its response.

Annotated controllers and functional routes read the same on the servlet and reactive stacks: `RequestMappings`
doesn't tell them apart, and `FunctionalEndpoints` reads both packages. The stack matters later, to the rules and
filters.

**What can't be read becomes a finding.** These are OPAQUE_CONFIG findings (decision 0080), and nothing is dropped.
A route predicate AuthTracer can't read (a lambda, `negate()`, a path that isn't a constant) keeps the route, widened
to every request it may let through. A handler it can't follow keeps the route, run by `HandlerFunction#handle`. A
`RouterFunction` bean it can't read at all is named in a finding. Servlet URL patterns that aren't constants, and SOAP
endpoints with no dispatcher servlet AuthTracer can find, are findings too.

**Relies on / relied on by**

- Relies on [`CALL_PATHS`](features.md#call_paths) ([`CallTraversal`](../../scanner/src/main/java/dev/crain/authtracer/scan/CallTraversal.java#L44),
  [`RequestFilters.around`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestFilters.java#L291)),
  [`REQUEST_RULES`](features.md#request_rules) ([`HttpSecurityRules.locationFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L792)),
  [`RESPONSE_FIELDS`](features.md#response_fields) and [`VIEW_FIELDS`](features.md#view_fields)
  ([`ViewModels`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewModels.java#L45)).
- Relied on by [`SERVICE_CALLS`](features.md#service_calls):
  [`HttpClientEgress`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L77) reads a Feign or
  HTTP-interface client's mappings with `RequestMappings.mappingInfo`, and
  [`SoapCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SoapCalls.java#L37) writes a call's namespace with
  `SoapEndpoints.NAMESPACE`.
- [`RequestFilters`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestFilters.java#L66) reads filter and
  interceptor URL patterns with
  [`ServletEndpoints.mappings`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ServletEndpoints.java#L344) and a war's
  filters with [`WebXml.load`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/WebXml.java#L83)
  ([`CALL_PATHS`](features.md#call_paths)).
- [`SYSTEM_GRAPH`](features.md#system_graph): [`Routes`](../../src/main/java/dev/crain/authtracer/link/Routes.java#L22)
  matches calls to the route, the params (`paramsMatch`) and a SOAP namespace (`sameNamespace`).

**Tests**: [`WebFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/WebFixtureTests.java#L17),
[`WebFluxFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/WebFluxFixtureTests.java#L13),
[`InheritedMappingsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/InheritedMappingsFixtureTests.java#L16),
[`MappingFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MappingFormsFixtureTests.java#L13),
[`MappingParamsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MappingParamsFixtureTests.java#L15),
[`MappingConditionsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MappingConditionsFixtureTests.java#L15),
[`KotlinSuspendFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/KotlinSuspendFixtureTests.java#L13),
[`FunctionalFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FunctionalFixtureTests.java#L16) and
[`FunctionalUnreadFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FunctionalUnreadFixtureTests.java#L20)
(fixtures [`functional`](../../src/fixtures/java/fixtures/functional/),
[`kotlinroutes`](../../src/fixtures/kotlin/fixtures/kotlinroutes/)),
[`JaxRsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/JaxRsFixtureTests.java#L19),
[`ServletFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ServletFixtureTests.java#L17),
[`ServletHelpersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ServletHelpersFixtureTests.java#L17),
[`SoapFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/SoapFixtureTests.java#L26),
[`DataRestFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DataRestFixtureTests.java#L18), and the
example services in
[`ExampleServicesScanTests`](../../src/integrationTest/java/dev/crain/authtracer/ExampleServicesScanTests.java#L25).

**Before changing it**

- Only the handlers in `dispatched` get the DispatcherServlet's interceptors. They are recorded right after
  controllers and functional routes, and for GraphQL; a detector added before that line would give its handlers
  interceptors they don't have.
- Set `functional` when the handler's return value isn't the response (a `ServerResponse`, a `StreamObserver`'s
  message, a listener's nothing), or the walk reads the wrong type and may look for a view.
- Params are part of the id, not the route. The order of `distinct`, `MessageListeners.distinct` and `unique` decides
  which id a clash gets: conditions first, then the listener's handler, then the full handler key.
- The mapping lookups follow Spring's `findMergedAnnotation` order (`above`: each interface, then the superclass);
  changing it changes which mapping an override inherits.
- Library behaviour here was read from bytecode, with versions noted in the code: Spring WS 5.0.2's initializer
  mappings, Boot 4.1.1's `ServletRegistrationBean` constructors and `WebServicesAutoConfiguration` backing off for
  `@EnableWs`, Data REST 5.1.1's detection strategies. Check the jar again before relying on a different version.
- Jersey's `@RolesAllowed` asks the request wrapper's `isUserInRole`, which takes no role hierarchy:
  `hierarchiesAndFactories` and `AnonymousAuthentication` leave `JaxRsResources.MECHANISM` alone.

## GraphQL operations

Feature: [`GRAPHQL_OPERATIONS`](features.md#graphql_operations). Spring for GraphQL's queries, mutations and
subscriptions, each an Ingress named by its root field, arriving over HTTP and, when configured, over WebSocket. The
field resolvers of other types add their checks and calls to the operations that reach them, and the schema says which
fields a response can hold.

**How it works**

1. [`GraphQlMappings.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlMappings.java#L60), from
   `Scan.entryPoints`: each controller method with `@QueryMapping`, `@MutationMapping` or `@SubscriptionMapping`, or a
   `@SchemaMapping` on a root type (its own `typeName` or the class's), is `QUERY <field>`. Its transport is
   `POST <spring.graphql.http.path>` (`/graphql`); `spring.graphql.websocket.path` adds the `webSocket` way in. The
   mapping isn't `functional`, so the walk reads the handler's return type.
2. [`EntryRules.checks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L942) gives an
   operation with a WebSocket way its `alternatives` (decision 0034).
   [`GraphQlMappings.webSocketAuthentication`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlMappings.java#L97)
   turns an `AuthenticationWebSocketInterceptor` bean into an `authenticated` check on the WebSocket way.
3. `Scan.walk` walks the operation behind `POST /graphql`'s filters and interceptors.
4. [`Scan.graphQlResolvers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L791) walks each
   resolver [`GraphQlMappings.resolvers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlMappings.java#L131)
   finds once: a `@SchemaMapping` or `@BatchMapping` on a non-root type, with the source type it resolves for (`source`)
   and the value type (`valueType`, unwrapping `Mono`, collections and a batch's `Map`).
5. At the end of `run`,
   [`GraphQlFieldPaths.append`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlFieldPaths.java#L44) appends
   each resolver's steps to the operations whose result holds its type. Then
   [`GraphQlSchema.load`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlSchema.java#L40) reads the
   `.graphqls` files under `spring.graphql.schema.locations`, and
   [`GraphQlFieldPaths.markSchemaFields`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlFieldPaths.java#L74)
   marks which response fields the schema has (decision 0033).

**Relies on / relied on by**: relies on [`CALL_PATHS`](features.md#call_paths),
[`REQUEST_RULES`](features.md#request_rules) and [`RESPONSE_FIELDS`](features.md#response_fields) (see
[fields.md](fields.md)). [`GraphQlTools`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlTools.java#L19) adds
GraphiQL and the schema endpoint only when there are operations. The
[`Linker`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L53) matches a traced call to `QUERY <field>` by the
operations its server span ran ([`SYSTEM_GRAPH`](features.md#system_graph)).

**Tests**: [`GraphQlFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GraphQlFixtureTests.java#L21)
(fixtures [`graphql`](../../src/fixtures/java/fixtures/graphql/), [`graphqlbooks`](../../src/fixtures/java/fixtures/graphqlbooks/),
[`graphqlws`](../../src/fixtures/java/fixtures/graphqlws/), [`graphqlwsauth`](../../src/fixtures/java/fixtures/graphqlwsauth/)).

**Before changing it**

- An operation's id is its root field, not a path: two controllers mapping one field collide, and `unique` tells them
  apart by handler.
- A resolver's checks guard one field: a denial nulls that field and the rest of the result is returned. That is why
  they become field checks on the operations, not steps of their own (decision 0030).
- `GraphQlSchema` reads only what decides which fields a response can hold: object types, interfaces, extensions and
  the root types a `schema` block renames.

## gRPC methods

Feature: [`GRPC_METHODS`](features.md#grpc_methods). The rpcs of the gRPC services a Spring gRPC application serves,
on gRPC's own server or through the servlet container, each named by its full method name.

**How it works**

1. [`GrpcServices.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcServices.java#L163), from `Scan`'s
   constructor: each bean extending a generated `*ImplBase` (`implBaseOuter`). `methods` reads the generated `*Grpc`
   class: each static `get<Rpc>Method()` builds its descriptor with `generateFullMethodName(SERVICE_NAME, "Rpc")`, both
   constants, and its `MethodType` says whether it streams. grpc-kotlin's `*GrpcKt` takes its descriptors from
   grpc-java's class. The override is the handler; the Ingress `GRPC pkg.Service/Method` carries the rpc's response
   type, since the answer goes to a `StreamObserver`, not the handler's return.
2. Through the servlet container (`servletTransport`: a servlet application with grpc-servlet, unless
   `spring.grpc.server.servlet.enabled=false`), the transport is `POST /pkg.Service/Method` and the HTTP rules and
   filters apply. Otherwise [`EntryRules.checks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L942)
   asks [`GrpcSecurityRules.locationsFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcSecurityRules.java#L84)
   and there are no filters.
3. `Scan.entryPoints` adds the rpcs after GraphQL, and `Scan.walk` walks each handler.
4. [`GrpcServices.library`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcServices.java#L110) adds the services
   Boot's gRPC server registers (see [Library endpoints](#library-endpoints)).

**Relies on / relied on by**: relies on [`CALL_PATHS`](features.md#call_paths) and the gRPC rules
([`REQUEST_RULES`](features.md#request_rules)).
[`GrpcServices.stubCall`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcServices.java#L192) names the rpc a stub
call makes, which [`HttpClientEgress`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L77) makes
a `GRPC` Egress ([`SERVICE_CALLS`](features.md#service_calls)). `GrpcServices.serviceNames` gives
`HttpSecurityRules` the services `GrpcRequest.toAnyService()` matches.

**Tests**: [`GrpcFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GrpcFixtureTests.java#L30) (fixtures
[`grpc`](../../src/fixtures/java/fixtures/grpc/), [`grpcservlet`](../../src/fixtures/java/fixtures/grpcservlet/),
[`grpcreflection`](../../src/fixtures/java/fixtures/grpcreflection/), [`grpckotlin`](../../src/fixtures/kotlin/fixtures/grpckotlin/)
and more), [`GrpcFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GrpcFormsFixtureTests.java#L15).

**Before changing it**

- `GrpcServices` is built before the HTTP rules because they need its service names; keep it there.
- The servlet transport follows Boot 4.1.1's `ServletGrpcServerConfiguration`; with it the gRPC rules don't apply.
- The generated classes' methods are read once per class and cached (`generated`), and the cache is shared between
  services and stub calls.

## Message listeners

Feature: [`MESSAGE_LISTENERS`](features.md#message_listeners). Kafka, RabbitMQ and JMS listeners and Spring Cloud
Stream functions: an Ingress per topic, queue or destination, with what the message carries. Nobody authenticates a
message, so no request rule applies and the method checks on the path run without a caller.

**How it works**

1. [`MessageListeners.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageListeners.java#L112): each
   `@KafkaListener`, `@RabbitListener` or `@JmsListener` method (repeated ones too), and a class-level listener's
   `@KafkaHandler` and `@RabbitHandler` methods, which share its topics. `kafkaTopics` reads `topics`, `topicPattern`
   and `topicPartitions`, `rabbitQueues` reads `queues` and the queues of `bindings` and `queuesToDeclare`, and both
   resolve `${..}` from the properties. A class with several handlers tells them apart with `?payload=<Type>`. A
   listener with no destination AuthTracer can read is an OPAQUE_CONFIG finding.
2. [`MessageListeners.request`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageListeners.java#L181) sets what
   the listener receives (decisions 0090, 0098): its `@Payload` parameter, else the one Spring's resolver takes, else
   the value of a `ConsumerRecord`, `Message` or batch it takes whole.
3. [`StreamFunctions.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/StreamFunctions.java#L80), when
   `StreamBridge` and a binder are on the classpath. It binds the functions `spring.cloud.stream.function.definition`
   (or `spring.cloud.function.definition`) names, `;` between them and `|` composing them, else the only function
   bean. `functions` finds `@Bean` methods returning `Consumer`, `Function`, `Supplier` or a Kotlin function type,
   and components implementing one. The input binding `<name>-in-0`'s destinations are Ingress like a listener's; a
   `Supplier` is polled, so it is a `SCHEDULED` entry point. A `Function`'s or `Supplier`'s output binding is an
   Egress, with what it carries (`StreamFunctions.carried`).
4. `Scan.run` splits two consumers of one topic with `MessageListeners.distinct`.
5. `Scan.walk`: `EntryRules` gives no rules, the path is walked into a set of its own, and
   [`NoCaller.mark`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/NoCaller.java#L59) makes the method checks that ask
   for a caller deny there, with an ALWAYS_DENIED finding, unless the path sets a SecurityContext. For a Stream binding,
   the composition's other functions are walked next and its outputs follow, with
   [`MessagePayloads.returned`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessagePayloads.java#L70) carrying
   what the last function returns.

**Relies on / relied on by**: relies on [`CALL_PATHS`](features.md#call_paths) and
[`NoCaller`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/NoCaller.java#L28).
[`MessageSends`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSends.java#L31) uses the kind names and
[`StreamFunctions.send`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/StreamFunctions.java#L221) for
`StreamBridge.send(..)` ([`MESSAGE_SENDS`](features.md#message_sends));
[`MessagePayloads`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessagePayloads.java#L38) follows what a listener
receives on into what it writes ([`FIELD_LINEAGE`](features.md#field_lineage)); `Routes.sameDestination` links a send to
the listeners of its destination, a Kafka `topicPattern` as a regular expression
([`SYSTEM_GRAPH`](features.md#system_graph)).

**Tests**: [`MessageListenerFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MessageListenerFixtureTests.java#L25)
(fixtures [`messaging`](../../src/fixtures/java/fixtures/messaging/), [`listenerforms`](../../src/fixtures/java/fixtures/listenerforms/)),
[`StreamFunctionFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/StreamFunctionFixtureTests.java#L26)
(fixtures [`stream`](../../src/fixtures/java/fixtures/stream/), [`streamcompose`](../../src/fixtures/java/fixtures/streamcompose/),
[`streamkotlin`](../../src/fixtures/kotlin/fixtures/streamkotlin/)),
[`ConfiguredDestinationsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ConfiguredDestinationsFixtureTests.java#L21),
and the example services' listeners in the integration tests.

**Before changing it**

- A destination is resolved with `resolveKnown`: a placeholder the properties don't settle stays as written, so it
  can still match a send written the same way.
- A Stream binding is found again by `StreamFunctions.Binding.key` (handler, kind and route), because the Ingress id
  may change when the ids are made unique.
- A listener's response is set to none on purpose: a `@SendTo` reply is a message of its own.

## WebSocket messages

Feature: [`WEBSOCKET_MESSAGES`](features.md#websocket_messages). Plain WebSocket handlers and STOMP messages and
subscriptions, each behind its WebSocket handshake, which the HTTP rules check first.

**How it works**

1. [`WebSocketHandlers.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/WebSocketHandlers.java#L111). On a
   servlet stack with `@EnableWebSocket`, each `addHandler(handler, paths..)` in a `WebSocketConfigurer` gives
   `WEBSOCKET <path>`, handled by the class's `handleTextMessage`, `handleBinaryMessage` or `handleMessage`
   (`handleMethod`), with the transport `GET <path>`. `handlerClass` finds the class from what is created, what a bean
   method returns, the argument's type, or the only implementation. Decision 0113: a handler whose class it can't
   tell keeps its paths with the interface's `handleMessage`, and paths it can't read are `/**`, each with an
   OPAQUE_CONFIG finding; with `withSockJS()` on the registration (`sockJs`), the session arrives in SockJS's
   transports under the path, `GET` and `POST <path>/**` (`handshakes`); a JSR-356 `@ServerEndpoint` class is
   `WEBSOCKET <path>` too, handled by its `@OnMessage` (else `@OnOpen`) method (`serverEndpoints`). On WebFlux, `urlMapped` reads the URL maps of
   `SimpleUrlHandlerMapping` beans (`put`, `Map.of`, `Map.entry`, Kotlin's `to`). A path it can't read becomes
   `WEBSOCKET /**`, and a handler it can't follow keeps its path with the interface's `handle`; both are OPAQUE_CONFIG
   findings.
2. [`StompMappings.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/StompMappings.java#L99): `broker` reads the
   application destination prefixes and STOMP endpoints from a `WebSocketMessageBrokerConfigurer`, or from the XML's
   `<websocket:message-broker>`. Each controller's `@MessageMapping` is `MESSAGE <prefix><path>` and each
   `@SubscribeMapping` is `SUBSCRIBE <prefix><path>`. Decision 0113: every endpoint's handshake reaches them, and an
   endpoint with SockJS is its transports under the path (`handshakes`); the first is their transport. The sender
   gets the reply only from a subscription or `@SendToUser` (`replies`). Otherwise the reply goes to everyone
   subscribed to `@SendTo`'s destination, or `/topic/<path>`: a `Broadcast`. `pushes` adds a `Broadcast` for each
   `convertAndSend(..)` and `convertAndSendToUser(..)` (under `/user`) with a constant destination.
3. [`EntryRules.checks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L942): a STOMP message
   gets the handshake's request checks, then
   [`MessageSecurityRules.locationsFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSecurityRules.java#L465);
   a WebSocket handler gets the handshake's. Where a session may arrive in several handshakes, `handshakeChecks`
   makes them alternatives, a Split asking for any one's (decision 0034's way).
4. `Scan.walk`: the handshake's filters run. A servlet handshake gets only the `MappedInterceptor` beans, because
   `WebSocketConfigurationSupport` makes its handler mapping. A servlet handler's messages arrive with no
   SecurityContext, so [`NoCaller`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/NoCaller.java#L28) applies. The
   handshake's own steps keep their caller. A WebFlux handler runs with the handshake's Reactor Context
   ([`WebSocketHandlers.reactive`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/WebSocketHandlers.java#L92)), so
   its checks see the handshake's user.
5. [`Scan.stompBroadcasts`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L770): each
   broadcast's `SUBSCRIBE` exposes the fields each sender sends. The Ingress's `response` is the first sender's
   type and `otherResponses` the rest (`Ingress.withOtherResponse`), which `Exposures` reads too, telling apart two
   types' properties of one name by the type (`detail (Bulletin)`). A destination no `@SubscribeMapping` handles gets
   the handshake's request checks and its message rules, and nothing else.

**Relies on / relied on by**: relies on [`REQUEST_RULES`](features.md#request_rules) (the handshake's, and the message
rules on [rules.md](rules.md)), [`CALL_PATHS`](features.md#call_paths) and
[`RESPONSE_FIELDS`](features.md#response_fields). `MessageSecurityRules` reads the `MESSAGE` and `SUBSCRIBE` kinds;
`StompMappings.pushes` is where STOMP pushes are read ([`MESSAGE_SENDS`](features.md#message_sends)).

**Tests**: [`WebSocketHandlerFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/WebSocketHandlerFixtureTests.java#L19)
(fixtures [`websocket`](../../src/fixtures/java/fixtures/websocket/), [`webfluxsocket`](../../src/fixtures/java/fixtures/webfluxsocket/),
[`webfluxsocketkotlin`](../../src/fixtures/kotlin/fixtures/webfluxsocketkotlin/)),
[`StompFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/StompFixtureTests.java#L19),
[`StompRulesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/StompRulesFixtureTests.java#L20),
[`StompTopicsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/StompTopicsFixtureTests.java#L20),
[`XmlWebSocketFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/XmlWebSocketFixtureTests.java#L19).

**Before changing it**

- The servlet/WebFlux split in caller context is read from Reactor Netty's and Spring's code
  (`HttpServerOperations#withWebsocketSupport`, Spring Framework 7.0.9's `WebFluxConfigurationSupport`), as the class's
  Javadoc records.
- `replies` follows spring-messaging 7.0.9's `SendToMethodReturnValueHandler`: the method's annotation when it names a
  destination, else the class's.
- Message rules take no role hierarchy (decision 0039): `hierarchiesAndFactories` skips them.

## RSocket routes

Feature: [`RSOCKET_ROUTES`](features.md#rsocket_routes). The `@MessageMapping` routes Spring Boot's RSocket server
serves, on its own port or over a WebSocket on the WebFlux server, each behind its connection's setup.

**How it works**

1. [`RSocketMappings.server`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketMappings.java#L50): Boot starts a
   server when `RSocketMessageHandler` is on the classpath and `spring.rsocket.server.port` is set (even from the
   environment), or `spring.rsocket.server.mapping-path` with the `websocket` transport.
   [`RSocketMappings.port`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketMappings.java#L81) becomes one of the
   graph's ports in `additionalPorts`, so calls to it can be linked.
2. [`RSocketMappings.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketMappings.java#L94): each
   controller's `@MessageMapping` methods, the class's route and the method's joined with `.`
   ([`RSocketMappings.join`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketMappings.java#L131)), answered with
   what the method returns. Over WebSocket the transport is `GET <mapping-path>`.
3. [`EntryRules.checks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L942): the
   handshake's request checks when over WebSocket, then
   [`RSocketSecurityRules.locationsFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketSecurityRules.java#L348).
   Only the handshake has filters.

**Relies on / relied on by**: relies on [`REQUEST_RULES`](features.md#request_rules) and
[`CALL_PATHS`](features.md#call_paths). `HttpClientEgress` makes `RSocketRequester` calls `RSOCKET` Egress, which the
linker matches to these routes.

**Tests**: [`RSocketFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/RSocketFixtureTests.java#L26)
(fixtures [`rsocket`](../../src/fixtures/java/fixtures/rsocket/), [`rsocketdefault`](../../src/fixtures/java/fixtures/rsocketdefault/),
[`rsocketenvport`](../../src/fixtures/java/fixtures/rsocketenvport/)),
[`RSocketRulesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/RSocketRulesFixtureTests.java#L20).

**Before changing it**

- The route separator is `RSocketMessageHandler`'s default `.`, not `/`.
- RSocket rules are `AuthorityReactiveAuthorizationManager`'s, which take no role hierarchy: `hierarchiesAndFactories`
  skips `RSocketSecurityRules.MECHANISM`.

## Scheduled tasks

Feature: [`SCHEDULED_TASKS`](features.md#scheduled_tasks). Each `@Scheduled` method is an entry point nobody calls.
What it reaches, other services among it, is on its path, and its method checks run without a caller.

**How it works**

1. [`ScheduledTasks.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ScheduledTasks.java#L37): with
   `@EnableScheduling` on any class, each `@Scheduled` or `@Schedules` method (not Kotlin's `$suspendImpl` copy) is
   [`ScheduledTasks.ingress`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ScheduledTasks.java#L56):
   `SCHEDULED <Class>.<method>`, the class's simple name after any `$`. A Stream `Supplier` uses the same Ingress.
2. [`EntryRules.checks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L942) gives none, and
   there are no filters.
3. `Scan.walk` walks the task into a set of its own, and
   [`NoCaller.mark`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/NoCaller.java#L59) replaces each check that asks
   for a caller with `(no caller)` and an ALWAYS_DENIED finding, unless the path sets a SecurityContext.
4. Events the task publishes reach their `@EventListener` methods on the same path:
   [`CallTraversal`](../../scanner/src/main/java/dev/crain/authtracer/scan/CallTraversal.java#L44) follows `publishEvent(..)` (see
   [call-paths.md](call-paths.md)).

**Relies on / relied on by**: relies on [`CALL_PATHS`](features.md#call_paths) and `NoCaller`. The off-thread findings
in `RequestPath` word themselves for a task when `NoCaller.applies` (decision 0093).

**Tests**: [`ScheduledTaskFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ScheduledTaskFixtureTests.java#L18)
(fixtures [`scheduled`](../../src/fixtures/java/fixtures/scheduled/), [`schedules`](../../src/fixtures/java/fixtures/schedules/),
[`scheduledhandoff`](../../src/fixtures/java/fixtures/scheduledhandoff/)),
[`EventListenerFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/EventListenerFixtureTests.java#L18).

**Before changing it**

- Two tasks with the same simple class and method name share an id until `RequestMappings.unique` adds the handler.
- Without `@EnableScheduling` there are no tasks: Spring doesn't run them.

## Library endpoints

Feature: [`LIBRARY_ENDPOINTS`](features.md#library_endpoints). Endpoints a library serves rather than the application's
code: Actuator, Spring Cloud Config Server, Spring Authorization Server, a resource server's metadata, a Eureka server,
the H2 console and other library servlets, springdoc's API docs, GraphiQL and the schema, and gRPC reflection and
health. Many of them hand out secrets or control, so what checks them matters as much as the application's own.

**How it works**

Library endpoints take three shapes.

1. **Walked like a controller.**
   [`ActuatorEndpoints.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ActuatorEndpoints.java#L381): `exposed`
   lists the endpoints that are on. Actuator must be `active` (and not on a negative `management.server.port`); each
   endpoint class, from `BUILT_IN` (Boot 4.1.1's and Spring Cloud's) or the application's own `@Endpoint`, must be
   exposed (`management.endpoints.web.exposure.include`, by default `health`), accessible (`access`, capped by
   `max-permitted`) and `available`. Each `@ReadOperation`, `@WriteOperation` and `@DeleteOperation` is `GET`, `POST`
   or `DELETE` at the endpoint's `path` (`basePath` plus the id or its `path-mapping`), with a segment per
   `@Selector` (`/{*name}` for `ALL_REMAINING`). A read-only endpoint keeps its reads only. `@RestControllerEndpoint`s
   are read as Spring MVC mappings (`controllerOperations`). Ids in `include`, `exclude` and `path-mapping` compare
   as Boot's `EndpointId` compares them (`canonicalId`: `thread-dump` and `threadDump` are `threaddump`). The health
   endpoint's read is also at each `additionalHealthPaths`: a health group's `additional-path` and, with
   `management.endpoint.health.probes.add-additional-paths`, `/livez` and `/readyz`.
   [`ConfigServerEndpoints.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ConfigServerEndpoints.java#L37):
   with `@EnableConfigServer`, the mappings of the config server's own controllers, read with
   `RequestMappings.prefixes` and `mappingInfo` under `spring.cloud.config.server.prefix`. Both are `Mapping`s that
   `Scan.walk` walks like a controller's.
2. **Checked by the request rules alone.**
   [`Scan.libraryEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L702) collects
   [`ServletEndpoints.library`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ServletEndpoints.java#L206) (the H2
   console with `spring.h2.console.enabled`, and any library servlet the application registers at a path),
   [`EurekaServerEndpoints.library`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EurekaServerEndpoints.java#L33),
   [`ApiDocsEndpoints.library`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ApiDocsEndpoints.java#L35) (servlet
   stack only) and [`GraphQlTools.library`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlTools.java#L33).
   Each gets `withFilters`: the request checks, the filters around the rule and, for the last two (the
   DispatcherServlet serves them), the interceptors. [`GrpcServices.library`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcServices.java#L110)
   adds Boot's reflection and health services (and reflection the application registers by hand), checked by the gRPC
   rules on gRPC's own server or by the HTTP rules through the servlet container.
3. **With a check of their own.** [`Scan.authorizationServers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L747)
   calls [`AuthorizationServerEndpoints.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthorizationServerEndpoints.java#L135).
   The endpoints are on when the application calls `oauth2AuthorizationServer(..)` or creates the configurer, or when
   Boot configures them: no chain of the application's, and a `RegisteredClientRepository` or client properties. Each
   kind's path comes from the `AuthorizationServerSettings` builder, Boot's properties or the default. Each is an
   Ingress handled by its filter class, whose path is one step: the check for its kind of caller
   (`check`: anyone, a signed-in user, an authenticated client, or a bearer token with `SCOPE_openid` or
   `SCOPE_client.create`). The clients it issues tokens to, and their scopes, become the graph's issuer.
   [`ResourceServerMetadata.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ResourceServerMetadata.java#L57)
   adds `GET /.well-known/oauth-protected-resource/**` with a public check when a servlet chain that takes that path
   configures `oauth2ResourceServer(..)` (the Java or Kotlin DSL, or dynamic Groovy), or Boot's resource server chain
   does.

Each walked mapping, and each endpoint of the second shape except gRPC's, is passed to `SensitiveEndpoints.note` (see
[the finding](#open-sensitive-endpoints)).

**Relies on / relied on by**: relies on [`REQUEST_RULES`](features.md#request_rules) and
[`CALL_PATHS`](features.md#call_paths). [`HttpSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L51)
asks `ActuatorEndpoints` for the health paths Boot's own chain lets through (its additional ones on the server too),
and
[`SecurityDsl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L68) for the paths an
`EndpointRequest` matcher names, so Actuator's paths shape the rules too.
[`FINDING_OPEN_SENSITIVE_ENDPOINT`](features.md#finding_open_sensitive_endpoint) is built on these endpoints, and
[`INFRASTRUCTURE_CALLS`](features.md#infrastructure_calls) are the calls other services make to them.

**Tests**: [`ActuatorFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ActuatorFixtureTests.java#L18),
[`ActuatorFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ActuatorFormsFixtureTests.java#L13)
(fixtures [`actuator`](../../src/fixtures/java/fixtures/actuator/), [`actuatorcapped`](../../src/fixtures/java/fixtures/actuatorcapped/),
[`actuatorcloud`](../../src/fixtures/java/fixtures/actuatorcloud/) and more),
[`ConfigServerFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ConfigServerFixtureTests.java#L15),
[`AuthorizationServerFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AuthorizationServerFixtureTests.java#L25),
[`ResourceServerMetadataFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ResourceServerMetadataFixtureTests.java#L16),
[`EurekaServerFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/EurekaServerFixtureTests.java#L15),
[`ApiDocsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ApiDocsFixtureTests.java#L15),
[`ServletBasePathsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ServletBasePathsFixtureTests.java#L17)
(the H2 console), and [`GrpcFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GrpcFixtureTests.java#L30)
(reflection and health).

**Before changing it**

- What each library serves, when, and at which path is read from its jar, with the version in the code: Boot 4.1.1's
  Actuator access rules and endpoint classes, Spring Cloud 2025.1's endpoints, Config Server 5.0, Eureka 5.0,
  springdoc 3.0, Spring Security 7.1.1's authorization server filters and `OAuth2ProtectedResourceMetadataFilter`, and
  grpc-services 1.83.1. A new library version can move these.
- The authorization server's checks are shared per kind of caller, so the endpoints that ask the same read as one.
  Where an endpoint's filter sits (before or after the `AuthorizationFilter`) decides its kind.
- Boot's gRPC reflection service is `@ConditionalOnBean(BindableService.class)`, not on a missing bean, so it is added
  beside one the application registers.

## Gateway routes

Feature: [`GATEWAY_ROUTES`](features.md#gateway_routes). Spring Cloud Gateway's routes, on the WebFlux server and on
Server MVC. Each is an Ingress for its paths that forwards, after the gateway's own rules, to its URI. The linker joins
that call to every endpoint under it.

**How it works**

1. [`Scan.gatewayRoutes`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L685), after the
   walks, calls [`GatewayRoutes.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GatewayRoutes.java#L112).
2. Routes come from three places. `configured` reads the properties (`spring.cloud.gateway.server.webflux.routes`, the
   pre-4.3 key, and Server MVC's, as a list or keyed by id under `routes-map`), shortcut (`Path=/api/**`) or expanded
   (`name` and `args`, through `entries`). The WebFlux server's `default-filters` join each of its property routes'
   filters, ordered by their place in each list (5.0.0 `RouteDefinitionRouteLocator#getFilters`); a `RouteLocator`
   bean's routes don't get them.
   `built` reads `RouteLocatorBuilder` beans: each `route(..)` lambda and the lambdas in it (`read`), with URIs from
   constants, the configuration or what the lambda captures (`text`). `mvcBuilt` reads Server MVC `RouterFunction`
   beans route by route: `GatewayRouterFunctions.route(id)`, `GET(..)` or `path(..)`, `before(uri(..))`,
   `filter(lb(..))`, and predicates joined with `and` and `or` (`endpoints`).
3. Each path and method (`*` without a `Method` predicate) is an Ingress at the route's declaration. Its Egress,
   `Gateway`, goes to the path the filters leave
   ([`GatewayRoutes.downstream`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GatewayRoutes.java#L169):
   `StripPrefix`, `PrefixPath`, `SetPath`, `RewritePath`) at the route's URI, with `lb://x` read as `http://x`.
   [`GatewayRoutes.credentials`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GatewayRoutes.java#L143) says what it
   carries: the caller's token (a relay) unless a filter removes or sets `Authorization`, the last filter to change
   the header deciding (an added one leaves the caller's in place).
4. The route's path is its request checks, then the Egress. There is no handler to walk.

**Relies on / relied on by**: relies on [`REQUEST_RULES`](features.md#request_rules) and
[`ConfiguredValues`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ConfiguredValues.java#L37). What a route's Egress
carries is part of [`CALL_CREDENTIALS`](features.md#call_credentials).
[`FunctionalEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FunctionalEndpoints.java#L66) skips Server MVC
route beans so they aren't read twice. [`Routes.reaches`](../../src/main/java/dev/crain/authtracer/link/Routes.java#L46)
links a wildcard Egress to every route under it ([`SYSTEM_GRAPH`](features.md#system_graph), decision 0043).

**Tests**: [`GatewayFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GatewayFixtureTests.java#L21)
(fixtures [`gateway`](../../src/fixtures/java/fixtures/gateway/), [`gatewayforms`](../../src/fixtures/java/fixtures/gatewayforms/),
[`gatewaymvc`](../../src/fixtures/java/fixtures/gatewaymvc/), [`gatewaymvcforms`](../../src/fixtures/java/fixtures/gatewaymvcforms/)),
[`ConfiguredDestinationsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ConfiguredDestinationsFixtureTests.java#L21)
(`gatewayconfig`, `gatewaymvcconfig`).

**Before changing it**

- A route's path gets the request checks only: no filters or interceptors are put around it, unlike a controller's.
- Gateway Server MVC 5.0.0's `HandlerFunctions.http()` takes no URI; the URI comes from `before(uri(..))` or
  `filter(lb(..))`.
- `credentials` returns at the first filter that decides, in the route's order: `TokenRelay` relays,
  `RemoveRequestHeader=Authorization` sends nothing, and setting or adding `Authorization` sends fixed credentials.

## Open sensitive endpoints

Feature: [`FINDING_OPEN_SENSITIVE_ENDPOINT`](features.md#finding_open_sensitive_endpoint). A library endpoint that
hands out secrets or control of the application, and that answers callers who haven't signed in, is a finding of its
own (decision 0061), not one more "No Authorization" among many.

**How it works**

1. `Scan.entryPoints` builds [`SensitiveEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SensitiveEndpoints.java#L27)
   with the `ActuatorEndpoints` it detected with.
2. [`SensitiveEndpoints.note`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SensitiveEndpoints.java#L60) runs for
   every walked Ingress (with its handler) and every library endpoint of the second shape (with none). `sensitive`
   keeps those that are sensitive: the H2 console when `spring.h2.console.settings.web-allow-others` is on; a Eureka
   server's writes; a config server's `EnvironmentController` and `ResourceController`, and its
   `EncryptionController#decrypt`; and Actuator's writes, its heap dump, and `env` and `configprops` with
   `show-values=always` (by `ActuatorEndpoints.endpointId`).
3. [`SensitiveEndpoints.report`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SensitiveEndpoints.java#L109), near the
   end of `Scan.run`, reads each one's path in the graph. It is open when no unconditional check on it, other than a
   field check, has a requirement that doesn't `permitsAnyone`. An open one is an OPEN_SENSITIVE_ENDPOINT finding at its
   handler, saying what it hands out and how to close it.

**Relies on / relied on by**: relies on [`LIBRARY_ENDPOINTS`](features.md#library_endpoints) and
[`REQUEST_RULES`](features.md#request_rules); its findings reach the diff and the UI's Findings view like any other
(see [findings.md](findings.md)).

**Tests**: [`SensitiveEndpointFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/SensitiveEndpointFixtureTests.java#L21)
(fixtures [`actuatorvalues`](../../src/fixtures/java/fixtures/actuatorvalues/), [`configserver`](../../src/fixtures/java/fixtures/configserver/),
[`eurekaserver`](../../src/fixtures/java/fixtures/eurekaserver/), [`h2remote`](../../src/fixtures/java/fixtures/h2remote/)
and more).

**Before changing it**

- `report` must run after the role hierarchy, anonymous callers and Splits have settled the requirements: a check
  that reads as a role may admit anonymous callers once `AnonymousAuthentication` has applied.
- A check on only some branches doesn't keep anyone out (decision 0027); a Provided requirement does, since it is a
  check on the path.
- Only endpoints passed to `note` can be reported: the authorization server's, the resource server's metadata and
  gateway routes aren't.

## Files

| File | Role | Features |
|---|---|---|
| [`RequestMappings`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestMappings.java#L29) | Controller mappings; the `Mapping` record every detector returns; making ids unique | HTTP_ENDPOINTS; CALL_PATHS, SERVICE_CALLS, LIBRARY_ENDPOINTS on members |
| [`FunctionalEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FunctionalEndpoints.java#L66) | `RouterFunction` routes, WebFlux and MVC, Java and Kotlin DSLs | HTTP_ENDPOINTS, FINDING_OPAQUE_CONFIG |
| [`JaxRsResources`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/JaxRsResources.java#L38) | JAX-RS resources on Jersey, and Jersey's `@RolesAllowed` check | HTTP_ENDPOINTS, METHOD_SECURITY |
| [`ServletEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ServletEndpoints.java#L47) | Servlets the application registers; the H2 console; URL pattern reading for filters | HTTP_ENDPOINTS, LIBRARY_ENDPOINTS, CALL_PATHS, FINDING_OPAQUE_CONFIG |
| [`WebXml`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/WebXml.java#L30) | A war's `web.xml` filter mappings, for the filters on each request | CALL_PATHS |
| [`SoapEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SoapEndpoints.java#L40) | Spring Web Services operations behind the dispatcher servlet's paths | HTTP_ENDPOINTS, FINDING_OPAQUE_CONFIG |
| [`DataRestRepositories`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DataRestRepositories.java#L51) | Repositories Spring Data REST exports, and their event handlers | HTTP_ENDPOINTS |
| [`ConfigServerEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ConfigServerEndpoints.java#L23) | Spring Cloud Config Server's controllers | LIBRARY_ENDPOINTS |
| [`MessageListeners`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageListeners.java#L31) | Kafka, RabbitMQ and JMS listeners, and what they receive | MESSAGE_LISTENERS, FIELD_LINEAGE, FINDING_OPAQUE_CONFIG |
| [`StreamFunctions`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/StreamFunctions.java#L42) | Spring Cloud Stream function bindings, in and out | MESSAGE_LISTENERS, MESSAGE_SENDS, FIELD_LINEAGE |
| [`WebSocketHandlers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/WebSocketHandlers.java#L47) | Plain WebSocket handlers, servlet and WebFlux | WEBSOCKET_MESSAGES, FINDING_OPAQUE_CONFIG |
| [`StompMappings`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/StompMappings.java#L36) | STOMP messages, subscriptions and broadcasts | WEBSOCKET_MESSAGES, MESSAGE_SENDS |
| [`RSocketMappings`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketMappings.java#L27) | RSocket routes and the RSocket server's port | RSOCKET_ROUTES, SYSTEM_GRAPH |
| [`ScheduledTasks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ScheduledTasks.java#L20) | `@Scheduled` methods | SCHEDULED_TASKS |
| [`GraphQlMappings`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlMappings.java#L35) | GraphQL operations, field resolvers, WebSocket authentication | GRAPHQL_OPERATIONS |
| [`GraphQlSchema`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlSchema.java#L30) | The schema's object types and fields | GRAPHQL_OPERATIONS, RESPONSE_FIELDS |
| [`GraphQlTools`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlTools.java#L19) | GraphiQL and the schema endpoint | LIBRARY_ENDPOINTS |
| [`GrpcServices`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcServices.java#L40) | gRPC services and rpcs; Boot's reflection and health; stub calls' rpcs | GRPC_METHODS, LIBRARY_ENDPOINTS, SERVICE_CALLS, REQUEST_RULES |
| [`ActuatorEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ActuatorEndpoints.java#L40) | Actuator's exposed endpoints and their paths | LIBRARY_ENDPOINTS, REQUEST_RULES |
| [`SensitiveEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SensitiveEndpoints.java#L27) | Library endpoints that must not answer anyone | FINDING_OPEN_SENSITIVE_ENDPOINT |
| [`AuthorizationServerEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthorizationServerEndpoints.java#L41) | Spring Authorization Server's endpoints and their checks | LIBRARY_ENDPOINTS |
| [`ResourceServerMetadata`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ResourceServerMetadata.java#L33) | A resource server's protected resource metadata | LIBRARY_ENDPOINTS |
| [`EurekaServerEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EurekaServerEndpoints.java#L20) | A Eureka server's API and dashboard | LIBRARY_ENDPOINTS |
| [`ApiDocsEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ApiDocsEndpoints.java#L20) | springdoc's API docs and Swagger UI | LIBRARY_ENDPOINTS |
| [`GatewayRoutes`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GatewayRoutes.java#L51) | Spring Cloud Gateway routes and where they forward | GATEWAY_ROUTES, CALL_CREDENTIALS |
