# Calls out

How the scan turns a call out of a service into an **Egress** node: which client calls it recognises, how it reads
each one's method, target, base URL and response type, what the call authenticates with, and what it shows when it
can't read where a call goes. The linker ([system.md](system.md)) then matches each Egress to the Ingress it reaches.

The page starts with the Egress node itself and its id, which everything downstream keys on. Then one section per
feature: [service calls](#service-calls) (HTTP, GraphQL, gRPC, RSocket and SOAP clients),
[calls whose target can't be read](#calls-whose-target-cant-be-read), [message sends](#message-sends),
[infrastructure calls](#infrastructure-calls) (identity provider, config server, Eureka) and
[call credentials](#call-credentials). It ends with the [files](#files).

## The Egress node and its id

An [`Egress`](../../scanner/src/main/java/dev/crain/authtracer/graph/Egress.java#L24) is a record. These fields decide what it
links to:

| Field | Holds | Example |
|---|---|---|
| `client` | The kind of client, a fixed name per reader | `RestClient`, `Feign`, `gRPC`, `KafkaTemplate`, `JwtDecoder` |
| `httpMethod` | An HTTP verb, `*` when it isn't a constant, or the protocol | `GET`, `*`, `QUERY`, `GRPC`, `RSOCKET`, `SOAP`, `KAFKA` |
| `uriTemplate` | The path, root field, rpc, route, operation or destination | `/employees/{id}`, `employee`, `employees.v1.EmployeeDirectory/GetEmployee` |
| `baseUrl` | The scheme, host and port, when known | `http://localhost:9000` |
| `baseUrlExpression` | Where the base URL comes from, when that's configuration | `${employee-service.base-url}` |
| `query` | A constant query string, or SOAP's namespace and action | `use_case=delegation` |
| `response` / `request` | The type the response is read into; what a message carries | `dev.crain.employees.v1.EmployeeRecord` |
| `credentials`, `credentialsVia`, `registration` | What it authenticates with, the code that showed it, and the OAuth2 client registration | `RELAY`, `ServletBearerExchangeFilterFunction` |

[`Egress.of`](../../scanner/src/main/java/dev/crain/authtracer/graph/Egress.java#L55) forms the id from the call site's
[`CodeRef.key`](../../scanner/src/main/java/dev/crain/authtracer/graph/CodeRef.java#L29) (class and method, never the line), the
method and the target:

```
egress:<class>#<method>(<parameter types>) <httpMethod> <uriTemplate>

egress:dev.crain.profileservice.employeeservice.EmployeeServiceClient#getEmployee(long) GET /employees/{id}
egress:dev.crain.employeeservice.employee.SalaryChanges#publish(long,java.math.BigDecimal,java.math.BigDecimal,java.lang.String) KAFKA employee.salary-changed
egress:org.springframework.boot.security.oauth2.server.resource.autoconfigure.JwtDecoderConfiguration GET /.well-known/openid-configuration
```

The last one is an infrastructure call: its site is the library class that makes it, so it has no method. A call
whose target isn't read gets a longer id from [`UnreadCalls.egress`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/UnreadCalls.java#L43):
`egress:<site> <method> ? <client>[ <baseUrl>]`, one per client and service in a method.

Three things follow from the id:

- **One node per method, verb and target.** [`GraphBuilder.node`](../../scanner/src/main/java/dev/crain/authtracer/scan/GraphBuilder.java#L50)
  keeps the first node of an id, so two calls in one method to the same template are one Egress, with the first one's
  line and credentials.
- **A lambda's call is its method's.** [`SpringSecurityModule.onCallSite`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1514)
  re-keys every Egress with [`Egress.withCallSite`](../../scanner/src/main/java/dev/crain/authtracer/graph/Egress.java#L80) and
  [`EnclosingMethods.site`](../../scanner/src/main/java/dev/crain/authtracer/scan/EnclosingMethods.java#L62), so a call written
  in a lambda is named after the method it's written in (decision 0089), and the id doesn't change when a lambda is
  added elsewhere in the class.
- **Everything downstream keys on it.** The path's edges point to it, the linker's links go from
  `<service>/<egress id>` ([`Linker.link`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L114)), trace matching
  narrows candidates to those on the serving request's path by id ([`Linker.narrow`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L877)),
  a cross-service Flow's `path` is it, and [`Exposures.acrossLinks`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L491)
  follows `system.linksFrom(egressId)`. Changing how an id is formed changes every golden, every link's key and every
  lineage that crosses a call.

The linker doesn't match on the id itself. [`Linker.inferStatically`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L190)
matches the fields: the base URL's host picks the service when it names one (else the port, else any service),
`httpMethod` and [`Routes.reaches`](../../src/main/java/dev/crain/authtracer/link/Routes.java#L46) pick the Ingress
(an exact [`Routes.sameTemplate`](../../src/main/java/dev/crain/authtracer/link/Routes.java#L36) wins), `query` picks
between endpoints told apart by params, and [`Linker.protocol`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L513)
keeps GraphQL, gRPC, RSocket and SOAP calls to their own kind of Ingress, by `client`.

## Service calls

Feature: [`SERVICE_CALLS`](features.md#service_calls). Each call to another service on an entry point's path
becomes an Egress step on that path, with the method, target and base URL the linker needs to find the endpoint it
reaches, and the type its response is read into.

### How it works

1. [`SpringSecurityModule.run`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L221) walks
   each entry point, and `CallTraversal` calls [`SpringSecurityModule.onCallSite`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1514)
   for every call on the way. Custom decision code is walked too:
   [`SpringSecurityModule.decisionCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L525)
   puts what it calls (a remote authorization manager, OPA) right after its check (decision 0065).
2. In `onCallSite`, a dynamic Groovy call on a RestClient, WebClient or RestTemplate
   ([`HttpClientEgress.dynamicClient`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L449))
   is untyped past its first call, so it becomes an Opaque step with an `OPAQUE_CALLPATH` finding, not an Egress.
   Every other call goes to [`HttpClientEgress.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L296).
3. `detect` tries the readers in this order, and the first that recognises the call answers. (A dynamic Groovy call on
   a typed receiver, and a method reference such as `ids.stream().map(orders::order)`, are tried as HTTP interface and
   Feign calls only.)

   | Reader | Recognises | `client` | `httpMethod` | `uriTemplate` | Base URL | Response |
   |---|---|---|---|---|---|---|
   | [`fluent`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L460), [`withoutUri`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L536) | `uri(..)` on a RestClient or WebClient request; `retrieve()`/`exchange..()` on one with no `uri` (the path is `/`) | `RestClient`, `WebClient` | `get()`, `post()`... or `method(HttpMethod.X)` followed back; `*` | The `uri` argument, or what a `uri(builder -> ..)` function adds | [`fluentBaseUrl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1770) | [`response`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L507): the first `body`, `bodyToMono`, `toEntity`... after `uri` |
   | [`restTemplate`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L850) | `getForObject`, `postForEntity`, `exchange`, `execute`... and `exchange(requestEntity, ..)` | `RestTemplate` | From the method's name, or `exchange`'s `HttpMethod` argument | The URL argument, or the [`requestEntity`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L928)'s | Absolute URL, else [`restTemplateBaseUrl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L911) (`rootUri`) | A class literal or `ParameterizedTypeReference` argument |
   | [`jdkHttpClient`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L696) | `HttpClient.send`/`sendAsync` | `HttpClient` | `GET()`, `POST(..)`, `method("X", ..)`; `GET` by default, `*` for a request built elsewhere | `newBuilder(uri)` or `uri(..)` | The URI's | None |
   | [`graphQl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L573) | `retrieve..(path)`/`execute..()` on a GraphQL request | `GraphQlClient` | The operation type, `*` without a document | The root field the response path reads ([`GraphQlDocuments.firstOperation`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlDocuments.java#L52)) | `url(..)` on a GraphQL client builder, else the RestClient's or WebClient's, scheme, host and port only | `toEntity`/`toEntityList` |
   | [`rsocket`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L632) | `RSocketRequester.route(..)` | `RSocketRequester` | `RSOCKET` | The route | `tcp://host:port` or `websocket(uri)`, in the class or a `@Bean` method | `retrieveMono`/`retrieveFlux` |
   | [`grpcCall`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L389) | A generated stub's method ([`GrpcServices.stubCall`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcServices.java#L192)) | `gRPC` | `GRPC` | `package.Service/Method` | The channel's target property, in `baseUrlExpression` | The rpc's response type |
   | [`httpInterface`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1003) | A call to an interface method with `@GetExchange`... (or a method reference to one) | `HTTP interface` | The annotation's | The interface's and the method's URLs, joined | Absolute `url`, else [`serviceGroupBaseUrl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1061), else [`proxyFactoryBaseUrl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1093) | The method's return type |
   | [`feign`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L353) | A call to a `@FeignClient` interface method | `Feign` | The Spring MVC mapping's ([`RequestMappings.mappingInfo`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestMappings.java#L250)) | The client's `path` and the mapping | `url`, else `http://<name>` | The method's return type |
   | [`MessageSends.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSends.java#L81) | Template sends and `StreamBridge.send` | See [message sends](#message-sends) | | | | |
   | [`SoapCalls.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SoapCalls.java#L67) | `WebServiceTemplate.marshalSendAndReceive` and its other sends | `WebServiceTemplate` | `SOAP` | The request's root element ([`SoapCalls.rootElement`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SoapCalls.java#L156), [`SoapCalls.elementName`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SoapCalls.java#L226)), else its SOAP action | The `uri` argument, else [`SoapCalls.defaultUri`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SoapCalls.java#L175) | None |

4. A URL argument is read by [`HttpClientEgress.url`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1199):
   - a constant, split by [`HttpClientEgress.split`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1732)
     into a base URL and a path. [`HttpClientEgress.pathOnly`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1757)
     drops the query string, which a constant one keeps in `query`;
   - `URI.create`, `new URI` and `UriComponentsBuilder` chains ([`HttpClientEgress.uriCall`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1513)):
     `path(..)` and `pathSegment(..)` add to the path, and the calls that only add a query, expand or build pass it
     through;
   - text built from parts ([`HttpClientEgress.textParts`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1348)):
     a concatenation, a `StringBuilder`'s appends, `String.format` or `formatted` with a constant format.
     [`HttpClientEgress.joined`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1314) makes the
     first part, when it's a value, the base URL, and each other value the text it holds when the configuration says,
     else a path variable `{p1}`, `{p2}`...;
   - a value from the configuration ([`ConfiguredValues.of`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ConfiguredValues.java#L68)):
     a `@Value` parameter or field, a field a constructor sets from one, a `@ConfigurationProperties` getter. A whole
     URL there is split; anything else is the base URL.

   [`HttpClientEgress.templateUrl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1249)
   expands URI variables in the host (`http://{host}:8080/orders`, `{gateway}/orders`) from the call's varargs or
   `Map.of(..)`, as Spring's `UriComponents` does. A `uri(builder -> ..)` function, a lambda, a method reference or a
   Groovy closure, is read statement by statement in
   [`HttpClientEgress.readUriFunction`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1612),
   following the builder into the application's helpers; `scheme`, `host` or `port` there sends the request
   elsewhere than the client's base URL, so the base URL is dropped.
5. A fluent client's base URL ([`HttpClientEgress.fluentBaseUrl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1770))
   is, in order: the one the chain builds right there (`RestClient.create(url).get()`); the one the field it's read
   from was built with ([`HttpClientEgress.fieldBaseUrl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1806),
   when every assignment agrees); the one the class configures ([`HttpClientEgress.classBaseUrl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1849),
   only when it configures exactly one); the one the application's only `@Bean` method of that client type sets
   ([`HttpClientEgress.beanBaseUrl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1866)).
   [`HttpClientEgress.rebased`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1718) then
   moves a base URL's own path in front of the request's: `http://orders/api` and `/orders/{id}` are
   `http://orders` and `/api/orders/{id}`.
6. The reader wraps the result in [`HttpClientEgress.withCredentials`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L237)
   (see [call credentials](#call-credentials)) and returns it. Back in `onCallSite`, a relayed token on another thread
   becomes `NONE` (decisions 0048, 0062), the Egress is re-keyed and added to the graph, and
   [`MessagePayloads.sent`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessagePayloads.java#L59) fills a
   message's request fields. Its id becomes the path's next step.

### Relies on / relied on by

- Relies on [`CALL_PATHS`](features.md#call_paths) (`CallTraversal` reaches the call),
  [`GrpcServices.stubCall`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcServices.java#L192) for stubs,
  [`RequestMappings.mappingInfo`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestMappings.java#L250) for Feign's
  mappings, [`Payloads.returnedBy`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/Payloads.java#L49) for interface
  return types, and the service's properties (`context.properties()`).
- Relied on by [`SYSTEM_GRAPH`](features.md#system_graph) ([`Linker.inferStatically`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L190),
  and [`Linker.egresses`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L846) for traced calls) and
  [`FIELD_LINEAGE`](features.md#field_lineage), which matches an Egress's `response` to the reached Ingress's.
  [`GatewayRoutes`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GatewayRoutes.java#L51) reads route URIs with
  `textParts`, `RequestFilters` names filters with [`HttpClientEgress.constant`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L812),
  and [`GraphQlSchema`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlSchema.java#L30) reads SDL with
  [`GraphQlDocuments.tokenize`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlDocuments.java#L155).

### Tests

- [`ClientsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ClientsFixtureTests.java#L13): RestTemplate,
  WebClient, base URLs from fields and beans, HTTP interfaces, the JDK's client (fixtures
  [`clients`](../../src/fixtures/java/fixtures/clients/), [`jdkclient`](../../src/fixtures/java/fixtures/jdkclient/)).
- [`ClientFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ClientFormsFixtureTests.java#L18),
  [`EgressUrlsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/EgressUrlsFixtureTests.java#L19) and
  [`EgressConcatFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/EgressConcatFixtureTests.java#L10):
  the other ways code writes a request and a URL ([`egressurls`](../../src/fixtures/java/fixtures/egressurls/),
  [`egressconcat`](../../src/fixtures/java/fixtures/egressconcat/)).
- [`FeignFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FeignFixtureTests.java#L18),
  [`GraphQlClientTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GraphQlClientTests.java#L20),
  [`GraphQlDocumentsTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GraphQlDocumentsTests.java#L7),
  [`GrpcFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GrpcFixtureTests.java#L30),
  [`RSocketFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/RSocketFixtureTests.java#L26),
  [`SoapFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/SoapFixtureTests.java#L26): one per client
  kind ([`graphqlclient`](../../src/fixtures/java/fixtures/graphqlclient/),
  [`grpcclient`](../../src/fixtures/java/fixtures/grpcclient/),
  [`rsocketclient`](../../src/fixtures/java/fixtures/rsocketclient/),
  [`soapclient`](../../src/fixtures/java/fixtures/soapclient/)).
- [`GroovyUriFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GroovyUriFixtureTests.java#L17) and
  [`GroovyFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GroovyFixtureTests.java#L22): closures as
  `uri` functions, and dynamic Groovy clients ([`groovyuri`](../../src/fixtures/groovy/fixtures/groovyuri/),
  [`groovyclients`](../../src/fixtures/groovy/fixtures/groovyclients/)).
- The integration goldens: every example service's Egress, ids included.

### Before changing it

- **The order in `detect` matters.** An application interface is tried as an HTTP interface before Feign, and both
  only after the library clients. A call on an application type returns there, so it never reaches the message and
  SOAP readers.
- **Spring's own joining rules are copied, not guessed.** `rebased` joins as `DefaultUriBuilderFactory` and Boot's
  `RootUriTemplateHandler` do; [`HttpClientEgress.exchangeUrl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L1041)
  puts a `/` between an interface's and a method's URL as Spring 7's `HttpServiceMethod` does; Feign's name is
  resolved as `FeignClientsRegistrar.getName` does (5.0); gRPC's address comes from Boot 4.1's
  `spring.grpc.client.channel.<name>.target`, then the standalone starter's `channels.<name>.address`.
- **Don't pick among several.** A class that configures two base URLs has none the walk can pick, a field assigned
  two has none, and a `@Bean` counts only when it's the only one of its type. A host that is a URI variable with no
  known value leaves `baseUrl` empty and keeps the template in `baseUrlExpression`.
- **A response type is the first body call after the `uri` call**, and the search stops at the next `uri`, so a
  method making two requests gives each its own.
- Chains are followed back at most `MAX_CHAIN` calls (24 for the JDK's request builder).

## Calls whose target can't be read

Feature: [`FINDING_OPAQUE_CONFIG`](features.md#finding_opaque_config) (with service calls and message sends). A call
AuthTracer recognises but whose target it can't read is still an Egress, with the target
[`Egress.UNKNOWN_TARGET`](../../scanner/src/main/java/dev/crain/authtracer/graph/Egress.java#L32) (`?`), and an `OPAQUE_CONFIG`
finding that says what it couldn't read and where that came from (decision 0082). Dropping the call would make the
service look as if it called nothing there.

### How it works

1. A reader that can't read the target calls [`UnreadCalls.egress`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/UnreadCalls.java#L43)
   with what it does know (client, method, base URL, response type), what it couldn't read (`path`, `URL`, `field`,
   `route`, `topic`, `queue`, `destination`, `binding`, `request`) and why.
2. [`UnreadCalls.origin`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/UnreadCalls.java#L66) says where the value
   came from in one look back: "a parameter", "the field x", "a concatenation", "what Map.get(..) returns", "a new X".
3. `UnreadCalls` keeps the findings, and [`SpringSecurityModule.run`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L221)
   adds them to the graph after every path is walked, through [`HttpClientEgress.findings`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L229):

   ```
   The RestClient call in fixtures.unreadcalls.OrderCalls#pathFromParameter(java.lang.String) sends POST to
   http://orders:8080 with a path AuthTracer can't read (UriBuilder.path(..) with a value that isn't a constant):
   its Egress is POST ?, which links to nothing
   ```
4. [`Linker.inferStatically`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L190) links a `?` to nothing (it
   would otherwise reach `/{name}`). When its base URL names a service, or it's a message and a service listens on
   that broker, the linker adds an `OPAQUE_CALLPATH` finding: the call "may go to" those services.

What becomes `?`:

| Client | Unread when |
|---|---|
| RestClient, WebClient | The `uri` argument isn't read (a whole URL, so the base URL is dropped too), or the `uri` function does something other than add constant paths |
| RestTemplate | The URL argument isn't read, or the `RequestEntity` comes from elsewhere |
| HttpClient | The URI isn't read, or the request or its builder comes from elsewhere |
| GraphQlClient | Neither a constant document (or `graphql-documents/` file) nor a constant response path |
| RSocketRequester | The route isn't a constant |
| WebServiceTemplate | Neither a request type with a root element nor a SOAP action (XML sent as it is, a message a callback writes) |
| KafkaTemplate | The topic isn't read; `sendDefault` or a `Message` with no `kafka_topic` header, without `spring.kafka.template.default-topic` |
| JmsTemplate | A `Destination` object, or the template's default destination |
| RabbitTemplate | The template's default exchange, a named exchange (its bindings aren't read), or an exchange from a value |
| StreamBridge | The binding isn't read |

HTTP interfaces and Feign clients are never unread: their target is declared. A call no reader recognises isn't an
Egress at all.

### Tests

[`UnreadCallsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/UnreadCallsFixtureTests.java#L25) on
[`unreadcalls`](../../src/fixtures/java/fixtures/unreadcalls/): every client's unread form, the finding's text, and
the linker placing it nowhere.

### Before changing it

- The unread id adds the client and base URL, so two unread sends of one template in one method are one Egress, but a
  topic and a binding, or two services, stay apart.
- `?` must stay out of matching: `Routes.reaches` would land it on `/{name}`, and a Kafka `topicPattern` could match
  it, so `inferStatically` checks for it before either.

## Message sends

Feature: [`MESSAGE_SENDS`](features.md#message_sends). A message sent to a topic, queue or destination is an Egress
the linker links to the listeners of that name, with the type of what it carries.

### How it works

1. `HttpClientEgress.detect` hands calls no HTTP reader took to [`MessageSends.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSends.java#L81).
2. `StreamBridge.send("binding", ..)` goes to [`StreamFunctions.send`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/StreamFunctions.java#L221):
   the binding's binder ([`StreamFunctions.binder`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/StreamFunctions.java#L247),
   `KAFKA` or `RABBIT`) and destination (decision 0047).
3. Template sends go through [`MessageSends.templateSend`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSends.java#L176):

   | Template | Destination |
   |---|---|
   | `KafkaTemplate` `send` | Its topic argument, a `ProducerRecord`'s first constructor argument, or a built `Message`'s `kafka_topic` header ([`MessageSends.message`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSends.java#L148)); else the default topic |
   | `KafkaTemplate` `sendDefault` | `spring.kafka.template.default-topic` ([`MessageSends.defaultTopic`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSends.java#L230)) |
   | `JmsTemplate`, `JmsMessagingTemplate` `send`, `convertAndSend`, `sendAndReceive`, `convertSendAndReceive` | Its destination name argument |
   | `RabbitTemplate` the same four | The routing key on the default exchange (`""` or no exchange), which routes by queue name |

4. [`MessageSends.destination`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSends.java#L261) reads the
   name through `ConfiguredValues`. A placeholder no file sets is kept as `${..}`, which a listener with the same
   placeholder matches. The Egress is `client` the template's simple name, `httpMethod` `KAFKA`, `RABBIT` or `JMS`,
   `uriTemplate` the destination.
5. [`MessageSends.request`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSends.java#L131) records the
   message's type when it's an application type (decision 0090), taken by [`MessageSends.payload`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSends.java#L110):
   the last `Object` parameter, a `ProducerRecord`'s value, or a built `Message`'s payload (decision 0098).
   `MessagePayloads.sent` then fills its fields on the walk.
6. The linker matches the destination with [`Routes.sameDestination`](../../src/main/java/dev/crain/authtracer/link/Routes.java#L60),
   and a traced producer span with [`Linker.observeMessage`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L632).

A message carries no caller, so a send has no `credentials`: the UI shows "no caller"
([`NO_CALLER`](../../frontend/src/lib/format.ts#L135)). STOMP pushes to subscribers are added by `SpringSecurityModule`'s
`stompBroadcasts`, not here.

### Relies on / relied on by

Relies on [`CALL_PATHS`](features.md#call_paths), [`StreamFunctions`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/StreamFunctions.java#L42)
and [`ConfiguredValues`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ConfiguredValues.java#L37). Relied on by
[`SYSTEM_GRAPH`](features.md#system_graph), [`MESSAGE_LISTENERS`](features.md#message_listeners) (what a listener
receives) and [`FIELD_LINEAGE`](features.md#field_lineage) across messages.

### Tests

[`MessageListenerFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MessageListenerFixtureTests.java#L25)
(`sendsAreEgressToTheirTopics`, `producersLinkToTheListenersOfTheirTopics`; fixtures
[`messagingproducer`](../../src/fixtures/java/fixtures/messagingproducer/),
[`sendforms`](../../src/fixtures/java/fixtures/sendforms/)),
[`ConfiguredDestinationsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ConfiguredDestinationsFixtureTests.java#L21)
([`messageconfig`](../../src/fixtures/java/fixtures/messageconfig/)),
[`StreamFunctionFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/StreamFunctionFixtureTests.java#L26).

### Before changing it

- `KafkaHeaders.TOPIC` is a constant the compiler copies into the code, so the header is matched by its text,
  `kafka_topic`. `MessageSends.message` reads a builder chain from `build()` back, so the first `setHeader` it meets
  is the last one set.
- A `Message` send with no topic header goes to the template's default topic, as `MessagingMessageConverter#fromMessage`
  does. RabbitMQ's own `Message` holds bytes and is no payload.
- Destinations resolve only the placeholders a file sets (`resolveKnown`); the rest stay as written, on both sides.

## Infrastructure calls

Feature: [`INFRASTRUCTURE_CALLS`](features.md#infrastructure_calls). What a service calls off its request paths, on
the infrastructure it is configured with: its authorization server's keys, OpenID configuration, introspection and
token endpoints, its config server and Eureka. They link the service to those servers in the system graph.

### How it works

1. After the entry points, [`SpringSecurityModule.run`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L221)
   adds [`IdentityProviderCalls.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/IdentityProviderCalls.java#L60)'s
   and [`InfrastructureCalls.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/InfrastructureCalls.java#L35)'s
   Egress to the graph. No path has an edge to them.
2. `IdentityProviderCalls` (decisions 0049, 0073), when Boot's resource server auto-configuration is on the classpath:

   | Configured with | Egress |
   |---|---|
   | `spring.security.oauth2.resourceserver.jwt.jwk-set-uri` | `JwtDecoder GET` the JWK set |
   | else `jwt.issuer-uri` | `JwtDecoder GET <issuer>/.well-known/openid-configuration` |
   | `opaquetoken.introspection-uri` | `OpaqueTokenIntrospector POST` there, `STATIC` when `opaquetoken.client-id` is set |
   | Each `spring.security.oauth2.client.registration.*`'s provider ([`IdentityProviderCalls.clientCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/IdentityProviderCalls.java#L139)) | `OAuth2 client POST` its `token-uri`, `STATIC`; else `GET` its issuer's OpenID configuration |
   | Code: `NimbusJwtDecoder.withJwkSetUri("..")`, `JwtDecoders.fromIssuerLocation("..")`, an introspector's URI ([`IdentityProviderCalls.codeCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/IdentityProviderCalls.java#L95)) | The same, with a constant location |

3. `InfrastructureCalls` (decision 0058): a config client reads `GET <uri>/{name}/{profiles}`, the URI from
   `spring.config.import=configserver:..` ([`InfrastructureCalls.configServer`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/InfrastructureCalls.java#L67))
   or `spring.cloud.config.uri`, `STATIC` with `spring.cloud.config.username`. A Eureka client with a
   `defaultZone` registers (`POST <zone>/apps/{app}`), renews (`PUT <zone>/apps/{app}/{id}`) and fetches
   (`GET <zone>/apps/`), as `register-with-eureka` and `fetch-registry` allow.
4. Both build their Egress with [`AbsoluteUrl.parse`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AbsoluteUrl.java#L24)
   and [`AbsoluteUrl.call`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AbsoluteUrl.java#L47): the site is the
   library class, the credentials `NONE` unless set above. A URL with an unresolved placeholder isn't a URL, so it
   adds nothing.

### Relies on / relied on by

Relies on the service's properties only. Relied on by [`SYSTEM_GRAPH`](features.md#system_graph) (links to a scanned
authorization, config or Eureka server's [`LIBRARY_ENDPOINTS`](features.md#library_endpoints)),
[`Linker.issuing`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L466), which finds the authorization server
that issues a registration's token by its `OAuth2 client` Egress ([`FINDING_TOKEN_REJECTED`](features.md#finding_token_rejected)),
and `Linker.issuers`, which finds the servers whose keys each `JwtDecoder` fetches
([`FINDING_ALWAYS_DENIED`](features.md#finding_always_denied)). [`Linker.credentialFindings`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L252)
skips these calls, as they act for no caller.

### Tests

[`AuthorizationServerFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AuthorizationServerFixtureTests.java#L25)
([`jwkset`](../../src/fixtures/java/fixtures/jwkset/), [`introspection`](../../src/fixtures/java/fixtures/introspection/),
[`oauthclient`](../../src/fixtures/java/fixtures/oauthclient/)),
[`JwtValidationFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/JwtValidationFixtureTests.java#L15)
(decoders built in code), [`InfrastructureCallsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/InfrastructureCallsFixtureTests.java#L21)
([`cloudclient`](../../src/fixtures/java/fixtures/cloudclient/) and its variants),
[`AbsoluteUrlTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AbsoluteUrlTests.java#L7).

### Before changing it

- Each property-based call applies only when the library that makes it is on the classpath
  (`OAuth2ResourceServerAutoConfiguration`, `ClientRegistration`, `ConfigServerConfigDataLoader`,
  `EurekaClientAutoConfiguration`): properties alone call nothing. The calls built in code need no auto-configuration. A JWK set URI wins over the issuer, as Boot's `JwtDecoderConfiguration` does.
- A client registration's `jwkSetUri` in code is for its ID tokens, not a resource server's.
- `Linker.issuing` compares `baseUrl + uriTemplate` of the `OAuth2 client` Egress with the registration's token URI:
  keep the client name and the split.
- A host with an underscore (`config_server`) is no host to `java.net.URI`; `AbsoluteUrl.parse` reads it from the
  authority.

## Call credentials

Feature: [`CALL_CREDENTIALS`](features.md#call_credentials). What each call authenticates with, which decides whose
checks the called service makes (decision 0021): a relayed token is checked as the caller, anything else as the
calling service, so only a relayed call's downstream checks count toward what the caller's own callers need.

| [`Credentials`](../../scanner/src/main/java/dev/crain/authtracer/graph/Credentials.java#L11) | Meaning | Typical source |
|---|---|---|
| `RELAY` | The caller's token, forwarded | `ServletBearerExchangeFilterFunction`, an interceptor reading the security context, an OAuth2 registration with a user grant |
| `OAUTH2_CLIENT` | The service's own OAuth2 client token | `OAuth2ClientHttpRequestInterceptor` with a registration, an authorized-client manager |
| `STATIC` | Fixed credentials | `BasicAuthenticationInterceptor`, a constant or configured `Authorization` header |
| `NONE` | Nothing AuthTracer can see | A plain client |
| `UNKNOWN` | Something sets credentials it can't read | A library interceptor it doesn't know, a header value it can't follow |

### How it works

1. Each reader asks [`EgressCredentials`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L69)
   for the client the call is made on: [`forClient`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L276)
   for RestClient, WebClient and RestTemplate (via [`HttpClientEgress.clientOf`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L277)),
   [`forFeign`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L609),
   [`forHttpInterface`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L683),
   [`forStub`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L977) for gRPC, and
   [`forClass`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L544) when the client's build
   isn't seen. `rsocket` reads its own: `UsernamePasswordMetadata` is `STATIC`, `BearerTokenMetadata` `UNKNOWN`.
2. **Where the client is built** (decision 0083): [`EgressCredentials.builds`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L291)
   follows the client to each assignment of its field, or its chain in the method, and
   [`EgressCredentials.build`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L319) to where
   the chain starts. [`EgressCredentials.forBuild`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L437)
   then reads: for a static factory (`RestClient.create`, `new RestTemplate()`), that method only; for Boot's builder,
   also the application's builder beans, else Boot's customizers; for an injected client,
   [`EgressCredentials.injected`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L459): the
   bean its field is named after, else all beans of that type, `UNKNOWN` when they differ. A method that builds
   several clients gives each only its own statements ([`EgressCredentials.isolated`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L366)).
3. **What the code sends.** [`EgressCredentials.resolve`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L871)
   scans the methods ([`EgressCredentials.scan`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L889)):
   known interceptors and filters by type (`KNOWN`), application interceptors and lambdas by their code
   ([`EgressCredentials.classify`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L1120)), and
   OAuth2 defaults ([`EgressCredentials.defaultRegistration`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L1049)).
   Code that sets `Authorization` and reads an authorized-client manager is `OAUTH2_CLIENT`, the security context or
   the incoming header `RELAY`; otherwise [`EgressCredentials.trace`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L1272)
   follows the value back through locals, fields, parameters, lambdas and Reactor pipelines (decision 0083 amended),
   to a fixed value (`STATIC`), the caller's token, an authorized client's, or the place it stopped (`UNKNOWN`, which
   `credentialsVia` names). Spring gRPC's bearer interceptor gets the same treatment
   ([`EgressCredentials.grpcBearer`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L948)).
4. [`EgressCredentials.strongest`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L519)
   picks among what was found: `RELAY`, then `OAUTH2_CLIENT`, `STATIC`, `UNKNOWN`, else `NONE`.
5. **Per-request OAuth2.** Spring Security's OAuth2 interceptor and filter functions add a token only to a request
   that names its registration (7.1.1). [`HttpClientEgress.withCredentials`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L237)
   looks in the calling method for `clientRegistrationId("x")` ([`EgressCredentials.registrationIn`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L824))
   or `oauth2AuthorizedClient(..)` ([`EgressCredentials.authorizedClientIn`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L839));
   an HTTP interface uses `@ClientRegistrationId`. With none, the call has what the client sends otherwise
   ([`Found.unnamed`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L101)).
6. **Which registration.** [`EgressCredentials.forRegistration`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L764)
   makes a user grant (authorization code, token exchange, JWT bearer, device code) `RELAY`, a client credentials
   grant `OAUTH2_CLIENT` and a password grant, which Spring Security 7.1.1 no longer has, `UNKNOWN`. A registration
   that names no grant (`grant`) is an authorization code one when Boot builds it from its provider's issuer or a
   `CommonOAuth2Provider` (google, github, facebook, x, okta). [`EgressCredentials.registration`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L800)
   puts the registration's client id, grant, scopes and provider on the Egress
   ([`Registration`](../../scanner/src/main/java/dev/crain/authtracer/graph/Registration.java#L23), decision 0075 amended).
7. In `onCallSite`, a call made on another thread has no token to relay: `RELAY` becomes `NONE`.
8. The linker judges each link: [`Linker.credentialFindings`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L252)
   reports a non-relayed call to a checked endpoint (`BYPASSED`, or `OPAQUE_CONFIG` for `NONE` and `UNKNOWN`);
   [`Linker.audienceFindings`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L299) a relayed token the callee may
   reject for its audience; [`Linker.clientTokenFindings`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L403)
   a service's own token that the issuer refuses or the callee's checks deny (`TOKEN_REJECTED`).
   [`Credentials.callerChecked`](../../scanner/src/main/java/dev/crain/authtracer/graph/Credentials.java#L38) decides whether
   [`Exposures`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L40) and
   [`Policies`](../../src/main/java/dev/crain/authtracer/diff/Policies.java#L51) count downstream checks.

### The clients an authorization server issues tokens to

When the service is an authorization server, [`SpringSecurityModule.authorizationServers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L747)
records [`RegisteredClients.read`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RegisteredClients.java#L96) as the
graph's [`Issuer`](../../scanner/src/main/java/dev/crain/authtracer/graph/Issuer.java#L24) (decision 0075): each client's id and
the scopes it can be granted, from `RegisteredClient` builders in the code
([`RegisteredClients.code`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RegisteredClients.java#L145)) or Boot's
`spring.security.oauth2.authorizationserver.client.*` when there's no repository bean
([`RegisteredClients.repository`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RegisteredClients.java#L106), which
reads the bean with [`BuiltValues.returnedBy`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/BuiltValues.java#L94)).
What could let a token carry other scopes goes into `unread`: a client store it can't read, a builder handed on,
clients registered at run time, a token customizer that writes `scope`, the application's own validators and
token endpoint providers ([`RegisteredClients.other`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RegisteredClients.java#L205)).
The linker judges a service's own token against the issuer's clients only when `unread` is empty.

### Relies on / relied on by

Relies on [`SERVICE_CALLS`](features.md#service_calls); the linker's judgments also read the callee's
[`AUTHORITY_SOURCE`](features.md#authority_source) (its JWT audiences and scope claims). Relied on by [`FINDING_TOKEN_REJECTED`](features.md#finding_token_rejected),
[`FINDING_BYPASSED`](features.md#finding_bypassed) (the linker's), [`EXPOSURES`](features.md#exposures),
[`POLICIES`](features.md#policies) and [`DIFF`](features.md#diff), which fails when a call stops relaying. The UI
labels each Egress with [`CREDENTIALS`](../../frontend/src/lib/format.ts#L123).

### Tests

- [`CredentialsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/CredentialsFixtureTests.java#L13)
  ([`relay`](../../src/fixtures/java/fixtures/relay/), [`credentialforms`](../../src/fixtures/java/fixtures/credentialforms/)
  and the other `credential*`/`relay*` fixtures),
  [`OwnClientsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/OwnClientsFixtureTests.java#L16)
  ([`ownclients`](../../src/fixtures/java/fixtures/ownclients/)),
  [`ClientBuildsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ClientBuildsFixtureTests.java#L17)
  ([`clientbuilds`](../../src/fixtures/java/fixtures/clientbuilds/), [`tokentrace`](../../src/fixtures/java/fixtures/tokentrace/)),
  [`ClientDefaultsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ClientDefaultsFixtureTests.java#L16)
  ([`clientdefaults`](../../src/fixtures/java/fixtures/clientdefaults/)).
- Per client: [`FeignFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FeignFixtureTests.java#L18)
  (`feignoauth2`), [`GrpcFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GrpcFixtureTests.java#L30)
  (`grpcrelay`, `grpctokens`), [`RSocketFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/RSocketFixtureTests.java#L26);
  threads: [`AsyncFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AsyncFixtureTests.java#L22)
  (`anAsyncCallHasNoTokenToRelay`).
- The issuer: [`RegisteredClientsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/RegisteredClientsFixtureTests.java#L15)
  ([`authserverclients`](../../src/fixtures/java/fixtures/authserverclients/)).
- Downstream: [`TokenLinkTests`](../../src/test/java/dev/crain/authtracer/link/TokenLinkTests.java#L24),
  [`ClientTokenLinkTests`](../../src/test/java/dev/crain/authtracer/link/ClientTokenLinkTests.java#L32),
  [`IssuerLinkTests`](../../src/test/java/dev/crain/authtracer/link/IssuerLinkTests.java#L29),
  [`CredentialsExposureTests`](../../src/test/java/dev/crain/authtracer/diff/CredentialsExposureTests.java#L31).

### Before changing it

- **The strength order is the safe one.** When code may send either of two, the one that makes the callee check the
  caller wins, and a per-request token keeps what the client sends without one (`Found.otherwise`).
- **Boot's customizers reach only its builders.** Boot 4.1.1 applies `RestClientCustomizer`s, `WebClientCustomizer`s
  and `RestTemplateCustomizer`s to its builder beans, and HTTP service groups get their group configurers too; a
  client from a static factory gets neither.
- **Spring picks a client bean by its field's name** when several match, so `injected` and `forClass` do too, and
  call it `UNKNOWN` ("one of several client beans") rather than guess.
- `resolve` sorts methods by signature so the same code always reports the same `credentialsVia`.
- A `null` `credentials` means a graph from before they were recorded, and `callerChecked` treats it as a relay.
  Message sends and SOAP calls have none.

## Files

| File | Role | Features |
|---|---|---|
| [`HttpClientEgress`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L77) | Recognises each client call and reads its method, URL, base URL and response type; hands on to the message and SOAP readers | `SERVICE_CALLS`, `MESSAGE_SENDS`, `CALL_CREDENTIALS`, `FIELD_LINEAGE`, `FINDING_OPAQUE_CONFIG`, `FINDING_OPAQUE_CALLPATH` |
| [`MessageSends`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSends.java#L31) | Kafka, JMS, RabbitMQ and StreamBridge sends, their destinations and payloads | `MESSAGE_SENDS`, `FIELD_LINEAGE` |
| [`SoapCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SoapCalls.java#L37) | `WebServiceTemplate` calls: the operation, namespace, action and endpoint | `SERVICE_CALLS` |
| [`UnreadCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/UnreadCalls.java#L34) | The `?` Egress and its `OPAQUE_CONFIG` finding | `FINDING_OPAQUE_CONFIG`, `SERVICE_CALLS`, `MESSAGE_SENDS` |
| [`EgressCredentials`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L69) | What a call authenticates with, from where its client is built | `CALL_CREDENTIALS`, `FINDING_TOKEN_REJECTED` |
| [`IdentityProviderCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/IdentityProviderCalls.java#L33) | A resource server's and OAuth2 client's calls to its authorization server | `INFRASTRUCTURE_CALLS`, `FINDING_ALWAYS_DENIED`, `FINDING_TOKEN_REJECTED` |
| [`InfrastructureCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/InfrastructureCalls.java#L24) | Config server and Eureka client calls | `INFRASTRUCTURE_CALLS` |
| [`AbsoluteUrl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AbsoluteUrl.java#L19) | A configured absolute URL split into base and path | `INFRASTRUCTURE_CALLS`, `SERVICE_CALLS` |
| [`RegisteredClients`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RegisteredClients.java#L53) | An authorization server's clients and their scopes, as the graph's `Issuer` | `FINDING_TOKEN_REJECTED`, `FINDING_ALWAYS_DENIED` |
| [`ConfiguredValues`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ConfiguredValues.java#L37) | The text a value holds when it comes from the configuration: `@Value`, `@ConfigurationProperties` with relaxed binding and defaults | `SERVICE_CALLS`, `MESSAGE_SENDS`, `GATEWAY_ROUTES`, `CALL_CREDENTIALS` |
| [`BuiltValues`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/BuiltValues.java#L40) | What an object handed to Spring is built from: created, returned by a library call, or unread (decision 0074) | `AUTHORITY_SOURCE`, `FINDING_TOKEN_REJECTED`, `FINDING_ALWAYS_DENIED` |
| [`GraphQlDocuments`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlDocuments.java#L16) | Just enough of a GraphQL document to name its operation and root fields | `SERVICE_CALLS`, `GRAPHQL_OPERATIONS` |
