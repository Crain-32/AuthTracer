# Request rules

This page covers how a service's security configuration becomes the first checks on each entry point's path: the
filter chain's rules on HTTP requests, and the rules Spring Security applies to gRPC calls, STOMP messages and RSocket
exchanges. It follows the order a scan meets them: the HTTP rules (where the configuration is read from, how matchers
are modelled, which chain and which rule take a request, `ignoring()`, dispatcher types, the default chains, the XML
namespace), then the protocol rules, then SOAP and WS-Security, then the findings these classes raise.

Where the rules land on a path, after Provided requirements and around the request's filters, is the subject of
[call-paths.md](call-paths.md) (`SpringSecurityModule`'s `EntryRules`). What a requirement such as `hasRole("ADMIN")`
becomes is the subject of [requirements.md](requirements.md). The classes here are all in
`scanner/src/main/java/dev/crain/authtracer/scan/spring/`. The library versions their comments name (Spring Security 7.1.1,
Spring Boot 4.1.1, Spring gRPC 1.1.1, Spring WS 5.0.2) are the ones whose bytecode was read with `javap`.

## HTTP request rules

Feature: [`REQUEST_RULES`](features.md#request_rules)

Every HTTP Ingress gets one request-level Authorization Location: the rule of the `SecurityFilterChain` (or
`SecurityWebFilterChain`) that takes the request, the first of that chain's rules that matches, or the chain's
default. When the scan can't tell which chain or rule matches first, the Location is a Split that asks for the weakest
of the candidates, and a finding says why. In the graph it is a `location` node with `scope` `HTTP_REQUEST`, a
`mechanism` such as `authorizeHttpRequests`, `authorizeExchange` or `intercept-url`, and a `routePattern` that writes
the matcher as the configuration does.

### How it works

1. [`SpringSecurityModule.Scan`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L86)
   loads the XML namespace configuration, decides servlet or reactive with
   [`WebStack.reactive`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/WebStack.java#L57), and builds one
   [`HttpSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L51) with the role
   prefix the request rules' factory uses, the gRPC services served through the servlet container, and the XML. Steps
   2 to 8 run in its constructor, once per scan.
2. [`HttpSecurityRules.requestMatcherBasePath`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1273)
   reads the `basePath` of a unique `PathPatternRequestMatcher.Builder` bean. Without one, on a Boot servlet
   application, Boot's own builder's base path is `spring.mvc.servlet.path`. Every `String` pattern of the DSL gets
   this prefix.
3. [`SecurityDsl.defaultDsls`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L743) (servlet only)
   reads the `AbstractHttpConfigurer`s listed in a `META-INF/spring.factories`, in the application's resources and in
   every library jar. Spring applies them to every `HttpSecurity` before anything else.
4. [`HttpSecurityRules.readCustomizers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1222)
   reads the `Customizer<HttpSecurity>` (and `ThrowingCustomizer`) beans, then the
   `Customizer<AuthorizationManagerRequestMatcherRegistry>` beans, each in `@Order`, through `lambdaBeans`. On WebFlux
   the types are `ServerHttpSecurity` and `AuthorizeExchangeSpec`. What they configure is kept for every chain.
5. [`HttpSecurityRules.readKotlinDslBeans`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1202)
   reads the Kotlin DSL's beans (`HttpSecurityDsl.() -> Unit`, then `AuthorizeHttpRequestsDsl.() -> Unit`) and hands
   their rules to [`SecurityDsl.startKotlinChainsWith`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L590):
   every chain written with `http { }` starts with them.
6. Each bean method that returns a chain or a `WebSecurityCustomizer`
   ([`SpringBeans.beanMethodsOf`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringBeans.java#L142)) is read by
   [`HttpSecurityRules.chain`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1428) or
   [`HttpSecurityRules.ignoring`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1308), both
   through `SecurityDsl` (next section).
7. [`HttpSecurityRules.xmlChains`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L689) adds
   each `<http>` of the XML (servlet only).
8. The chains are sorted by `@Order`. The sort is stable, so XML chains, which have the lowest precedence, stay after
   Java chains without an `@Order`.
9. For each Ingress, `SpringSecurityModule.EntryRules` asks
   [`HttpSecurityRules.locationFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L792) for
   its check and puts it on the path ([call-paths.md](call-paths.md)).
   [`RequestFilters.around`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestFilters.java#L291) is given
   [`HttpSecurityRules.chainsFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L906): the
   chains whose filters the request passes.

### Reading the configuration: `SecurityDsl`

[`SecurityDsl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L68) reads a configuration method's
bytecode statement by statement. Each local holds a `DslValue` that says what it stands for: the `HttpSecurity`
(`Http`), the rule registry (`Registry`), a rule being written (`AuthorizedUrl`), a matcher (`MatcherValue`), a manager
(`Manager`), a lambda (`Lambda`). A call is read by the value it is made on, so Java, Kotlin and Groovy, which compile
the DSL differently, read the same. What it finds goes into a
[`SecurityDsl.Interpretation`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L490): the chain's
`securityMatcher`, its rules in order, `ignoring()` matchers, login and logout configurers, rules custom DSLs add, and
what it couldn't read (`Unread` rules and `Note`s).

1. [`SecurityDsl.chain`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L599) binds the bean
   method's parameters (the `HttpSecurity`, a `PathPatternRequestMatcher.Builder`, a
   `WebExpressionAuthorizationManager.Builder`, an `AuthorizationManager` bean found by name or type) and calls
   `interpret`, which gives each right-hand side a value with `evaluate` and reads each call in `instanceCall`:
   - On `Http`: `securityMatcher(..)` replaces the chain's matcher; `securityMatchers(..)` takes the OR of everything
     it configures; `authorizeHttpRequests(lambda)` (or `authorizeExchange`) reads the lambda with a `Registry`;
     `with(configurer)` reads a custom DSL; `formLogin` and `logout` record their URLs; `csrf(..)` records whether it
     is turned off; `objectPostProcessor(..)` reads a post-processor.
   - On `Registry`: `requestMatchers`, `pathMatchers`, `matchers`, `anyRequest`, `anyExchange` and
     `dispatcherTypeMatchers` start an `AuthorizedUrl`; the call on it (`hasRole`, `permitAll`, `access(..)`, after
     an optional `not()`) adds a `Rule` with its line.
2. [`SecurityDsl.requirement`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L1713) gives the rule's
   requirement: [`BuiltInManagers.named`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/BuiltInManagers.java#L123)
   for the built-in names, with the DSL's role prefix, or `access(..)` for a manager. A manager is one of Spring
   Security's static factories (`BuiltInManagers.factory`), a `WebExpressionAuthorizationManager` parsed by
   [`SpelRequirements.parse`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpelRequirements.java#L114) with `ROLE_`,
   or the application's own, read by `customManager` and `injectedManager` through `DecisionCode` (decision 0064).
   A `ConditionalAuthorizationManager` is the OR of its branches (`conditional`, decision 0018); the multi-factor
   builders add the factors they require (`multiFactor`, `factorsCall`, decision 0037).
3. Lambdas: [`SecurityDsl.interpretLambda`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L1440)
   reads the body with its captured values bound, and its last parameter bound to the receiver. A Groovy closure is a
   class extending `Closure`, read through its `doCall` (`SecurityDsl.closure`); a dynamic Groovy call
   ([`GroovyCalls.of`](../../scanner/src/main/java/dev/crain/authtracer/scan/GroovyCalls.java#L92)) is read in `groovyCall`, which
   gathers varargs into one array as Java passes them.
4. Kotlin: `http { }` compiles to `HttpSecurityDslKt.invoke(http, lambda)`. The Kotlin DSL beans' rules go first, then
   the lambda's. `authorize(..)` and `authorize$default` (arguments left out, read from the mask) go to
   [`SecurityDsl.kotlinRule`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L1410); `permitAll`,
   `authenticated` and the rest are property getters (`getPermitAll`). A `servletPath` argument replaces the builder's
   base path.
5. Helpers: [`SecurityDsl.helper`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L1460) spots a call
   to an application method that takes the `HttpSecurity` or a registry, or returns a `Customizer`; `follow` reads it
   with its arguments bound, up to three deep. A helper it can't read (abstract, too deep, recursive) that takes the
   `HttpSecurity`, and `authorizeHttpRequests(..)` given a customizer from a field or a bean, become `unreadRules`: one
   opaque rule for every request.
6. Custom DSLs: [`SecurityDsl.customDsl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L701) reads
   an application `AbstractHttpConfigurer`'s `init(HttpSecurity)` and `configure(HttpSecurity)`. Their rules are
   `deferred`: Spring adds them when the chain is built, after the chain's own. A library's configurer is a `Note`,
   except the authorization server's (read under decision 0049) and Boot gRPC's CSRF configurer, which adds no rules.
7. Post-processors: [`SecurityDsl.postProcessor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L1541)
   reads an application `ObjectPostProcessor<AuthorizationFilter>` that only sets dispatch flags
   (`setFilterErrorDispatch(false)` leaves error dispatches unchecked). Any other is a `Note`: it may replace the
   filter or the manager.
8. Back in [`HttpSecurityRules.chain`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1428), a
   chain's rules are put in the order Spring builds them:

| Order | Rules | From |
|---|---|---|
| 1 | The login and logout URLs a `permitAll()` opens (`PermitAllSupport`) | [`SecurityDsl.permitted`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L397), over the spring.factories DSLs, the customizer beans, then the chain |
| 2 | Customizer beans' rules, each bean in `@Order` | `readCustomizers` |
| 3 | The chain's own rules; in a Kotlin `http { }`, the Kotlin DSL beans' first | `SecurityDsl.chain` |
| 4 | Custom DSLs' rules: spring.factories ones, customizers', then the chain's `with(..)` | `Interpretation.deferred` |

The chain's `securityMatcher` is its own, else the last customizer's. A chain authorizes requests when it, a
customizer or a spring.factories DSL calls `authorizeHttpRequests`.

### Matchers

A rule's matcher is a [`HttpSecurityRules.Matcher`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L101):
parts that match when any of them does, and a `custom` text for parts the scan can't evaluate. Each
[`Matcher.Part`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L285) reads the request in one
[`Matcher.Syntax`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L259):

| Syntax | Written as | Matches |
|---|---|---|
| `PATH` | `requestMatchers("/a/**")`, `pathMatchers`, `PathPatternRequestMatcher`, Boot's `PathRequest` and `EndpointRequest`, `GrpcRequest.toAnyService()`, an XML `pattern` | A `PathPattern` on the route, its variables filled with sample values |
| `REGEX` | `RegexRequestMatcher`, XML `request-matcher="regex"` | The regex on the route and its query string |
| `EXACT` | The login and logout URLs (decision 0093) | The URI and query string, exactly |
| `DISPATCH` | `dispatcherTypeMatchers(..)`, `new DispatcherTypeRequestMatcher(..)` | The request's dispatch, not its path |
| `TESTS` | A `RequestMatcher` lambda that `MatcherLambdas` could read | Each alternative's tests, all of which must hold |
| `GRPC` | Spring gRPC's `methods(..)` and `allRequests()` | `*` wildcards on the full method name |

- [`Matcher.matches`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L318) says the matcher
  surely matches a route. [`Matcher.mayMatch`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L119)
  says it may match without surely matching: a custom part in `Matcher.UNKNOWN` (a lambda the scan couldn't read, a
  pattern that isn't a constant), or a lambda's test whose truth is `MAYBE`.
- [`Matcher.callerDecides`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L134) singles out
  the second kind when what decides is the caller's to send: a header, a parameter, how it writes the raw URI
  (`Matcher.Test.choice`), the query string of an exact URL.
- [`Matcher.within`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L439) finds a narrower path
  rule under a route that is itself a pattern (`/api/public/**` under `/api/**`): it takes part of the route's requests.
- [`Matcher.describe`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L227) writes the matcher
  as the DSL does (`GET /a,/b`, `regex ^/x$`, `anyRequest`). It is the location's `routePattern` and part of its id.

[`MatcherLambdas.read`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MatcherLambdas.java#L130) reads a
`RequestMatcher` lambda, a method reference to a predicate such as `CorsUtils::isPreFlightRequest`, or a matcher bean's
`matches` method. It runs the method's control flow graph symbolically (`MatcherLambdas.evaluate`), knowing the
request's `getServletPath`, `getRequestURI`, `getMethod`, `getHeader` and `getParameter`, constants, the comparisons
`equals`, `equalsIgnoreCase`, `startsWith` and `HttpMethod.matches`, and predicates it calls with the request, three
deep. Which side the request is on matters: `"/admin/reports".startsWith(path)` asks whether the path is a start of
the constant (`PATH_START_OF`), and `path.equalsIgnoreCase("/ops")` matches `/OPS` too (`PATH_IGNORING_CASE`). Each way to `return true` becomes an alternative. It reads the servlet path only for a DispatcherServlet on `/`,
and the raw URI only without a context path. Anything else (the caller's address, a bean, a field), more than 400 steps
or more than 16 alternatives leave the lambda unread, and the DSL makes it a custom part that may match.

### Which chain, which rule

[`HttpSecurityRules.locationFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L792) matches
the Ingress's method and its path without the context path: the DispatcherServlet's path and the route, or the route
alone for a servlet of its own.

1. `ignoring()` comes first (next section).
2. [`HttpSecurityRules.checkedLocation`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L833)
   goes through the chains in order. A chain covers the request when it has no `securityMatcher` or its matcher
   matches; it may cover it when its matcher may match. The first covering chain decides. Chains before it that may
   cover the request are alternatives
   ([`HttpSecurityRules.mayCoverFirst`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1024),
   decision 0027): a Split, "a securityMatcher may match first", asks for the weakest of their checks and the covering
   chain's, or `permitAll` ("no SecurityFilterChain covers the request") when none covers it. A request that no chain
   covers or may cover gets no request rule, as Spring Security never sees it. Decision 0111: a chain whose bean may
   not be made ([`BeanConditions`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/BeanConditions.java#L47):
   a `@Profile` the configuration doesn't activate, a condition it leaves open, a configuration outside the component
   scan) never covers a request, only may; when every chain is such a one, the default chain (`withoutChains`) is
   the covering alternative.
3. [`HttpSecurityRules.chainLocation`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L935): a
   chain that doesn't authorize requests gives no check, or, as an alternative, `permitAll` ("the chain authorizes no
   request").
4. [`HttpSecurityRules.dispatchLocation`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L978)
   goes through the chain's rules in order and the first whose matcher matches decides. Rules before it that may match,
   and narrower rules `within` a route that is a pattern, are alternatives:
   [`HttpSecurityRules.maybeFirst`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1059) makes
   a Split asking for the OR of their requirements, and reports each one it can't evaluate (OPAQUE_CONFIG) or whose
   test the caller decides (BYPASSED), once per rule. A rule for one method on a mapping for any method is a known
   alternative, without a finding. A route with path variables (`/reports/{type}`) is one too: a rule whose own
   paths it takes (`/reports/public-*`, `Matcher.sample` and `overlaps`) is an alternative, unless a more specific
   mapping of the application answers those paths (`elsewhere`, from the mappings `handled` gives it: `/users/me`
   beside `/users/{id}`).
5. When no rule matches, the location is "no rule matched: denied by default" (`denyAll`, as Spring Security 7's
   `RequestMatcherDelegatingAuthorizationManager` and `DelegatingReactiveAuthorizationManager` deny), or "let through"
   for an XML chain with the legacy `FilterSecurityInterceptor` (decision 0097).
6. [`HttpSecurityRules.queryBypass`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1117)
   checks the rule that matched: a regex without a trailing `.*` stops matching once the request has a query string,
   and the request falls to a later rule. When that rule, or the default, asks for something else, a BYPASSED finding
   says so.

A rule's location id is `location:HTTP_REQUEST:<declaring method>:<index>:<pattern>`, with the target at the rule's
line; a customizer bean's rule is declared in the customizer bean method. Splits are registered with
[`GraphBuilder.split`](../../scanner/src/main/java/dev/crain/authtracer/scan/GraphBuilder.java#L76), so
[`SpringSecurityModule.rebuildSplits`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1078)
recomputes their requirement after the role hierarchy has widened their parts.

[`HttpSecurityRules.hierarchyAware`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1146) tells
[`SpringSecurityModule.hierarchiesAndFactories`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L807)
which rules a RoleHierarchy widens. It doesn't widen a manager from Spring Security's static factories that wasn't
given `setRoleHierarchy` (decision 0063), a `new WebExpressionAuthorizationManager(..)`, an XML chain's configuration
attributes or `authorization-manager-ref`, or anything on WebFlux.

### `ignoring()`

1. [`HttpSecurityRules.ignoring`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1308) reads a
   `WebSecurityCustomizer` bean's lambda with a `Web` receiver: each `ignoring().requestMatchers(..)` is an `Ignored`
   matcher. An XML `<http pattern=".." security="none">` is one too.
2. In `locationFor`, the first `Ignored` that surely matches decides before any chain, as `WebSecurity#performBuild`
   puts its empty chains first.
   [`HttpSecurityRules.ignoredLocation`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1183)
   records `permitAll`, mechanism "WebSecurityCustomizer ignoring() (skips the filter chain)", and a BYPASSED finding
   per request: no filter runs at all, so there is no authentication, CSRF protection or SecurityContext either.
3. An `Ignored` that may match (decision 0051) is an alternative to the chains' check:
   [`HttpSecurityRules.mayIgnoreFirst`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L814)
   makes a Split, "may match first and skip the filter chain". One the scan can't evaluate, or whose test the caller
   decides, is reported as BYPASSED when it is read.
4. `chainsFor` gives `RequestFilters` no chains for an ignored request.

### Dispatcher types and the error page

A `DISPATCH` part matches the request's dispatch, not its path. A request's own dispatch is `REQUEST`, so
`dispatcherTypeMatchers(DispatcherType.REQUEST)` matches every request ahead of the rules after it, while `FORWARD`,
`INCLUDE`, `ASYNC` and `ERROR` rules never take a request's own dispatch.

Boot's error page is the exception
([`HttpSecurityRules.errorPage`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L967)). On a
servlet application with auto-configuration, the route at `spring.web.error.path` (default `/error`) is also reached by
the `ERROR` dispatch of any request that fails, one Spring Security denies included. `chainLocation` checks it under
both dispatches and makes a Split when they ask for different things. When a post-processor has set
`setFilterErrorDispatch(false)`, the error dispatch is not checked at all.

### Default chains

When the application declares no chain, `checkedLocation` uses
[`HttpSecurityRules.bootDefault`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1364):

| Application | Check | Location id |
|---|---|---|
| Servlet, auto-configured, Boot's security module present | `anyRequest().authenticated()` | `location:HTTP_REQUEST:spring-boot-default:anyRequest` |
| Servlet, `@EnableWebSecurity` without Boot | The same, from Spring Security's own chain | `location:HTTP_REQUEST:spring-security-default:anyRequest` |
| WebFlux, `@EnableWebFluxSecurity` or Boot's reactive security | `anyExchange().authenticated()` | `location:HTTP_REQUEST:webflux-default:anyExchange` |

Customizer beans' rules come before the default chain's, as they do before any chain's. With Actuator and its health
endpoint exposed, [`HttpSecurityRules.bootHealth`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1337)
lets everyone reach it first, as Boot's `ManagementWebSecurityAutoConfiguration` does (decision 0041). In any other
application without a chain, there is no request rule at all.

### The XML namespace

1. [`SecurityXml.load`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityXml.java#L185) walks the resource
   directories (six levels deep) for `.xml` files and parses those that use the security or beans namespace, with SAX,
   namespace-aware and with DOCTYPEs refused. A security file that doesn't parse goes on `Config.unread`, which
   `SpringSecurityModule` reports as OPAQUE_CONFIG (decision 0036, decision 0097).
2. Its [`SecurityXml.Handler`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityXml.java#L308) keeps each
   `<http>` as a [`SecurityXml.Http`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityXml.java#L71): its
   `pattern` (regex with `request-matcher="regex"`), `security="none"`, `request-matcher-ref`,
   `authorization-manager-ref`, `use-authorization-manager`, `use-expressions`, and its `<intercept-url>`s in document
   order. An `<intercept-url>` without `access` asks for `authenticated`; `filters="none"` is `permitAll`. The same
   pass keeps what other features need: `<method-security>` and its pointcuts, `<intercept-methods>`, the login
   elements, the beans and their ids, a JSP view resolver, and the WebSocket brokers.
3. [`HttpSecurityRules.xmlChains`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L689) makes
   each `<http>` a chain, keyed `<file>#http@<line>` so two chains in one file are told apart. `access` is SpEL, or,
   with `use-expressions="false"`, configuration attributes as the default voters read them
   ([`XmlReferences.attributes`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/XmlReferences.java#L156)). A chain
   with an `authorization-manager-ref` has one rule for every request: the manager decides, and its `<intercept-url>`s
   aren't read.
4. [`XmlReferences.requestMatcher`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/XmlReferences.java#L56) resolves
   a `request-matcher-ref`: a `RegexRequestMatcher` bean with constant constructor arguments, or the application's
   `RequestMatcher` class, component or `@Bean` lambda, read by `MatcherLambdas`; otherwise a matcher that may match
   anything. [`XmlReferences.manager`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/XmlReferences.java#L82) reads
   an application `AuthorizationManager` through
   [`DecisionCode.namedManager`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L310).

### Relies on / relied on by

- Relies on [`REQUIREMENTS`](features.md#requirements) for what a rule asks (`SpelRequirements`, `BuiltInManagers`,
  `MultiFactor`) and on [`CUSTOM_DECISIONS`](features.md#custom_decisions) for managers the application writes
  (`DecisionCode`). It also uses `SpringBeans` for bean methods, `ActuatorEndpoints` for `EndpointRequest`,
  `GrpcServices` for `GrpcRequest`, and `GroovyCalls` for dynamic Groovy.
- Relied on by [`CALL_PATHS`](features.md#call_paths): `SpringSecurityModule.EntryRules` places the check, and
  `RequestFilters` takes `chainsFor`. `RequestFilters` (interceptor patterns) and the module's Provided requirements
  match URLs with `Matcher.paths` too.
- Relied on by [`VIEW_FIELDS`](features.md#view_fields):
  [`ViewFields`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewFields.java#L45) asks `locationFor` what a
  view's URL guard asks (decision 0081).
- [`ResourceServerMetadata.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ResourceServerMetadata.java#L57)
  asks `chainsFor` whether a chain takes the metadata endpoint;
  [`AnonymousAuthentication.apply`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AnonymousAuthentication.java#L140)
  meets each rule with the anonymous token; `SensitiveEndpoints` reads the checks on a library endpoint's path for
  [`FINDING_OPEN_SENSITIVE_ENDPOINT`](features.md#finding_open_sensitive_endpoint).

### Tests

| Test | Fixtures | Covers |
|---|---|---|
| [`WebFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/WebFixtureTests.java#L17) | [`web`](../../src/fixtures/java/fixtures/web/), `defaultchain`, `loginpage`, `customdsl` | First match, method matchers, `securityMatcher`, default denial, `ignoring()`, conditional managers, custom DSLs, Spring Security's own default chain |
| [`MatchersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MatchersFixtureTests.java#L13), [`ServletBasePathsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ServletBasePathsFixtureTests.java#L17) | [`matchers`](../../src/fixtures/java/fixtures/matchers/), `basepath`, `servletpath`, `servletbasepaths` | Regex rules and the query string, static resources, built matchers, `securityMatchers`, base paths and the servlet path |
| [`CustomizersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/CustomizersFixtureTests.java#L12), [`CustomizerFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/CustomizerFormsFixtureTests.java#L17) | [`customizers`](../../src/fixtures/java/fixtures/customizers/), `customizerboot`, `customizerforms` | Customizer rules first, in `@Order`, on Boot's default chain too |
| [`DslFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DslFormsFixtureTests.java#L17), [`DslHelpersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DslHelpersFixtureTests.java#L22), [`DslUnreadFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DslUnreadFixtureTests.java#L15) | `dslforms`, [`dslhelpers`](../../src/fixtures/java/fixtures/dslhelpers/), `dslunread` | The DSL's other forms, helper methods, rules it can't read |
| [`LoginUrlsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/LoginUrlsFixtureTests.java#L15), [`PostProcessorsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/PostProcessorsFixtureTests.java#L18) | [`loginurls`](../../src/fixtures/java/fixtures/loginurls/), `postprocessors` | `PermitAllSupport`'s URLs; post-processors |
| [`LibraryDslFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/LibraryDslFixtureTests.java#L18), [`LibraryFactoriesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/LibraryFactoriesFixtureTests.java#L24) | `librarydsl`, jars the test writes | Library configurers, spring.factories in jars |
| [`MatcherLambdasFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MatcherLambdasFixtureTests.java#L22), [`MatcherLambdaFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MatcherLambdaFormsFixtureTests.java#L19), [`MatcherFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MatcherFormsFixtureTests.java#L19), [`MatcherTestsTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MatcherTestsTests.java#L15) | [`matcherlambdas`](../../src/fixtures/java/fixtures/matcherlambdas/), `matcherlambdaforms`, `matcherlambdapaths`, `matcherforms` | Reading lambdas; the truth of each `Matcher.Test` |
| [`DynamicMatchersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DynamicMatchersFixtureTests.java#L16), [`DynamicPatternsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DynamicPatternsFixtureTests.java#L17), [`AnyMethodFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AnyMethodFixtureTests.java#L18) | `dynamicmatchers`, `dynamicpatterns`, `anymethod` | Matchers that may match first, and the Splits they make |
| [`IgnoringFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/IgnoringFormsFixtureTests.java#L19) | [`ignoringforms`](../../src/fixtures/java/fixtures/ignoringforms/), `ignoringunread` | `ignoring()` in its forms |
| [`DispatchTypesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DispatchTypesFixtureTests.java#L19) | [`dispatchtypes`](../../src/fixtures/java/fixtures/dispatchtypes/), [`errorpage`](../../src/fixtures/java/fixtures/errorpage/) | Dispatcher types and the error dispatch |
| [`KotlinFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/KotlinFixtureTests.java#L23), [`KotlinFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/KotlinFormsFixtureTests.java#L15) | [`kotlindsl`](../../src/fixtures/kotlin/fixtures/kotlindsl/), `kotlinreactive`, `kotlinforms` | The Kotlin DSL and its beans |
| [`GroovyFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GroovyFixtureTests.java#L22), [`GroovyFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GroovyFormsFixtureTests.java#L17) | [`groovydsl`](../../src/fixtures/groovy/fixtures/groovydsl/), `groovyforms` | Closures and dynamic calls |
| [`WebFluxFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/WebFluxFixtureTests.java#L13), [`WebFluxFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/WebFluxFormsFixtureTests.java#L15) | [`webflux`](../../src/fixtures/java/fixtures/webflux/), `webfluxdefault`, `webfluxforms` | `authorizeExchange`, WebFlux's default chain, no hierarchy |
| [`ActuatorFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ActuatorFixtureTests.java#L18) | `actuator`, `actuatordefault` and others | `EndpointRequest` matchers; Boot's chain opening health |
| [`ManagerBeansFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ManagerBeansFixtureTests.java#L16), [`CustomManagersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/CustomManagersFixtureTests.java#L19) | `managerbeans`, `custommanagers` | Managers handed to the chain, or written by the application |
| [`XmlConfigFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/XmlConfigFixtureTests.java#L17), [`XmlFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/XmlFormsFixtureTests.java#L16), [`XmlMatchersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/XmlMatchersFixtureTests.java#L18) | [`xmlconfig`](../../src/fixtures/resources/xmlconfig/), `xmlforms`, [`xmlmatchers`](../../src/fixtures/resources/xmlmatchers/) | `<http>` chains, `security="none"`, bean references, the legacy interceptor |
| [`SecurityXmlTests`](../../src/test/java/dev/crain/authtracer/scan/spring/SecurityXmlTests.java#L15), [`XmlReferencesTests`](../../src/test/java/dev/crain/authtracer/scan/spring/XmlReferencesTests.java#L14) | Files the tests write | The parser, and configuration attributes as the voters read them |

The example services' golden graphs (`src/integrationTest/resources/golden/`, checked by `ExampleServicesScanTests`)
hold their real chains' rules.

### Before changing it

- **Order is the semantics.** The first matching rule decides, in the order Spring builds them: login URLs, customizer
  beans in `@Order`, the chain's own, custom DSLs. Chains go in `@Order`, XML ones after Java ones. A request no rule
  matches is denied, except under an XML chain's legacy `FilterSecurityInterceptor`.
- **Unknown means "may match first".** A matcher the scan can't evaluate is never treated as matching or as not
  matching: it becomes an alternative in a Split and a finding (decisions 0027 and 0051). A rule whose requirement
  can't be read keeps its place with an opaque requirement; dropping it would hand its requests to a later rule.
- **Splits are recomputed.** Keep a Split's requirement the OR of its alternatives and register it with
  `GraphBuilder.split`, or `rebuildSplits` won't recompute it after the hierarchy widens its parts.
- **Prefix and hierarchy depend on how the manager was built.** The DSL's methods use the configured prefix and the
  hierarchy; static factories and `new WebExpressionAuthorizationManager` use `ROLE_` and no hierarchy; WebFlux always
  uses `ROLE_` and no hierarchy. `Rule.hierarchyAware` and `hierarchyAware` must follow any change.
- **Descriptions are ids.** `Matcher.describe` goes into location ids, so changing it rewrites every golden graph.
- **Paths.** `String` patterns go through the Builder bean's base path; Boot's `PathRequest` and `EndpointRequest`
  patterns are relative to the servlet path instead. Matching sees the path without the context path, and a servlet
  of its own sees its whole path.
- **What the caller picks is a bypass, not a blind spot.** Keep `callerDecides` (BYPASSED) apart from unknown parts
  (OPAQUE_CONFIG): a header or parameter is the caller's to send; a matcher the scan can't read is the scan's limit.
- **Library behaviour is read from bytecode** at the versions noted in the comments (`ExactUrlRequestMatcher`,
  `PermitAllSupport`'s URLs, `CONFIGURERS_WITHOUT_RULES`, Boot's builder bean). A new version needs them read again.

## Protocol rules: gRPC, STOMP and RSocket

Feature: [`REQUEST_RULES`](features.md#request_rules)

The same model for other ways in: ordered rules, the first match decides, a matcher the scan can't evaluate may match
first (a Split and an OPAQUE_CONFIG finding), and a default for what nothing matches. Each class gives
`SpringSecurityModule.EntryRules` the locations for an Ingress of its kind; a STOMP message or an RSocket exchange over
a WebSocket passes its handshake's HTTP rule first.

### gRPC: `GrpcSecurityRules`

1. [`GrpcSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcSecurityRules.java#L38)'s constructor
   finds every application `@Bean` method with a `GrpcSecurity` parameter and reads it with
   [`SecurityDsl.grpcChain`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L680):
   `authorizeRequests(r -> r.methods("pkg.Service/*").hasRole("X").allRequests().authenticated())` gives `GRPC`
   rules, `not()` negating one. The interceptors are sorted by `@Order` (decision 0032).
2. An interceptor applies to every service when it is a `@GlobalServerInterceptor`, else to the services whose
   `@GrpcService` lists `AuthenticationProcessInterceptor` in `interceptors` or its bean name in `interceptorNames`
   ([`GrpcSecurityRules.applies`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcSecurityRules.java#L152)). One
   that applies to no service is NOT_ENFORCED.
3. [`GrpcSecurityRules.locationsFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcSecurityRules.java#L84)
   gives one location per interceptor that applies and authorizes, and each must pass: the first rule matching the
   full method name, a Split for rules before it over methods the scan can't read, and denial when none matches
   (`RequestMapperAuthorizationManager`).
4. A call on Spring gRPC's own server passes only these rules. A call served through the servlet container passes the
   HTTP rules instead, where Boot's `GrpcRequest.toAnyService()` is `/<service>/**` for each service the application
   serves ([`GrpcServices.serviceNames`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcServices.java#L84)).

### STOMP messages: `MessageSecurityRules`

1. [`MessageSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSecurityRules.java#L55)'s
   constructor reads the XML brokers first, then the Java configuration
   ([`MessageSecurityRules.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSecurityRules.java#L215),
   decision 0039):
   - With `@EnableWebSocketSecurity`, the `AuthorizationManager<Message<?>>` bean decides each message, and
     `interpret` reads its `MessageMatcherDelegatingAuthorizationManager.Builder` calls. Without the bean, every
     message must be `authenticated`.
   - A method that creates an `AuthorizationChannelInterceptor` (MSG-05) is read the same way, from the manager it is
     given.
   - A message manager bean with neither is NOT_ENFORCED: nothing puts it on the inbound channel.
2. [`MessageSecurityRules.xml`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSecurityRules.java#L140) reads
   each `<websocket-message-broker>` (MSG-06, decision 0097): its `<intercept-message>`s are rules in document order,
   ended by `anyMessage().permitAll()`. One with an `id` runs only where the inbound channel is given it: NOT_ENFORCED
   when nothing gives it there, OPAQUE_CONFIG when Java code wires interceptors the scan doesn't read
   (`channelWiring`). An `authorization-manager-ref` decides every message; an `<expression-handler>` is reported,
   since its rules are read with Spring's default handler.
3. The matchers are `HttpSecurityRules.Matcher`s with the message type (`MESSAGE`, `SUBSCRIBE`) where an HTTP method
   goes and the destination as the path: `simpDestMatchers` for any type, `simpMessageDestMatchers`,
   `simpSubscribeDestMatchers`, `simpTypeMatchers`, `anyMessage`. `nullDestMatcher` and `matchers(MessageMatcher)` may
   match anything.
4. [`MessageSecurityRules.locationsFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSecurityRules.java#L465)
   gives one location per interceptor: the first matching rule, a Split for those that may match first, else denial
   (Java) or `permitAll` (XML).
5. Requirements are `AuthorityAuthorizationManager`'s: `ROLE_` and no role hierarchy. A
   `MessageExpressionAuthorizationManager` is SpEL; custom managers and lambdas go through `DecisionCode`.

### RSocket: `RSocketSecurityRules`

1. [`RSocketSecurityRules.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketSecurityRules.java#L144)
   applies when Boot auto-configures RSocket security or the application has `@EnableRSocketSecurity` (decision 0045).
   The first `PayloadSocketAcceptorInterceptor` bean is read by `interpret`:
   `rsocket.authorizePayload(spec -> spec.setup()...route("orders.*")...anyRequest()...anyExchange()...)`. Without a
   bean, Spring Security's defaults apply: `setup()` and `anyRequest()` authenticated, everything else permitted.
2. A bean that never calls `authorizePayload` authorizes nothing, so there is no RSocket check. One whose customizer
   can't be read is one opaque rule for every frame, reported. `authorizePayload` with no rules denies every exchange.
3. [`RSocketSecurityRules.locationsFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketSecurityRules.java#L348)
   gives the rule for the connection's `SETUP` frame, then the one for the request, or one location when they are the
   same. `route(..)` patterns match with `.` between segments, as `RSocketMessageHandler`'s route matcher does
   ([`Rule.matches`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketSecurityRules.java#L78)); `matcher(..)` and
   a route that isn't a constant never surely match, but may match first.
4. Requirements are `AuthorityReactiveAuthorizationManager`'s: `ROLE_` and no role hierarchy.

### Relies on / relied on by

- Rely on `SecurityDsl` (gRPC), `HttpSecurityRules.Matcher` (gRPC and STOMP), `BuiltInManagers` and `DecisionCode`
  ([`REQUIREMENTS`](features.md#requirements), [`CUSTOM_DECISIONS`](features.md#custom_decisions)), and
  `XmlReferences` for the XML brokers.
- Relied on by `SpringSecurityModule.EntryRules`, for the Ingress that `GrpcServices`, `StompMappings` and
  `RSocketMappings` find ([entry-points.md](entry-points.md)). By their `MECHANISM`, `hierarchiesAndFactories` leaves
  message and RSocket rules unwidened, as their managers know no role hierarchy, and `AnonymousAuthentication` leaves
  gRPC, message and RSocket rules as they are.

### Tests

| Test | Fixtures |
|---|---|
| [`GrpcFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GrpcFixtureTests.java#L30), [`GrpcFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GrpcFormsFixtureTests.java#L15) | [`grpc`](../../src/fixtures/java/fixtures/grpc/), `grpcunenforced`, `grpcservlet`, `grpcbasic`, `grpcdynamic`, `grpcnamed`, `grpclisted`, `grpcforms` |
| [`StompFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/StompFixtureTests.java#L19), [`StompRulesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/StompRulesFixtureTests.java#L20) | `stomp`, `stompdefault`, `stompmanual`, [`stomprules`](../../src/fixtures/java/fixtures/stomprules/), `stomplambda`, `stompinjected`, `stompunsecured` |
| [`XmlWebSocketFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/XmlWebSocketFixtureTests.java#L19) | [`xmlwebsocket`](../../src/fixtures/resources/xmlwebsocket/), `xmlwebsocketbeans`, `xmlwebsocketmanager` |
| [`RSocketFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/RSocketFixtureTests.java#L26), [`RSocketRulesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/RSocketRulesFixtureTests.java#L20) | `rsocket`, `rsocketdefault`, `rsocketopen`, `rsocketclosed`, `rsocketopaque`, [`rsocketrules`](../../src/fixtures/java/fixtures/rsocketrules/) |

### Before changing it

- No match is denied for gRPC and the Java STOMP builder, but let through for the XML brokers. RSocket's defaults
  permit what neither `setup()` nor `anyRequest()` takes.
- gRPC interceptors and STOMP inbound interceptors are each a check of their own that must pass, not alternatives.
- The message and RSocket Splits are plain nodes (`graph.node`), not registered with `graph.split`, so
  `rebuildSplits` leaves them as they are. That holds while nothing widens their parts; register them if it changes.
- STOMP and gRPC rules match with `HttpSecurityRules.Matcher`: a change to how it matches paths changes destinations
  and method names too.

## SOAP and WS-Security

Feature: [`REQUEST_RULES`](features.md#request_rules), [`AUTHORITY_SOURCE`](features.md#authority_source)

SOAP operations have no rules of their own. A SOAP request is an HTTP request to the `MessageDispatcherServlet`, so it
passes the HTTP rules: `SpringSecurityModule.EntryRules` checks it at each path the dispatcher is mapped on, with a
Split when they ask for different things (decision 0056, [call-paths.md](call-paths.md)). WS-Security then
authenticates the message itself, outside the filter chain, and the endpoint's method checks see that user, not the
HTTP request's.

1. [`AuthenticationMechanisms.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthenticationMechanisms.java#L220)
   calls [`WsSecurity.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/WsSecurity.java#L50).
2. `WsSecurity.detect` looks through the application's code for a `new SpringSecurityPasswordValidationCallbackHandler`
   (or a subclass): the handler `Wss4jSecurityInterceptor` gives a `UsernameToken`'s principal to, which loads the user
   through its `UserDetailsService` and sets the `SecurityContext` for the message.
3. It returns a [`WsSecurity.Mechanism`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/WsSecurity.java#L44): "WS-Security
   UsernameToken (SOAP)", live, as each message loads the user; or, when `setUserCache(..)` is given anything but a
   `NullUserCache`, "(SOAP, user cache)" and a snapshot.
4. `AuthenticationMechanisms` adds it to the authority source as a `USER_DETAILS` way in.

Tests: [`SoapFixtureTests.wsSecuritysUsernameTokenIsAWayIn`](../../src/test/java/dev/crain/authtracer/scan/spring/SoapFixtureTests.java#L128),
with the fixtures [`soapactions`](../../src/fixtures/java/fixtures/soapactions/) and `soapwscache`.

Before changing it: other handlers, such as `SimplePasswordValidationCallbackHandler`, check the password without
setting a `SecurityContext`, so they are not ways in. The handler is found where the application creates it with
`new`; one a library builds is not seen.

## Findings the rules raise

Feature: [`FINDING_OPAQUE_CONFIG`](features.md#finding_opaque_config), [`FINDING_BYPASSED`](features.md#finding_bypassed), [`FINDING_NOT_ENFORCED`](features.md#finding_not_enforced)

The rules never guess. Configuration the scan can't read keeps its place in the order, as an opaque requirement or an
alternative in a Split, and a finding names it (OPAQUE_CONFIG). A request that skips the rules, or that a caller can
steer to a weaker rule, is BYPASSED. Rules that look configured but never run are NOT_ENFORCED.

### How it works

1. `SecurityDsl` raises no findings itself. It records configuration it can't read as a
   [`SecurityDsl.Note`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L550) (`customDsl`,
   `postProcessor`) and rules whose requirement it can't read as a
   [`SecurityDsl.Unread`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L543) (`unreadRules`, a
   role that isn't a constant, a manager it can't find).
2. [`HttpSecurityRules.opaque`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1402) and
   [`HttpSecurityRules.chain`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1428) turn them
   into OPAQUE_CONFIG findings at the bean method or the line.
3. The rest are raised where they are met, while reading or matching, once per rule or chain (the `reportedMaybe` and
   `reported` sets).

| Kind | Raised in | When |
|---|---|---|
| OPAQUE_CONFIG | `HttpSecurityRules.opaque` | A library configurer applied with `http.with(..)` or spring.factories; a post-processor that may replace the filter or the manager |
| OPAQUE_CONFIG | `HttpSecurityRules.chain` | A rule whose requirement isn't readable: `hasRole(?)`, `access(..)` of a manager the scan can't find, a customizer from a field, a helper it can't follow |
| OPAQUE_CONFIG | `HttpSecurityRules.maybeFirst`, `checkedLocation` | A rule's `RequestMatcher`, or a chain's `securityMatcher`, the scan can't evaluate |
| OPAQUE_CONFIG | `requestMatcherBasePath`, `managerPostProcessorBean` | A Builder bean's `basePath` that isn't a constant; an `ObjectPostProcessor` bean for every request manager |
| OPAQUE_CONFIG | `HttpSecurityRules.xmlChains`; `SpringSecurityModule` from `SecurityXml.parse` | An `authorization-manager-ref` the scan can't read; a security XML file that doesn't parse |
| OPAQUE_CONFIG | `GrpcSecurityRules.location`, `MessageSecurityRules.maybeFirst`, `RSocketSecurityRules.maybeFirst` | A gRPC, message or payload matcher the scan can't evaluate |
| OPAQUE_CONFIG | `MessageSecurityRules.xml`, `RSocketSecurityRules.detect` | An XML broker the Java code may wire, its unreadable manager or its expression handler; an unreadable `authorizePayload` customizer |
| BYPASSED | `HttpSecurityRules.ignoredLocation`, `ignoring` | Each request `ignoring()` takes; an `ignoring()` matcher the scan can't evaluate or the caller decides |
| BYPASSED | `HttpSecurityRules.queryBypass` | A regex rule a query string escapes, to a rule that asks for something else |
| BYPASSED | `HttpSecurityRules.maybeFirst`, `checkedLocation` | A rule or `securityMatcher` whose test the caller decides: a header, a parameter, the raw URI |
| NOT_ENFORCED | `GrpcSecurityRules` (constructor) | An `AuthenticationProcessInterceptor` no service runs |
| NOT_ENFORCED | `MessageSecurityRules.detect`, `MessageSecurityRules.xml` | A message manager bean nothing puts on the inbound channel; an XML broker with an `id` nothing wires |

### Tests

[`DslUnreadFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DslUnreadFixtureTests.java#L15),
[`DslHelpersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DslHelpersFixtureTests.java#L22),
[`LibraryDslFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/LibraryDslFixtureTests.java#L18),
[`PostProcessorsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/PostProcessorsFixtureTests.java#L18),
[`DynamicPatternsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DynamicPatternsFixtureTests.java#L17)
and [`ServletBasePathsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ServletBasePathsFixtureTests.java#L17)
for OPAQUE_CONFIG on HTTP; [`XmlMatchersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/XmlMatchersFixtureTests.java#L18)
and [`XmlWebSocketFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/XmlWebSocketFixtureTests.java#L19)
for the XML; [`WebFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/WebFixtureTests.java#L17),
[`IgnoringFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/IgnoringFormsFixtureTests.java#L19),
[`MatchersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MatchersFixtureTests.java#L13) and
[`MatcherLambdasFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MatcherLambdasFixtureTests.java#L22)
for BYPASSED; [`GrpcFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GrpcFixtureTests.java#L30) and
[`StompRulesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/StompRulesFixtureTests.java#L20) for
NOT_ENFORCED and the protocol rules' OPAQUE_CONFIG, with
[`RSocketRulesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/RSocketRulesFixtureTests.java#L20).

### Before changing it

- A finding never replaces the rule: the opaque requirement or the Split stays on the path, so exposures and the diff
  still see that something asks for something there.
- Findings are raised once per rule, chain or bean, not once per Ingress, except BYPASSED for `ignoring()` and the
  query string, which name the request. Keep the dedup keys (location ids) stable, or the findings repeat.
- Messages name matchers and requirements with `Matcher.describe` and `HttpSecurityRules.describe`; the UI folds
  findings that differ in a word, so keep their wording parallel.

## Files

| File | Role | Features |
|---|---|---|
| [`HttpSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L51) | The HTTP chains and their rules in order, the `Matcher` model, and the check each Ingress gets | `REQUEST_RULES`; `Matcher`: `CALL_PATHS`, `PROVIDED_FACTS`; `chainsFor`: `CALL_PATHS`; `hierarchyAware`: `REQUIREMENTS`; findings: `FINDING_OPAQUE_CONFIG`, `FINDING_BYPASSED` |
| [`SecurityDsl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L68) | Reads the Java, Kotlin and Groovy DSL from bytecode into rules, matchers and requirements | `REQUEST_RULES`; managers: `CUSTOM_DECISIONS`, `REQUIREMENTS`; `Note`, `Unread`: `FINDING_OPAQUE_CONFIG` |
| [`MatcherLambdas`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MatcherLambdas.java#L53) | Reads what a `RequestMatcher` lambda or predicate tests | `REQUEST_RULES` |
| [`SecurityXml`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityXml.java#L45) | Parses the security XML namespace: chains, method security, login elements, beans, view resolver, WebSocket brokers | `REQUEST_RULES`, `METHOD_SECURITY`, `WEBSOCKET_MESSAGES`, `VIEW_FIELDS`, `AUTHORITY_SOURCE`; `parse`: `FINDING_OPAQUE_CONFIG` |
| [`XmlReferences`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/XmlReferences.java#L33) | Resolves the XML's matcher and manager bean references, and configuration attributes | `REQUEST_RULES`, `METHOD_SECURITY`; `manager`: `CUSTOM_DECISIONS`; `attributes`: `REQUIREMENTS` |
| [`GrpcSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcSecurityRules.java#L38) | Spring gRPC's `authorizeRequests` rules on each gRPC call | `REQUEST_RULES`, `FINDING_NOT_ENFORCED`, `FINDING_OPAQUE_CONFIG` |
| [`MessageSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSecurityRules.java#L55) | STOMP message rules, from Java and from the XML brokers | `REQUEST_RULES`, `CUSTOM_DECISIONS`, `FINDING_OPAQUE_CONFIG`, `FINDING_NOT_ENFORCED` |
| [`RSocketSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketSecurityRules.java#L53) | RSocket `authorizePayload` rules on the setup frame and each request | `REQUEST_RULES`, `CUSTOM_DECISIONS`, `FINDING_OPAQUE_CONFIG` |
| [`WsSecurity`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/WsSecurity.java#L35) | WS-Security's `UsernameToken` as a way in for SOAP messages | `AUTHORITY_SOURCE` |
