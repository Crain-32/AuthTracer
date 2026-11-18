# Known bugs

Bugs found and not yet fixed, most serious first. Each says where it is, what happens, what Spring does instead, how to
confirm it, and which way a fix goes. Take an entry out in the commit that fixes it, with the test that shows the fix.

The links name the code they point at; refresh their line anchors with `scripts/guide-anchors.sh BUGS.md`.

## 1. SOAP calls count as relaying the caller's token

Found 2026-10-18, while writing the codebase guide's [calls page](guide/codebase/calls.md).

**Where.** [`SoapCalls.detect`](scanner/src/main/java/dev/crain/authtracer/scan/spring/SoapCalls.java#L67) makes a SOAP call's
Egress without credentials, and [`HttpClientEgress.detect`](scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L296)
returns it as it is. Every other kind of call gets its credentials there, through
[`HttpClientEgress.withCredentials`](scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L237) or what
[`EgressCredentials`](scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L69) finds.

**What happens.** The Egress's `credentials` stays `null`, and
[`Credentials.callerChecked`](scanner/src/main/java/dev/crain/authtracer/graph/Credentials.java#L38) reads `null` as a relay, which
it does so that graphs scanned before credentials were recorded keep their meaning. So for a SOAP call:

- [`Exposures.acrossLinks`](src/main/java/dev/crain/authtracer/diff/Exposures.java#L491) counts the called SOAP endpoint's
  checks toward what the original caller needs;
- [`Policies`](src/main/java/dev/crain/authtracer/diff/Policies.java#L51) counts them toward an endpoint policy;
- [`Linker.credentialFindings`](src/main/java/dev/crain/authtracer/link/Linker.java#L252) raises no `BYPASSED` or
  `OPAQUE_CONFIG` finding for the call.

**What Spring does.** A `WebServiceTemplate` doesn't forward the caller's token. Whatever authenticates the call comes
from its client interceptors (a WS-Security interceptor adding a username token, say) or its message sender (basic
auth): the service's own, fixed credentials, or none.

**Effect.** The SOAP service's checks evaluate the calling service, not its caller, yet the caller's exposure shows
them. An endpoint looks stricter than it is, and a change that weakens it can pass the diff.

**To confirm.** A fixture whose controller calls a SOAP endpoint, guarded by a role, through a `WebServiceTemplate`:
today the controller's exposure asks for that role.

**Fix direction.** Give SOAP calls credentials as the other clients get them: `NONE` by default, `STATIC` or `UNKNOWN`
from the template's interceptors and message sender.

## 2. Interceptors' `postHandle` and `afterCompletion` come before the response is written

Found 2026-10-18, while writing the codebase guide's [call paths page](guide/codebase/call-paths.md).

**Where.** [`SpringSecurityModule.Scan.walk`](scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L426)
puts a path's steps in this order: the interceptors' `preHandle`, the handler's walk, then every `postHandle` and every
`afterCompletion` (one list, `afterHandler`, which
[`RequestFilters.around`](scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestFilters.java#L291) builds), the Data REST
handlers that run after, a Stream function's outputs, then the field checks Jackson runs as it writes the response
([`SpringSecurityModule.serialized`](scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1108)), then
the view's checks, then the filters' code after `chain.doFilter(..)`.

**What Spring does.** `DispatcherServlet.doDispatch` runs `preHandle`, then the handler, inside which a `@ResponseBody`
handler's return value is written (so Jackson calls the proxies' getters there), then `postHandle`, then renders the
view, then `afterCompletion`. So the serialized checks belong before `postHandle`, and the view's checks between
`postHandle` and `afterCompletion`.

**Effect.** The Paths view shows these steps in the wrong order. And since
[`Exposures`](src/main/java/dev/crain/authtracer/diff/Exposures.java#L40) counts every unconditional check on a path
toward what a caller needs, wherever it falls, a check in `postHandle` after a `@ResponseBody` handler, or in
`afterCompletion`, counts as guarding a response already written: the endpoint looks stricter than it is. The filters'
code after `chain.doFilter(..)` raises the same question.

**To confirm.** A fixture with a `HandlerInterceptor` whose `postHandle` denies, on a `@ResponseBody` handler that
returns an authorization proxy and on one that renders a view: assert the order of the steps, and what each exposure
asks.

**Fix direction.** In `walk`, add the serialized checks before `postHandle`, and split `afterHandler` so the view's
checks go between `postHandle` and `afterCompletion`. Then decide, as a decision record, whether checks that run after
the response is written should count toward exposures, or show as conditional.

## 3. A field check that throws fails the whole response, but counts for its field only

Found 2026-10-18 by `./gradlew conformanceTest`. Decision draft 0100 asks which reading to keep.

**Where.** [`Exposures.checks`](src/main/java/dev/crain/authtracer/diff/Exposures.java#L296) puts every
`Scope.FIELD` check under the field it guards and never on the endpoint, whatever its denial does.

**What happens.** `GET /person` in the `jacksonnames` fixture asks nothing; `Person.ssn` asks `ROLE_ADMIN`.

**What Spring does.** Jackson calls every getter while it writes the body. A check with no denial handler
(`Denial.Kind.THROW`) throws `AccessDeniedException` (or `AuthenticationCredentialsNotFoundException`) from inside the
serializer, and `ExceptionTranslationFilter` finds it in the cause chain: 403 for the whole response. A caller without
`ROLE_ADMIN` gets nothing from `GET /person`, not a `Person` without `ssn`.

**Effect.** The endpoint looks open to callers it refuses (the graph is weaker than Spring, the safe direction), and
adding such a check to a getter doesn't show as strengthening the endpoint. Conformance lists 26 probes as known:
`jacksonnames`, `proxies`, `builtproxies`, `builtproxiesonly`, `builtproxiesunread`, `denials`, `proxyflows`,
`fields`, `proxyadvisors`, `proxyadvisorscustomized`.

The field probes see it for callers who meet the endpoint and fail a throwing field check (`FIELD_RESPONSE_FAILED`,
20 judgements in `builtproxies`, `denials`, `fields`, `jacksonnames`, `proxyadvisors`, `proxyadvisorscustomized`).
And where two fields' throwing checks share the authority a change widens (`builtproxies` `balance` and
`latest.amount`), no caller can show the field weaker: mutationTest leaves such a mutant UNJUDGED.

**To confirm.** `conformanceTest -Pfixtures=jacksonnames`: the anonymous caller of `GET /person` is denied.

**Fix direction.** Decision 0100: count an unconditionally serialized field check that throws toward the endpoint too,
with a finding naming the usual fix (`@HandleAuthorizationDenied`).

## 4. Code that sets the Authentication leaves the checks after it counted

Found 2026-10-18 by `./gradlew conformanceTest`. Decision draft 0101 asks which reading to keep.

**Where.** [`FilterAuthentication.inCode`](scanner/src/main/java/dev/crain/authtracer/scan/spring/FilterAuthentication.java#L167)
reports code outside a filter that sets the Authentication as an `AUTHORITIES_IN_CODE` finding (decision 0071), and
the checks after it stay on the path as they were.

**What happens.** In the `authoritiesincode` fixture, `POST /support/refunds/{id}` sets a token with `ROLE_BILLING`
before calling a `@PreAuthorize("hasRole('BILLING')")` method; the graph says a caller needs `ROLE_BILLING`.

**What Spring does.** The check decides on the token the code set: any signed-in caller refunds.

**Effect.** The graph is stricter than Spring (the dangerous direction), and a change that adds such a line before an
existing check shows no weakening.

**To confirm.** `conformanceTest -Pfixtures=authoritiesincode`: the caller without `ROLE_BILLING` gets 200.

**Fix direction.** Decision 0101: when the set is unconditional, on the request's thread and builds constant
authorities, decide the checks after it on those; otherwise make them conditional (the weaker reading). The finding
stays.

## 5. Smaller

- **The Findings view sorts `TOKEN_REJECTED` last.** Its kind order,
  [`ORDER`](frontend/src/features/findings/FindingsView.tsx#L17), leaves it out, so its findings come after every kind
  listed there.
- **A comment says unreadable RSocket rules give no check.** The one in
  [`RSocketSecurityRules.locationsFor`](scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketSecurityRules.java#L348)
  says so, but [`RSocketSecurityRules.detect`](scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketSecurityRules.java#L144)
  makes one opaque rule for them (with an `OPAQUE_CONFIG` finding), and `locationsFor` returns its check.
- **Three Javadoc comments are split in two, and the first half is lost.** Javadoc reads only the comment right before
  a declaration, so these lose their description:
  [`MethodSecurity.PointcutGuard`](scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L817) and
  [`SecurityDsl.customDsl`](scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L701). In
  [`HttpSecurityRules.Matcher.exactUrls`](scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L377),
  the comment for `grpc` sits above `exactUrls` instead.
- **Without any filter chain, callers who haven't signed in are still read as anonymous.**
  [`AnonymousAuthentication.detect`](scanner/src/main/java/dev/crain/authtracer/scan/spring/AnonymousAuthentication.java#L55)
  turns anonymous authentication on for every Servlet application unless a chain turns it off, so a check that admits
  anyone reads as open. With no `SecurityFilterChain` at all (method security only), nothing sets an Authentication,
  and 7.1.1's method interceptors throw `AuthenticationCredentialsNotFoundException` for such a caller, even for a
  check that permits all. Conformance shows it on hosted fixtures without security (`expressionhandler GET /pager`).
- **Checks on work nobody waits for, and denied branches that answer normally, read as a 403 the endpoint never
  gives.** Off-thread work with the caller's context, not waited for (decisions 0062, 0084), and a programmatic check
  whose denial returns early (decision 0066) are on the path, so they count toward the endpoint; the request still
  succeeds. The protection is real, but nothing in the graph says how it denies. Decision draft 0102.
- **A filter or advisor of a bean that may not be made still counts as running.** Decision draft 0111 makes chains,
  method security and their findings follow [`BeanConditions`](scanner/src/main/java/dev/crain/authtracer/scan/spring/BeanConditions.java#L47),
  but the detectors that find beans by going through the classes themselves (`RequestFilters`, `DecisionCode`,
  `ExpressionHandlers`, `AuthenticationProviders`, `StreamFunctions`, ...) don't ask it: a `@Profile("dev")` filter
  that checks the caller is shown on every request. Nested `@Configuration` classes don't take their outer class's
  condition. (`AuthorizationManagerFactories` and the customizer beans `HttpSecurityRules` reads ask: a factory that
  may not be made adds no factors, a customizer's rules may match first.) Fix direction: ask `BeanConditions.maybe` where a bean
  is found, and run a maybe-bean's check as conditional.
- **An advisor's pointcut doesn't see the methods a bean inherits.**
  [`MethodSecurity`](scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L56)'s pointcut checks
  are matched against each class's declared methods: for `class Sub extends Base` where only `Base` declares `m()`, a
  pointcut `execution(* Sub.*(..))` matches `m` on the `Sub` bean in Spring AOP, and the graph shows no check (found
  by review pass 3). Fix direction: match the bean class's inherited methods too, as `closestMethod` does for
  annotations.
- **Data REST's own HEAD handlers and the gateway's `Method` predicate aren't read for HEAD.** Decision draft 0110
  gives a GET mapping its HEAD twin, but Data REST declares `headForItemResource` (which runs `findById`) and
  `headCollectionResource` itself, and a gateway route's `Method=GET` predicate isn't checked against HEAD. Data REST
  associations reached through getters (property access), a target type with `exported = false`, and Map-valued
  associations' keys aren't read either (draft 0114).
- **Scheduled methods of classes that aren't beans count.** [`ScheduledTasks.detect`](scanner/src/main/java/dev/crain/authtracer/scan/spring/ScheduledTasks.java#L37)
  takes any application class's `@Scheduled` method, where Spring runs a bean's only, and XML
  `<task:annotation-driven>`/`<task:scheduled-tasks>` give no entry point and no finding. More no-caller entry points
  than run, or fewer.
- **A client registration built in code has no grant type.** [`EgressCredentials.grant`](scanner/src/main/java/dev/crain/authtracer/scan/spring/EgressCredentials.java#L780)
  reads the properties (and Boot's defaults for them): a `ClientRegistrationRepository` bean built with
  `authorizationGrantType(AUTHORIZATION_CODE)` reads as the service's own token, not the signed-in user's.
- **`@ServletComponentScan`'s packages aren't read.** [`ServletEndpoints.discovery`](scanner/src/main/java/dev/crain/authtracer/scan/spring/ServletEndpoints.java#L111)
  registers every `@WebServlet` and `@WebFilter` class once the annotation is there, where Boot scans its packages
  only (by default the annotated class's).
- **A token relay that needs an OAuth2 Login caller isn't read as a check.** Spring gRPC 1.1.1's
  `TokenRelayTokenSupplier` throws `BadCredentialsException` for a caller with no Authentication, or one that isn't an
  `OAuth2AuthenticationToken` (an anonymous caller, a JWT one), so the request fails before the call is made. The
  graph shows the call relaying the caller's token and the endpoint asking nothing (`grpcclient GET /greetings/{name}`,
  found by `conformanceTest`).
