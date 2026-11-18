# Findings

A finding is something a person should look at that the graph alone doesn't say: a check that never runs, a request
that skips one, code the scan can't read. This page follows a finding from where it is raised to where people see it,
then takes each kind in turn: what it means, every place that raises it, and the tests that pin it down.

Findings are the scan's way of keeping its one rule, **what can't be inferred is shown as such**. When a detector meets
something it can't read or a configuration that doesn't do what it seems to, it adds a finding rather than guessing,
so most detectors raise one somewhere. The kinds are the enum
[`Finding.Kind`](../../scanner/src/main/java/dev/crain/authtracer/graph/Finding.java#L18), each a feature of its own in the
[feature index](features.md#findings).

## Where findings go

1. **Raised in a scan.** A detector calls
   [`GraphBuilder.finding`](../../scanner/src/main/java/dev/crain/authtracer/scan/GraphBuilder.java#L142) with a
   [`Finding`](../../scanner/src/main/java/dev/crain/authtracer/graph/Finding.java#L12): its kind, a message that names the code
   and says why, and the [`CodeRef`](../../scanner/src/main/java/dev/crain/authtracer/graph/CodeRef.java#L12) it is about. The
   builder keeps them in a set, so the same finding raised twice is one, and
   [`ApplicationGraph`](../../scanner/src/main/java/dev/crain/authtracer/graph/ApplicationGraph.java#L21) sorts them, so two scans
   of the same code write the same list.
2. **Raised when linking.** [`Linker`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L53) raises the findings
   only several services, or their traces, can show, into
   [`SystemGraph.findings`](../../scanner/src/main/java/dev/crain/authtracer/graph/SystemGraph.java#L25): calls that match
   nothing, checks only traces show, tokens the called service rejects.
3. **Raised from Provided facts.**
   [`ProvidedFacts.resolve`](../../scanner/src/main/java/dev/crain/authtracer/provided/ProvidedFacts.java#L72) reports a local
   fact that lost to the organisation's.
4. **Compared.** [`GraphDiff.newFindings`](../../src/main/java/dev/crain/authtracer/diff/GraphDiff.java#L235) reports each
   finding the head has and the base doesn't as a `NEW_FINDING` change, which needs review
   ([`DiffReport.Kind`](../../src/main/java/dev/crain/authtracer/diff/DiffReport.java#L27)). Findings are matched by
   service, kind and message ([`GraphDiff.findingKey`](../../src/main/java/dev/crain/authtracer/diff/GraphDiff.java#L252)),
   so rewording a message makes every existing finding of it read as new in the next diff.
5. **Reported.** [`SarifReport`](../../src/main/java/dev/crain/authtracer/diff/SarifReport.java#L30) places new findings
   on the pull request's lines and [`AgentReport`](../../src/main/java/dev/crain/authtracer/diff/AgentReport.java#L20)
   lists them for a coding agent; [analysis.md](analysis.md) covers both.
6. **Shown.** The UI's Findings view folds findings that differ in a word into one
   ([`findingGroups`](../../frontend/src/features/findings/findingGroups.ts#L19)) and explains each kind with the text in
   [`FINDING_KINDS`](../../frontend/src/lib/format.ts#L188), which the Legend lists too ([delivery.md](delivery.md)).

Two kinds change what a path asks of a caller, not only what it shows: a `NOT_ENFORCED` check and an
`UNRECOGNIZED_CHECK` both count as no authorization, because nothing Spring enforces stands there.

**Adding a kind:** add it to `Finding.Kind` with a Javadoc that says what it means, add a `FINDING_<KIND>` constant to
[`Feature`](../../annotations/src/main/java/dev/crain/authtracer/annotations/Feature.java#L13) and tag the code that
raises it, add its text to `FINDING_KINDS` in `format.ts` (and its place in the Findings view's `ORDER` in
[`FindingsView.tsx`](../../frontend/src/features/findings/FindingsView.tsx) if it should sort early), and give it a
section here.

## NOT_ENFORCED

Feature: [`FINDING_NOT_ENFORCED`](features.md#finding_not_enforced)

Something looks like a check but never runs, so the path counts it as no authorization. It is raised where the scan
finds the check and then sees that nothing wires it in:

- [`MethodSecurity.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L634): a method
  annotation no proxy applies, for the reason
  [`MethodSecurity.notEnforcedReason`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L887)
  gives (method security isn't enabled for it, the class isn't a bean...).
- [`MethodAdvisors.add`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodAdvisors.java#L260) and the
  [`CustomAdvisors`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/CustomAdvisors.java#L42) constructor: an
  advisor bean nothing auto-proxies.
- [`ExpressionHandlers.root`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ExpressionHandlers.java#L169): an
  expression handler whose own root the pre/post annotations never use.
- [`WebStack.report`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/WebStack.java#L143): security configuration
  for the other web stack, which filters nothing: a `SecurityWebFilterChain` in a Servlet application, a
  `SecurityFilterChain` in a reactive one.
- [`MessageSecurityRules.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSecurityRules.java#L215):
  message rules no inbound channel is given.
- The [`GrpcSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcSecurityRules.java#L38)
  constructor: a gRPC authentication interceptor Spring gRPC never runs.

Tests: [`NoMethodSecurityFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/NoMethodSecurityFixtureTests.java#L12),
[`MethodFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MethodFormsFixtureTests.java#L27),
[`AdvisorsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AdvisorsFixtureTests.java#L14),
[`BuiltProxiesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/BuiltProxiesFixtureTests.java#L18).

## BYPASSED

Feature: [`FINDING_BYPASSED`](features.md#finding_bypassed)

A check that is enforced in general is skipped on some path, or a caller can choose to skip it:

- `SpringSecurityModule`'s request-path walk ([`SpringSecurityModule.bypassed`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1485)):
  a call that reaches a proxied check through `this`, past the proxy ([method-checks.md](method-checks.md)).
- [`HttpSecurityRules.ignoring`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1308): a
  request that `web.ignoring()` takes out of every filter chain.
- [`HttpSecurityRules.queryBypass`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1117): a
  regex rule a query string steps around.
- [`HttpSecurityRules.maybeFirst`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L1059) and
  the chain matching around it: a rule or a chain's `securityMatcher` that depends on what the caller sends
  ([rules.md](rules.md)).
- [`Scan.withHead`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L382): a `HEAD`
  request that runs a `GET` handler under another rule than `GET`'s, a rule for `GET` not matching it
  ([entry-points.md](entry-points.md)).
- [`Linker.credentialFindings`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L252): a call to another service
  that doesn't carry the caller's token, so the checks there evaluate the calling service instead
  ([system.md](system.md)).

Tests: [`IgnoringFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/IgnoringFormsFixtureTests.java#L19),
[`OrdersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/OrdersFixtureTests.java#L16),
[`DslFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DslFormsFixtureTests.java#L17),
[`BuiltProxiesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/BuiltProxiesFixtureTests.java#L18),
[`CredentialsExposureTests`](../../src/test/java/dev/crain/authtracer/diff/CredentialsExposureTests.java#L31),
[`HeadRequestsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/HeadRequestsFixtureTests.java#L18).

## UNRECOGNIZED_CHECK

Feature: [`FINDING_UNRECOGNIZED_CHECK`](features.md#finding_unrecognized_check)

Hand-rolled code reads the caller and denies, outside any mechanism Spring enforces. The path counts it as no
authorization until it moves to a recognized mechanism or a person declares it reviewed with a Provided `CHECK` fact.

- [`HandRolledChecks.finding`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HandRolledChecks.java#L183): code
  reachable from a request that reads the Authentication and throws or returns a denial. `SpringSecurityModule` runs
  it last, over every method a request reached, skipping those a Provided check covers.
- [`ProgrammaticChecks.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProgrammaticChecks.java#L92): code
  that asks an `AuthorizationManager` but drops or ignores the answer.

Tests: [`HandRolledFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/HandRolledFixtureTests.java#L15),
[`HandRolledFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/HandRolledFormsFixtureTests.java#L15),
[`ProgrammaticChecksFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ProgrammaticChecksFixtureTests.java#L22),
[`ProvidedFactsScanTests`](../../src/test/java/dev/crain/authtracer/provided/ProvidedFactsScanTests.java#L21).

## AUTHORITIES_IN_CODE

Feature: [`FINDING_AUTHORITIES_IN_CODE`](features.md#finding_authorities_in_code)

The checks after some code see an Authentication that code set, not the caller's, so a caller may need less than the
path shows:

- [`FilterAuthentication.inCode`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FilterAuthentication.java#L167):
  code outside the filters that are ways in sets the Authentication or its authorities.
- [`AuthenticationMechanisms.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthenticationMechanisms.java#L220):
  a filter that authenticates after the `AuthorizationFilter`, when the request rules have already decided.
- [`SpringSecurityModule.pooled`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1326):
  a check that runs on a pooled thread, which keeps the SecurityContext it was created with rather than the caller's,
  unless the executor carries the context over.

Tests: [`AuthoritiesInCodeFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AuthoritiesInCodeFixtureTests.java#L15),
[`ThreadHopFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ThreadHopFixtureTests.java#L19).

## OPAQUE_CALLPATH

Feature: [`FINDING_OPAQUE_CALLPATH`](features.md#finding_opaque_callpath)

A path goes through code the scan can't follow. The path gets an
[`Opaque`](../../scanner/src/main/java/dev/crain/authtracer/graph/Opaque.java#L11) step where it can't see past, and the finding
says what is missing:

- [`SpringSecurityModule.onCallSite`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1514):
  a call the walk can't resolve, such as reflection.
- [`SpringSecurityModule.passed`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L629): a
  filter or interceptor AuthTracer can't resolve to code.
- [`SpringSecurityModule.deniedValues`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L554):
  a denial handler that derives what it returns from the value it denied, read by code the graph doesn't follow
  ([fields.md](fields.md)).
- [`Linker.inferStatically`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L190): a call that may go to a
  service, but to an endpoint AuthTracer can't read.

Tests: [`ReflectionCallsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ReflectionCallsFixtureTests.java#L18),
[`FilterFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FilterFormsFixtureTests.java#L14),
[`InterceptorFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/InterceptorFormsFixtureTests.java#L15),
[`DenialsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DenialsFixtureTests.java#L23),
[`UnreadCallsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/UnreadCallsFixtureTests.java#L25).

## OPAQUE_CONFIG

Feature: [`FINDING_OPAQUE_CONFIG`](features.md#finding_opaque_config)

Security configuration the scan can't read: a role hierarchy built at runtime, a request matcher it can't evaluate, a
bean it can't resolve, an XML file it refuses to parse. It is the most common kind, raised wherever a detector reads
configuration, among them:

| Configuration | Raised in |
|---|---|
| Filter chains, rules and matchers | [`HttpSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L51), [`SecurityDsl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L68), [`MessageSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSecurityRules.java#L55), [`RSocketSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketSecurityRules.java#L53), [`GrpcSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GrpcSecurityRules.java#L38) |
| XML namespace files it can't parse | the [`SpringSecurityModule`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L60) scan's constructor |
| Role hierarchy and prefix, factories, anonymous authorities | [`RoleHierarchies`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RoleHierarchies.java#L45), [`AuthorizationManagerFactories`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthorizationManagerFactories.java#L43), [`AnonymousAuthentication`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AnonymousAuthentication.java#L45) |
| Authentication and its authorities | [`JwtSettings`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/JwtSettings.java#L77), [`AuthenticationProviders`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthenticationProviders.java#L44), [`ContextRepositories`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ContextRepositories.java#L46) |
| Method security | [`MethodSecurity`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L56), [`MethodAdvisors`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodAdvisors.java#L51), [`CustomAdvisors`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/CustomAdvisors.java#L42), [`ProxyFactories`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProxyFactories.java#L49), [`ExpressionHandlers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ExpressionHandlers.java#L36), [`XmlMethodChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/XmlMethodChecks.java#L45) |
| Custom decision code | [`DecisionCode.report`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L128), [`ProgrammaticChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProgrammaticChecks.java#L56) |
| Entry points it can't place | [`FunctionalEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FunctionalEndpoints.java#L66), [`ServletEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ServletEndpoints.java#L47), [`SoapEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SoapEndpoints.java#L40), [`MessageListeners`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageListeners.java#L31), [`WebSocketHandlers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/WebSocketHandlers.java#L47), [`RequestFilters.readWebXml`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RequestFilters.java#L898) |
| Beans that may not be made: a `@Profile` the configuration doesn't activate, a condition it leaves open, a component outside the component scan, a class with no `@Configuration` that nothing registers (decision 0111; Spring Security 6's `@Enable` annotations don't carry `@Configuration`) | [`BeanConditions.report`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/BeanConditions.java#L166); the weaker readings in `HttpSecurityRules.Chain.mayCover` and `MethodSecurity.enabling` |
| Calls it can't read | [`UnreadCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/UnreadCalls.java#L34) |
| A call that sends no credentials AuthTracer can see | [`Linker.credentialFindings`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L252) |

Tests: about sixty test classes assert one; [`DslUnreadFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DslUnreadFixtureTests.java#L15),
[`FunctionalUnreadFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FunctionalUnreadFixtureTests.java#L20),
[`DynamicMatchersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DynamicMatchersFixtureTests.java#L16)
and [`RoleFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/RoleFormsFixtureTests.java#L17) are
typical.

## CHECK_AFTER_COMMIT

Feature: [`FINDING_CHECK_AFTER_COMMIT`](features.md#finding_check_after_commit)

A `@PostAuthorize` or `@PostFilter` check runs outside its method's transaction, so it decides after the commit: a
denied caller gets an error, but what the method wrote is saved. Raised in
[`MethodSecurity.afterCommit`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L849), which compares
the order of the method-security and transaction advisors ([method-checks.md](method-checks.md)).

Tests: [`AdvisorsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AdvisorsFixtureTests.java#L14),
[`MethodFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MethodFormsFixtureTests.java#L27).

## ALWAYS_DENIED

Feature: [`FINDING_ALWAYS_DENIED`](features.md#finding_always_denied)

A check no caller can pass, so what it guards can't be reached:

- [`SpringSecurityModule`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L60)'s
  `hasPermission` phase: `hasPermission(..)` with no `PermissionEvaluator` reaching method security, which Spring's
  `DenyAllPermissionEvaluator` then denies.
- [`NoCaller.mark`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/NoCaller.java#L59) and
  [`SpringSecurityModule.offThread`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1274):
  a method check on a path with no caller (a listener, a task, another thread), which finds no Authentication
  ([call-paths.md](call-paths.md)).
- [`AuthenticationMechanisms.ungranted`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthenticationMechanisms.java#L375):
  an authority the service's tokens never grant.
- [`AnonymousAuthentication.apply`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AnonymousAuthentication.java#L140):
  a check for anonymous callers while anonymous authentication is turned off.
- [`DecisionCode.report`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L128): custom decision
  code that denies everyone, and an expression that calls a method only an expression handler's own root has, which
  pre/post annotations never use.
- The [`XmlMethodChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/XmlMethodChecks.java#L45) constructor: an
  XML `<protect method="...">` written with a qualified name, which Spring Security 7.1.1's matcher never matches, so
  the methods it names are denied.
- [`Linker.issuerFindings`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L332): a check for a scope the
  authorization server can grant none of its clients.

Tests: [`PermissionEvaluatorFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/PermissionEvaluatorFixtureTests.java#L16),
[`AsyncFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AsyncFixtureTests.java#L22),
[`JwtAuthoritiesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/JwtAuthoritiesFixtureTests.java#L19),
[`AnonymousFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AnonymousFixtureTests.java#L21),
[`IssuerLinkTests`](../../src/test/java/dev/crain/authtracer/link/IssuerLinkTests.java#L29).

## ALWAYS_GRANTED

Feature: [`FINDING_ALWAYS_GRANTED`](features.md#finding_always_granted)

A check every caller passes although it reads as if it asks for something:

- [`DecisionCode.report`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L128): custom decision
  code that always grants, a permit-all in disguise.
- [`AnonymousAuthentication.apply`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AnonymousAuthentication.java#L140):
  a role check callers who haven't signed in pass, because anonymous authentication gives them that role.
- `SpringSecurityModule`'s `hasPermission` phase: a negated `hasPermission(..)` that the deny-all evaluator makes
  true for everyone.

Tests: [`DecisionCodeFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DecisionCodeFixtureTests.java#L23),
[`AnonymousFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AnonymousFixtureTests.java#L21),
[`PermissionEvaluatorFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/PermissionEvaluatorFixtureTests.java#L16),
[`RSocketRulesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/RSocketRulesFixtureTests.java#L20).

## OPEN_SENSITIVE_ENDPOINT

Feature: [`FINDING_OPEN_SENSITIVE_ENDPOINT`](features.md#finding_open_sensitive_endpoint)

An endpoint a library serves that hands out secrets or control of the application (Actuator's heap dump and writes,
the H2 console, a config server's configuration, a Eureka server's registry) answers callers who haven't signed in.
[`SensitiveEndpoints`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SensitiveEndpoints.java#L27) notes each such
Ingress as the entry points are walked, and
[`SensitiveEndpoints.report`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SensitiveEndpoints.java#L109) raises the
finding once every path's checks are known, for those whose path permits anyone ([entry-points.md](entry-points.md)).

Tests: [`SensitiveEndpointFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/SensitiveEndpointFixtureTests.java#L21).

## PROVIDED_CONFLICT

Feature: [`FINDING_PROVIDED_CONFLICT`](features.md#finding_provided_conflict)

A local Provided fact (from the service's `authtracer.yaml`) lost to an organisation-level fact about the same thing,
and was dropped. [`ProvidedFacts.resolve`](../../scanner/src/main/java/dev/crain/authtracer/provided/ProvidedFacts.java#L72)
picks the winner by origin and
[`ProvidedFacts.dropped`](../../scanner/src/main/java/dev/crain/authtracer/provided/ProvidedFacts.java#L104) writes the finding
([analysis.md](analysis.md)).

Tests: [`ProvidedFactsTests`](../../src/test/java/dev/crain/authtracer/provided/ProvidedFactsTests.java#L20).

## RUNTIME_ONLY_CHECK

Feature: [`FINDING_RUNTIME_ONLY_CHECK`](features.md#finding_runtime_only_check)

A trace shows Spring Security evaluating a check on a request whose path in the static graph doesn't have it: the scan
missed a check. Raised in [`Linker.observeChecks`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L934) when it
reads a server span's authorization events ([system.md](system.md)).

Tests: [`LinkerTests`](../../src/test/java/dev/crain/authtracer/link/LinkerTests.java#L35).

## UNMATCHED_CALL

Feature: [`FINDING_UNMATCHED_CALL`](features.md#finding_unmatched_call)

A traced call between services matches no Egress of the caller or no Ingress of the called service: the scan missed a
call site or an entry point. Raised in [`Linker.observeCall`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L590)
for requests and [`Linker.observeMessage`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L632) for messages.

Tests: [`LinkerTests`](../../src/test/java/dev/crain/authtracer/link/LinkerTests.java#L35),
[`GraphDiffTests`](../../src/test/java/dev/crain/authtracer/diff/GraphDiffTests.java#L25).

## TOKEN_REJECTED

Feature: [`FINDING_TOKEN_REJECTED`](features.md#finding_token_rejected)

The called service may reject the token a call brings:

- [`Linker.audienceFindings`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L299): a relayed token need only
  name an audience the caller accepts, so the call fails for callers whose token names none of the called service's.
- [`Linker.clientTokenFindings`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L403): the service's own token
  carries only the scopes its client registration asks for, so a check on the called path that asks for another
  denies the call.

Tests: [`TokenLinkTests`](../../src/test/java/dev/crain/authtracer/link/TokenLinkTests.java#L24),
[`ClientTokenLinkTests`](../../src/test/java/dev/crain/authtracer/link/ClientTokenLinkTests.java#L32).
