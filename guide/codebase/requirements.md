# Requirements and authority sources

Every authorization question has two halves: what a check asks for, and what a caller can hold. This page covers
both. The first section, [`REQUIREMENTS`](features.md#requirements), follows a check from its SpEL expression, DSL call
or manager into one normalized [`Requirement`](../../scanner/src/main/java/dev/crain/authtracer/graph/Requirement.java#L25), and
then through the passes that rewrite it: the role prefix, the role hierarchy, the factors a multi-factor factory adds,
and what callers who haven't signed in hold. The second section, [`AUTHORITY_SOURCE`](features.md#authority_source),
follows how a service authenticates its requests into the one
[`AuthoritySource`](../../scanner/src/main/java/dev/crain/authtracer/graph/AuthoritySource.java#L24) its graph records: where the
authorities come from, how fresh they are and, for a service whose JWTs are its only way in, which authorities a
request can carry at all. Each section lists the findings its code raises. The page ends with a table of its files.

Both halves start in the setup of `SpringSecurityModule`'s scan, before any entry point is found (see
[scanning.md](scanning.md)), and both finish in the passes `run` makes after the call-path walk
([call-paths.md](call-paths.md)), once every check is in the graph. The rule and method-check readers that call this
code are described in [rules.md](rules.md) and [method-checks.md](method-checks.md).

## What a check asks for

Feature: [`REQUIREMENTS`](features.md#requirements)

Every Authorization Location carries a `Requirement`, the `location.requirement` of the graph JSON. It is a tree:
leaves that ask for something, joined by AND, OR and NOT. Authorities are full names (`ROLE_ADMIN`,
`SCOPE_employees.read`), and `expression` keeps the text the check was written as, so the UI can show both. Exposures,
the diff and policies compare these trees through [`Clauses`](../../src/main/java/dev/crain/authtracer/diff/Clauses.java#L23).

| Kind | Written as |
|---|---|
| PERMIT_ALL, DENY_ALL | `permitAll`, `denyAll`, `true`, `false`, `@PermitAll`, `@DenyAll` |
| AUTHENTICATED | `authenticated`, `isAuthenticated()` |
| FULLY_AUTHENTICATED | `fullyAuthenticated`: signed in, and not through remember-me |
| REMEMBER_ME | `rememberMe`: remember-me sessions only |
| ANONYMOUS | `anonymous`, `isAnonymous()`: only callers who haven't signed in, so it asks nothing of an outsider |
| ANY_AUTHORITY | `hasRole`, `hasAnyRole`, `hasAuthority`, `hasAnyAuthority`, `@Secured`, `@RolesAllowed`, `hasScope` |
| ALL_AUTHORITIES | `hasAllRoles`, `hasAllAuthorities`, `hasAllScopes`, the factors a multi-factor factory requires |
| AND, OR, NOT | `and`, `or`, `!`, `== false`, `AuthorizationManagers.allOf`, `anyOf`, `not` |
| EXPRESSION | Anything else, kept as text: `#owner == authentication.name`, a manager AuthTracer can't read |

An EXPRESSION is never dropped or guessed at. When application code decides it (a SpEL bean, a custom
`AuthorizationManager`), `decidedBy` names that code; that is [`CUSTOM_DECISIONS`](features.md#custom_decisions), on
[method-checks.md](method-checks.md).

### How it works

The configuration comes first, in the `Scan` constructor of
[`SpringSecurityModule`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L60):

1. [`RoleHierarchies.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RoleHierarchies.java#L60) reads the
   first `RoleHierarchy` bean method. It evaluates the method's body statement by statement (`evaluate`, `call`):
   `RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_STAFF\n...")`, or the builder
   `withDefaultRolePrefix().role("ADMIN").implies("STAFF")...build()`, which it turns into the same lines (`parse`).
   The result is each role's directly implied roles (`implies`). A body it can't evaluate is an OPAQUE_CONFIG finding,
   and the scan goes on with no hierarchy. The scan also records the hierarchy on the authority source
   (`AuthoritySource.withRoleHierarchy`), so that policies and the linker can widen roles the way this service does.
2. [`RoleHierarchies.rolePrefix`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RoleHierarchies.java#L80) reads
   `new GrantedAuthorityDefaults("...")` in its bean method. Without one the prefix is `ROLE_`; with one that isn't a
   constant, it is `ROLE_` and an OPAQUE_CONFIG finding.
3. [`AuthorizationManagerFactories.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthorizationManagerFactories.java#L83)
   reads the `AuthorizationManagerFactory` bean methods. The return type's type argument says which checks a bean
   builds, as 7.1.1 looks them up (`pick`): `RequestAuthorizationContext`, else `Object`, for
   `authorizeHttpRequests`; `MethodInvocation` for pre/post; a type variable or a raw type for both. `read` follows
   the bean's setters: `setRolePrefix`, `setRoleHierarchy` (through `hierarchyArgument`, which recognises the
   `RoleHierarchy` bean passed in or called, or reads one built in place with `RoleHierarchies.inline`),
   `setTrustResolver` and `setAdditionalAuthorization`, in the bean method and in the application `helpers` it hands
   the factory to or gets it from (one level down). A
   factory built with `AuthorizationManagerFactories.multiFactor()` gets its factors from
   [`MultiFactor.built`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MultiFactor.java#L158). Without a factory bean,
   `MultiFactor.annotated` reads `@EnableMultiFactorAuthentication(authorities = ..)`, which registers a raw factory.
   Each factory is a `Factory`: a role prefix, a hierarchy and an `additional` requirement.
4. The scan picks what each kind of check is built with. `authorizeHttpRequests` takes the HTTP factory, else a
   `Factory` of the `GrantedAuthorityDefaults` prefix and the `RoleHierarchy` bean.
   [`SpringSecurityModule.prePost`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L280)
   picks pre/post's: a `MethodSecurityExpressionHandler` bean's
   ([`ExpressionHandlers.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ExpressionHandlers.java#L77)) wins;
   reactive method security takes no hierarchy; otherwise the pre/post factory, else the beans. `@Secured` and
   JSR-250 never use a factory.
5. Each rule reader gets a [`SpelRequirements`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpelRequirements.java#L33)
   with its prefix. `HttpSecurityRules` and `GrpcSecurityRules` get the HTTP factory's. `MethodSecurity` builds
   pre/post's with the factory's prefix, the prefix the expression handler strips first, `withBeans` (SpEL bean
   calls) and `withRoot` (an application handler's own root). Message and RSocket rules, and managers built with the
   static factories, always use `ROLE_`.

Then each check is read where its reader finds it:

6. [`SpelRequirements.parse`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpelRequirements.java#L114) parses the
   expression with Spring's own `SpelExpressionParser` and walks the tree in `convert`. `and`, `or` and `!` become
   AND, OR and NOT; a check compared with `true` or `false` is the check or its negation (decision 0092); the
   security root's properties (`authenticated`, `anonymous`, ...) and methods (`hasRole`, `isFullyAuthenticated()`,
   ...) with string-literal arguments become their kinds. `role` gives a role its prefix as 7.1.1's
   `SecurityExpressionRoot.hasRole` does: it strips the handler's default prefix, then adds the factory's unless the
   role already has it. A call `@bean.method(..)` goes to
   [`DecisionCode.beanCall`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L220) (decision 0064),
   and a method of the handler's own root to `DecisionCode.rootCall` (decision 0091). Anything else, or an expression
   that doesn't parse, is an EXPRESSION of its text. `withSource` keeps the original text on the result.
7. A manager built in code rather than written in SpEL goes through
   [`BuiltInManagers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/BuiltInManagers.java#L21), one table for every
   reader: the `access(..)` DSL ([`SecurityDsl.managerFactory`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L1727)),
   method-security advisors, message, RSocket and gRPC rules, programmatic checks and decision code. The reader hands
   over what it knows of each argument as an `Arg` (`Text`, `Texts`, `Manager`, `Managers`, `Decision`, `Unknown`).
   `factory` reads the static factories (`AuthorityAuthorizationManager.hasAnyRole`,
   `AuthorizationManagers.anyOf`, `OAuth2AuthorizationManagers.hasScope`, ...) and tells overloads apart by the called
   method's parameter types (`prefixed`). `named` reads a DSL's rule methods and an `AuthorizationManagerFactory`'s.
   `composite` builds `anyOf`, `allOf` and `not`: an operand it can't read is an EXPRESSION, and `anyOf` with a
   granting default decision and such an operand also admits anyone.
8. [`MultiFactor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MultiFactor.java#L43) reads what a multi-factor
   builder asks for (`scan`): `requireFactor(RequiredFactor.Builder::passwordAuthority)`, `requireFactors(..)`, a
   factor's `authority(..)` and `validDuration`, and `when(..)`. `Factors.requirement` makes it ALL_AUTHORITIES of
   the factors (`FACTOR_PASSWORD`, `FACTOR_OTT`, ...); with a condition it is OR'ed with PERMIT_ALL, since only some
   callers are asked (decision 0018). `perUser` reads a `RequiredAuthoritiesAuthorizationManager`'s
   `MapRequiredAuthoritiesRepository` the same way, naming the users it asks. `require` adds the factors to a rule:
   each role, authority and authentication leaf becomes AND(leaf, factors), through AND, OR and NOT; PERMIT_ALL,
   DENY_ALL and EXPRESSION are left alone. `SecurityDsl` uses the same pieces for a factory built in place
   (`mfa.hasRole("ADMIN")`).
9. For a pre/post check, `MethodSecurity.read` also asks
   [`ExpressionReads`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ExpressionReads.java#L45) what the expression
   reads besides authorities (decision 0091). `arguments` gives each `#variable` the parameter Spring gives it:
   `@P` or Spring Data's `@Param` names first (and then only those), else the class file's parameter names, else a
   Kotlin function's when kotlin-reflect is present; `#p0` and `#a0` by position. A variable with no parameter is an
   OPAQUE_CONFIG finding in `MethodSecurity.read`, worded with `unnamed`. `claims` lists the token claims the
   expression reads off the caller (`principal.claims['aud']`, `authentication.token.getClaim('tenant')`,
   `principal.subject` as `sub`). Both land on the location through
   [`AuthorizationLocation.withReads`](../../scanner/src/main/java/dev/crain/authtracer/graph/AuthorizationLocation.java#L79).
10. After the walk, `run` calls
    [`MethodSecurity.bindArguments`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L1167), which
    asks `ExpressionReads.binding` what the request binds into each parameter: a handler's binding annotation
    (`@PathVariable("id")` is "path variable id"), the caller for a `Principal` or `Authentication`, a request parameter
    for a simple value on a request mapping; for a service method, the one binding every application call to it
    passes along from a handler, up to three calls deep. The UI shows it as "Reads #id (path variable id)"
    ([`stepSpec.ts`](../../frontend/src/features/paths/stepSpec.ts)).

Then `run` rewrites every check, in this order:

11. [`SpringSecurityModule.hierarchiesAndFactories`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L807)
    widens each check with the hierarchy of its kind: request rules with the HTTP factory's, pre/post with pre/post's,
    the rest (`@Secured`, JSR-250, programmatic checks) with the `RoleHierarchy` bean.
    [`RoleHierarchies.expand`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RoleHierarchies.java#L123) adds every
    role that reaches a required authority (`holders`, `reachable`): with `ROLE_ADMIN > ROLE_STAFF`, `hasRole('STAFF')`
    becomes any of the two. An ALL_AUTHORITIES becomes an AND with one ANY_AUTHORITY per authority. It skips Provided
    checks, Splits, message, RSocket and Jersey checks, and the managers a reader says ignore the hierarchy
    (`HttpSecurityRules.hierarchyAware`, `MethodSecurity.hierarchyAware`, `ProgrammaticChecks.hierarchyAware`). Then
    [`AuthorizationManagerFactories.Factory.build`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthorizationManagerFactories.java#L72)
    adds the factory's factors to the rules it builds: `authorizeHttpRequests` (and the default chains) and pre/post,
    on Servlet only.
12. [`AnonymousAuthentication.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AnonymousAuthentication.java#L55)
    reads who a caller who hasn't signed in is (decision 0063): on Servlet an anonymous token with `ROLE_ANONYMOUS`
    unless `anonymous(..)` turns it off or `authorities(..)` gives others; on WebFlux only when `anonymous(..)` is
    called. `apply` then meets each check with it (`meet`). With the token on, a role or authority check it passes
    becomes OR(ANONYMOUS, the check) (`anonymousOr`); with it turned off, `anonymous()` admits no one and becomes
    DENY_ALL. Provided checks and the rules that don't see the token (Jersey, message, RSocket, gRPC) are left alone
    (`seesToken`).
13. [`AuthenticationMechanisms.ungranted`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthenticationMechanisms.java#L375)
    then reports the checks no request can pass, against the authority source (see the next section), and
    `rebuildSplits` rebuilds each Split from its parts, which every pass above skipped.

### Findings the checks raise

Features: [`FINDING_ALWAYS_GRANTED`](features.md#finding_always_granted), [`FINDING_ALWAYS_DENIED`](features.md#finding_always_denied), [`FINDING_OPAQUE_CONFIG`](features.md#finding_opaque_config)

| Finding | Raised in | When |
|---|---|---|
| ALWAYS_GRANTED | [`AnonymousAuthentication.apply`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AnonymousAuthentication.java#L140) | A role check that the anonymous token's custom authorities meet: anyone passes. Asking for the default `ROLE_ANONYMOUS` by name is no finding |
| ALWAYS_DENIED | [`AnonymousAuthentication.apply`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AnonymousAuthentication.java#L140) | `anonymous()` with anonymous authentication turned off: a caller who hasn't signed in has no Authentication at all |
| OPAQUE_CONFIG | [`RoleHierarchies.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RoleHierarchies.java#L60), [`RoleHierarchies.rolePrefix`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RoleHierarchies.java#L80) | A `RoleHierarchy` or `GrantedAuthorityDefaults` bean not built from constants |
| OPAQUE_CONFIG | [`AuthorizationManagerFactories.read`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthorizationManagerFactories.java#L118), `opaque`, `hierarchyArgument` | A factory class of the application's own, a prefix or hierarchy that isn't a constant, a trust resolver of its own, an additional authorization AuthTracer can't read |
| OPAQUE_CONFIG | [`AnonymousAuthentication.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AnonymousAuthentication.java#L55) | Anonymous authorities that aren't constants; anonymous authentication turned off in one of several chains, which is then shown as on everywhere |

Elsewhere, `SpringSecurityModule.hasPermission` raises ALWAYS_DENIED (or ALWAYS_GRANTED, negated) for `hasPermission`
without a `PermissionEvaluator`, and `ungranted` raises the JWT one; see [method-checks.md](method-checks.md) and the
next section.

### Relies on, relied on by

- **Relies on** [`APPLICATION_GRAPH`](features.md#application_graph): `ScanContext`, `SpringBeans.beanMethods` to find
  bean methods by return type, `Locals` to read constants and definitions, and `GraphBuilder` to replace locations and
  add findings. The SpEL parser is Spring's own `spring-expression`, so expressions parse exactly as Spring parses them.
- **Relied on by** [`REQUEST_RULES`](features.md#request_rules): `HttpSecurityRules`, `SecurityDsl`,
  `GrpcSecurityRules`, `MessageSecurityRules` and `RSocketSecurityRules` read their rules with `SpelRequirements` and
  `BuiltInManagers`. [`METHOD_SECURITY`](features.md#method_security): `MethodSecurity`, `XmlMethodChecks`,
  `MethodAdvisors` and `ExpressionHandlers`. [`CUSTOM_DECISIONS`](features.md#custom_decisions): `DecisionCode`,
  `DecisionBodies` and `ProgrammaticChecks` reduce what custom code decides with the same table.
  [`VIEW_FIELDS`](features.md#view_fields): `ViewFields` reads a view's guard with `SpelRequirements.standard`.
  [`POLICIES`](features.md#policies): [`Policies`](../../src/main/java/dev/crain/authtracer/diff/Policies.java#L51) parses
  a policy's `requires` with `SpelRequirements.standard` and widens it with `SpelRequirements.widened`, the same way the
  scan widened that service. [`EXPOSURES`](features.md#exposures) and the diff read every requirement through
  `Clauses`.

### Tests

| Test | Covers |
|---|---|
| [`SpelRequirementsTests`](../../src/test/java/dev/crain/authtracer/scan/spring/SpelRequirementsTests.java#L9) | Parsing: prefixes, operators, comparisons with true and false, the root's properties, what stays an expression |
| [`RoleHierarchiesTests`](../../src/test/java/dev/crain/authtracer/scan/spring/RoleHierarchiesTests.java#L12) | `expand`: transitive reach, cycles, AND, untouched kinds |
| [`BuiltInManagersTableTests`](../../src/test/java/dev/crain/authtracer/scan/spring/BuiltInManagersTableTests.java#L21), [`BuiltInManagersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/BuiltInManagersFixtureTests.java#L19) | Each factory of the table; overloads; composites; [`builtinmanagers`](../../src/fixtures/java/fixtures/builtinmanagers/) |
| [`ExpressionReadsTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ExpressionReadsTests.java#L10), [`SpelArgumentsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/SpelArgumentsFixtureTests.java#L17) | Claims; parameter names and bindings, in [`spelarguments`](../../src/fixtures/java/fixtures/spelarguments/), its [Kotlin](../../src/fixtures/kotlin/fixtures/spelargumentskotlin/) and [Groovy](../../src/fixtures/groovy/fixtures/spelargumentsgroovy/) forms |
| [`RoleHierarchyFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/RoleHierarchyFixtureTests.java#L16), [`RolePrefixFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/RolePrefixFixtureTests.java#L13), [`RoleFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/RoleFormsFixtureTests.java#L17) | The hierarchy bean and builder ([`roles`](../../src/fixtures/java/fixtures/roles/), [`rolebuilder`](../../src/fixtures/java/fixtures/rolebuilder/)), the prefix ([`prefix`](../../src/fixtures/java/fixtures/prefix/)), and beans that aren't constants ([`roleforms`](../../src/fixtures/java/fixtures/roleforms/)) |
| [`FactoriesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FactoriesFixtureTests.java#L12), [`CustomFactoryFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/CustomFactoryFixtureTests.java#L15) | Factory beans per scope, `@Secured` and JSR-250 keeping the beans, a custom factory reported |
| [`MultiFactorFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MultiFactorFixtureTests.java#L19), [`MfaFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MfaFormsFixtureTests.java#L16), [`MfaAdditionalFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MfaAdditionalFixtureTests.java#L17) | The annotation, factories built in place, conditions, per-user factors, negated rules ([`mfa`](../../src/fixtures/java/fixtures/mfa/), [`mfawhen`](../../src/fixtures/java/fixtures/mfawhen/), [`mfaperuser`](../../src/fixtures/java/fixtures/mfaperuser/), ...) |
| [`AnonymousFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AnonymousFixtureTests.java#L21) | Custom anonymous authorities, anonymous off, the default role, WebFlux ([`anonymousauthorities`](../../src/fixtures/java/fixtures/anonymousauthorities/), [`anonymousoff`](../../src/fixtures/java/fixtures/anonymousoff/)) |
| [`SpelBeansFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/SpelBeansFixtureTests.java#L18), [`ExpressionHandlersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ExpressionHandlersFixtureTests.java#L18) | Bean calls and handler roots as parsed here and decided in `DecisionCode` |

### Before changing it

- **Spring's behaviour is read from the 7.1.1 bytecode**, and the classes say where: `hasRole` strips the handler's
  default prefix and then adds the factory's; `DefaultAuthorizationManagerFactory` adds its factors to the role,
  authority and authentication managers, `anonymous()` included, but not to `permitAll` or `denyAll`; `@Secured` and
  JSR-250 take the `RoleHierarchy` bean but never the factory; the static factories always use `ROLE_`, and no
  hierarchy unless `setRoleHierarchy` gives them one; message rules (decision 0039), RSocket rules (decision 0045) and
  Jersey's `isUserInRole` take no hierarchy. A change to one of these should be checked against `javap` on the jar
  first.
- **The order of the passes in `run` matters.** The hierarchy and the factory's factors come first; the anonymous
  token then meets the widened checks; `ungranted` judges checks once both have run; Splits are skipped by every pass
  and rebuilt from their parts last. Move a pass and some checks are judged in the wrong form.
- **Unreadable is shown, not dropped.** A role that isn't a constant makes the call an EXPRESSION, not a check with
  fewer roles; a hierarchy, prefix or factory AuthTracer can't read is an OPAQUE_CONFIG finding and the default
  reading. `withSource` must keep the text the check was written as: the UI and the findings quote it.
- **A condition means "only some callers".** Factors asked only `when(..)`, or of named users, are OR'ed with
  PERMIT_ALL, so exposures read them as asking nothing of an outsider. Don't AND them in unconditionally.
- **Policies widen the way the scan does.** `SpelRequirements.widened` runs the same `RoleHierarchies.expand` with the
  hierarchy recorded on the authority source. Change how one widens and change the other, or a policy compares a
  widened check with an unwidened requirement.

## Where the authorities come from

Feature: [`AUTHORITY_SOURCE`](features.md#authority_source)

Each graph has one `authoritySource`. Its `kind` says where the service's authorities come from: `JWT_CLAIMS`,
`OPAQUE_TOKEN_INTROSPECTION`, `USER_DETAILS`, `IDENTITY_PROVIDER` (an OAuth2, SAML 2.0 or CAS login), `CUSTOM_FILTER`
(a filter of the application's own) or `UNKNOWN`. Its `freshness` says whether they can go stale: `SNAPSHOT` when they
were fixed when the token was issued or the user logged in, `LIVE` when they are read again on every request.
`detail` names every way in. For a resource server it also has `jwt`, what the service reads from its tokens, and,
when tokens are its only way in and the scan reads every converter, `granted`: the only authorities a request can
carry. The example services' graphs show the common case:

```json
"authoritySource": {
  "kind": "JWT_CLAIMS", "freshness": "SNAPSHOT",
  "detail": "OAuth2 Resource Server (JWT); authorities: roles → ROLE_*, scope → SCOPE_*",
  "granted": ["FACTOR_BEARER", "ROLE_*", "ROLE_ANONYMOUS", "SCOPE_*"],
  "jwt": { "authorities": [{ "claims": ["roles"], "prefix": "ROLE_" }, { "claims": ["scope", "scp"], "prefix": "SCOPE_" }],
           "validators": ["issuer"] }
}
```

### How it works

1. In the `Scan` constructor, `RequestFilters` (see [call-paths.md](call-paths.md)) collects the filters requests
   pass, and [`FilterAuthentication.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FilterAuthentication.java#L108)
   reads each once (decision 0071). For a filter of the application's own, `read` walks up to 200 methods, starting
   from the filter's own and following calls with `CallTraversal.targets`. The filter authenticates when that code
   sets the Authentication (`SecurityContext#setAuthentication`, `SecurityContextHolder#setContext`,
   `ReactiveSecurityContextHolder.withAuthentication`) or the filter extends `AbstractAuthenticationProcessingFilter`
   or `AbstractPreAuthenticatedProcessingFilter`. Its authorities are LIVE when it looks the caller up on every
   request (a `UserDetailsService`, an introspector, JDBC, JPA, a repository, an HTTP client), else a SNAPSHOT of what
   the request carries. Spring's own authenticating filters added by hand (`RequestFilters.authenticating`, which asks
   `FilterAuthentication.authenticates`) are read by `library`. Each becomes a `Mechanism` with a label, a freshness,
   and whether it runs after the filter chain's rule (`RequestFilters.beforeRule`).
2. [`AuthenticationMechanisms.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthenticationMechanisms.java#L220)
   makes one pass over every call in the application. Calls on `HttpSecurity`, `ServerHttpSecurity`, their Kotlin
   DSLs, Spring gRPC's `GrpcSecurity` and the resource server configurers add a way in (`mechanism`): `jwt`,
   `opaqueToken`, `oauth2Login`, `saml2Login`, `x509`, `httpBasic`, `formLogin`, `rememberMe`,
   `oneTimeTokenLogin`, `webAuthn`, `jee`, gRPC's `preauth`. Dynamic Groovy calls are read through
   [`GroovyCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/GroovyCalls.java#L27), a closure's untyped receiver by
   the call's name (`untyped`). Calls on the other web stack's DSL are skipped: its chains never run. An
   `authenticationManagerResolver` adds one way per kind of manager the application builds (multi-tenancy). The same
   pass hands every call to `ContextRepositories.read` and `AuthenticationProviders.read`.
3. `Mechanism.way` gives each way its freshness. JWTs, OAuth2 Login and SAML 2.0 Login are SNAPSHOT; opaque tokens,
   X.509 and gRPC pre-authentication are LIVE. Form login, HTTP Basic, remember-me, one-time tokens, passkeys and JEE
   depend on whether their chain keeps the SecurityContext between requests, which
   [`ContextRepositories.keeps`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ContextRepositories.java#L152)
   answers: SNAPSHOT "(session)" when it does, LIVE "(stateless)" when it doesn't.
4. [`ContextRepositories`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ContextRepositories.java#L46) keeps what
   each chain sets, by the chain's bean method (lambdas count for the method they are written in, through
   [`EnclosingMethods`](../../scanner/src/main/java/dev/crain/authtracer/scan/EnclosingMethods.java#L32)):
   `sessionCreationPolicy(STATELESS)`, the chain's `securityContextRepository(..)`, and a way in's own repository
   (`httpBasic(b -> b.securityContextRepository(..))`). `keeps` combines the repository the chain loads from with the
   one the way in saves to, by 7.1.1's defaults, which differ between Servlet and WebFlux (the class Javadoc lists
   them). A repository value is followed with `BuiltValues`; a `DelegatingSecurityContextRepository` keeps when one of
   its parts does; one AuthTracer can't read is taken to keep the context, and is an OPAQUE_CONFIG finding (`findings`).
5. The XML namespace's login elements (`SecurityXml.Config.mechanisms`, decision 0036) add their ways, kept in the
   session except HTTP Basic.
6. When nothing so far adds a way and the application gets a default chain (`defaultChain`: security on by
   annotation or Boot's auto-configuration, and no chain bean of its web stack), `bootOAuth2Chain` looks for Boot's
   OAuth2 chains: the resource server's when JWT properties or a `JwtDecoder` bean are there (opaque tokens likewise),
   else OAuth2 Login when clients are registered. Without either, the default chain logs in with a form (kept in the
   session) and HTTP Basic.
7. [`AuthenticationProviders.providers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthenticationProviders.java#L161)
   adds what checks the credentials when it isn't the `UserDetailsService` (decision 0074): the one
   `AuthenticationProvider` bean or component the global manager takes, else the `AuthenticationManager` beans, and
   whatever `read` saw handed to a chain, a resource server or remember-me. `classify` follows each value with
   `BuiltValues`: a `ProviderManager` is its parts, a JAAS provider is named by its authority granters (`jaas`), LDAP
   is a LIVE "LDAP directory", Spring's own providers add nothing (the way in already says), and anything else is
   `custom`: UNKNOWN freshness and an OPAQUE_CONFIG finding. A `CasAuthenticationFilter` the application makes is a
   SNAPSHOT identity provider. The global manager's providers count only when form login or HTTP Basic is a way in.
8. `WsSecurity.detect` adds SOAP's WS-Security UsernameToken (decision 0056), and each filter from step 1 is a
   CUSTOM_FILTER way. A filter after the rule is also an AUTHORITIES_IN_CODE finding: the request rules decided before
   it set anything.
9. The ways combine into one source. A request may come in through any of them, so the service is as stale as its
   stalest way (`STALEST`: SNAPSHOT, then UNKNOWN, then LIVE), and the kind is that way's. The detail joins every
   label.
10. When a way is a JWT, [`JwtSettings.read`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/JwtSettings.java#L218)
    reads how tokens become authorities (decision 0073). `scan` tracks, per local, the converters each method builds:
    a `JwtGrantedAuthoritiesConverter` (`setAuthoritiesClaimName`, `setAuthorityPrefix`,
    `setAuthoritiesClaimDelimiter`), an `ExpressionJwtGrantedAuthoritiesConverter` and its SpEL, the delegating
    converter and the reactive adapters, and a `JwtAuthenticationConverter` that uses the default converter until it
    is given another. `unread` names a converter it can't read (a class of the application's, a lambda, a field, an
    injected value, dynamic Groovy). `boot` reads Boot's `spring.security.oauth2.resourceserver.jwt.*` properties when
    Boot defines the converter bean. `claimSet` reads the claims a `MappedJwtClaimSetConverter` rewrites first, and
    `validators`, `audiences` and `bootDecoder` read the audiences and validators a token must pass (OAUTH-06).
    `result` puts it together as an `AuthoritySource.Jwt` and the detail text, and says whether every authority a
    token can grant was read.
11. When tokens are the service's only way in and everything was read, `granted` lists what a request can carry: each
    claim's prefix with `*`, `FACTOR_BEARER` (which `JwtAuthenticationConverter` adds) and `ROLE_ANONYMOUS` (a request
    without a token). A claim kept without a prefix can grant anything, so then there is no `granted`.
12. The scan stores the source with the role hierarchy
    ([`GraphBuilder.authoritySource`](../../scanner/src/main/java/dev/crain/authtracer/scan/GraphBuilder.java#L156)). After the
    walk and the requirement passes, `AuthenticationMechanisms.ungranted` asks
    [`AuthoritySource.unmet`](../../scanner/src/main/java/dev/crain/authtracer/graph/AuthoritySource.java#L64) of every check: one
    that asks for authorities no request carries, like `hasRole('ADMIN')` where tokens map only `scope` to `SCOPE_*`,
    is an ALWAYS_DENIED finding. The requirement is left as written.
13. Last, `SpringSecurityModule.handRolledChecks` calls
    [`FilterAuthentication.inCode`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FilterAuthentication.java#L167)
    on every method requests reach outside a filter. One that sets the Authentication itself, or builds one with
    `toBuilder().authorities(..)`, is an AUTHORITIES_IN_CODE finding at its first such line, naming the token and the
    constant authorities it grants.

### Findings the authority source raises

Features: [`FINDING_AUTHORITIES_IN_CODE`](features.md#finding_authorities_in_code), [`FINDING_ALWAYS_DENIED`](features.md#finding_always_denied), [`FINDING_OPAQUE_CONFIG`](features.md#finding_opaque_config)

| Finding | Raised in | When |
|---|---|---|
| AUTHORITIES_IN_CODE | [`FilterAuthentication.inCode`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FilterAuthentication.java#L167) | Code on a request path, outside a filter, sets the Authentication or its authorities: the checks after it see what it sets |
| AUTHORITIES_IN_CODE | [`AuthenticationMechanisms.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthenticationMechanisms.java#L220) | A filter authenticates after the `AuthorizationFilter`: only method and handler checks see what it sets |
| ALWAYS_DENIED | [`AuthenticationMechanisms.ungranted`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthenticationMechanisms.java#L375) | A check asks for authorities the service's JWTs never grant |
| OPAQUE_CONFIG | [`JwtSettings.result`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/JwtSettings.java#L229) | A converter AuthTracer can't read, an authority prefix that isn't a constant, a validator it can't read |
| OPAQUE_CONFIG | [`AuthenticationProviders.custom`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthenticationProviders.java#L280), `jaas` | A provider, manager or remember-me services of the application's own; a JAAS authority granter it can't follow |
| OPAQUE_CONFIG | [`ContextRepositories.findings`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ContextRepositories.java#L169) | A security context repository it can't read |

What `JwtSettings` reads of audiences and validators also feeds [`FINDING_TOKEN_REJECTED`](features.md#finding_token_rejected),
which the linker raises across services ([system.md](system.md)).

### Relies on, relied on by

- **Relies on** [`APPLICATION_GRAPH`](features.md#application_graph) and the scan's helpers: `BuiltValues` (what a
  value handed to Spring is built from), `EnclosingMethods`, `GroovyCalls`, `ConfigurationProperties` for Boot's
  properties, `WebStack.reactive`, and `RequestFilters` and `CallTraversal` from [`CALL_PATHS`](features.md#call_paths)
  for the filters.
- **Relied on by** [`POLICIES`](features.md#policies): a `fresh` policy needs a check on a service whose freshness is
  LIVE (`Policies.chain`). [`SYSTEM_GRAPH`](features.md#system_graph): the linker reads `jwt.audiences` and
  `jwt.unread` for TOKEN_REJECTED ([`Linker.audienceFindings`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L299)),
  narrows `granted` to the scopes the issuing authorization servers' clients can get for a cross-service
  ALWAYS_DENIED (`Linker.issuerFindings`, decision 0075), and matches traced decisions with the role hierarchy.
  [`LIBRARY_ENDPOINTS`](features.md#library_endpoints): `ResourceServerMetadata.detect` asks
  `AuthenticationMechanisms.bootResourceServerChain` whether Boot's resource server chain serves the metadata
  endpoint. The [`UI`](features.md#ui) shows the source in a lane's tooltip and a check's details
  ([`authorityText`](../../frontend/src/lib/format.ts#L171)).

### Tests

| Test | Covers |
|---|---|
| [`AuthoritySourceTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AuthoritySourceTests.java#L16) | Boot's OAuth2 chains ([`bootjwt`](../../src/fixtures/java/fixtures/bootjwt/), [`bootopaque`](../../src/fixtures/java/fixtures/bootopaque/), [`bootlogin`](../../src/fixtures/java/fixtures/bootlogin/)), manager resolvers ([`multitenant`](../../src/fixtures/java/fixtures/multitenant/)), X.509, the other web stack's chains |
| [`JwtAuthoritiesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/JwtAuthoritiesFixtureTests.java#L19) | Converters, Boot's properties, principal and claim set converters, Groovy, WebFlux, and the ALWAYS_DENIED of [`jwtauthorities`](../../src/fixtures/java/fixtures/jwtauthorities/) |
| [`JwtValidationFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/JwtValidationFixtureTests.java#L15) | Audiences and validators ([`jwtaudiences`](../../src/fixtures/java/fixtures/jwtaudiences/), [`jwtatvalidator`](../../src/fixtures/java/fixtures/jwtatvalidator/)) |
| [`ContextRepositoriesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ContextRepositoriesFixtureTests.java#L20) | Stateless chains, repositories per chain, unread ones, the [Kotlin](../../src/fixtures/kotlin/fixtures/sessionkotlin/) and [Groovy](../../src/fixtures/groovy/fixtures/sessiongroovy/) forms, WebFlux |
| [`AuthenticationProvidersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AuthenticationProvidersFixtureTests.java#L17) | Provider and manager beans, JAAS, LDAP, CAS, remember-me services ([`providerbeans`](../../src/fixtures/java/fixtures/providerbeans/), [`jaas`](../../src/fixtures/java/fixtures/jaas/), [`ldapbind`](../../src/fixtures/java/fixtures/ldapbind/)) |
| [`FilterAuthenticationFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FilterAuthenticationFixtureTests.java#L14), [`FilterAfterRuleFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FilterAfterRuleFixtureTests.java#L16) | Filters that decode a token or look the caller up, WebFilters, login and pre-authentication subclasses, filters after the rule ([`filterauth`](../../src/fixtures/java/fixtures/filterauth/), [`filterafterrule`](../../src/fixtures/java/fixtures/filterafterrule/)) |
| [`AuthoritiesInCodeFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AuthoritiesInCodeFixtureTests.java#L15) | `inCode` ([`authoritiesincode`](../../src/fixtures/java/fixtures/authoritiesincode/)) |
| [`FilterSourcesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FilterSourcesFixtureTests.java#L16) | Spring's authenticating filters added by hand ([`libraryauthfilters`](../../src/fixtures/java/fixtures/libraryauthfilters/)) |

The integration test's golden graphs pin the example services' sources (`src/integrationTest/resources/golden`).

### Before changing it

- **The weaker reading wins when the scan can't tell.** The stalest way sets the freshness; a repository AuthTracer
  can't read is taken to keep the context; a library filter that authenticates with the manager it is given is a
  SNAPSHOT. A SNAPSHOT claim is what makes a `fresh` policy fail, so don't make an unknown LIVE.
- **`granted` must never be narrower than what requests carry.** Set it only when tokens are the only way in and
  every converter, prefix and principal converter was read; any way in that can grant other authorities must leave it
  `null`. Otherwise `ungranted` reports checks that real callers pass.
- **Library facts are from Spring Security 7.1.1 and Boot 4.1.1 bytecode**, listed in each class's Javadoc: which
  converter `jwt()` uses (the one it is given, else the bean, else a new one), that `JwtAuthenticationConverter#convert`
  is final (so a subclass converts the same and is read) while `DelegatingJwtGrantedAuthoritiesConverter` isn't (so a
  subclass is the application's own), when Boot defines its converter bean and decoder, which repository each way in
  saves to, and which provider the global manager takes. Check `javap` before changing one.
- **One source per service.** A service with several chains grants what any of them does: `JwtSettings.read` counts
  every converter the application builds, whichever chain gets it. Both `AuthenticationMechanisms.detect` and
  `JwtSettings.read` carry a `@Might` for reading one source per chain instead.
- **A filter that authenticates is a way in, not a finding**, unless it runs after the rule; code elsewhere that sets
  the Authentication is a finding. `inCode` skips filter and WebFilter classes for that reason.

## Files

All under `scanner/src/main/java/dev/crain/authtracer/scan/spring/`.

| File | Role | Class | Members |
|---|---|---|---|
| [`SpelRequirements`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpelRequirements.java#L33) | Parses a SpEL check into a `Requirement` with the role prefix in effect; resolves bean and root calls; reads policies' and views' expressions | REQUIREMENTS | `withBeans`, `withRoot`: CUSTOM_DECISIONS; `standard`: POLICIES, VIEW_FIELDS; `widened`: POLICIES |
| [`ExpressionReads`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ExpressionReads.java#L45) | What a pre/post expression reads: parameters, what the request binds into them, token claims | REQUIREMENTS |  |
| [`BuiltInManagers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/BuiltInManagers.java#L21) | The table of Spring's built-in managers and their factories, shared by every reader | REQUIREMENTS |  |
| [`RoleHierarchies`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RoleHierarchies.java#L45) | Reads the `RoleHierarchy` and `GrantedAuthorityDefaults` beans; widens role checks | REQUIREMENTS | `detect`, `rolePrefix`: FINDING_OPAQUE_CONFIG |
| [`AuthorizationManagerFactories`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthorizationManagerFactories.java#L43) | Reads `AuthorizationManagerFactory` beans, per scope: prefix, hierarchy, additional factors | REQUIREMENTS | `read`, `hierarchyArgument`, `opaque`: FINDING_OPAQUE_CONFIG |
| [`MultiFactor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MultiFactor.java#L43) | The factors a multi-factor builder or annotation requires, and adding them to a rule | REQUIREMENTS |  |
| [`AnonymousAuthentication`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AnonymousAuthentication.java#L45) | What callers who haven't signed in hold, and each check as they meet it | REQUIREMENTS | `detect`: FINDING_OPAQUE_CONFIG; `apply`: FINDING_ALWAYS_GRANTED, FINDING_ALWAYS_DENIED |
| [`AuthenticationMechanisms`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthenticationMechanisms.java#L43) | The ways in, their freshness, the combined source, what JWTs grant, and the checks none can pass | AUTHORITY_SOURCE | `detect`: FINDING_AUTHORITIES_IN_CODE; `ungranted`: FINDING_ALWAYS_DENIED; `bootResourceServerChain`: LIBRARY_ENDPOINTS |
| [`JwtSettings`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/JwtSettings.java#L77) | How a resource server's JWTs become authorities, and the audiences and validators they must pass | AUTHORITY_SOURCE | `result`: FINDING_OPAQUE_CONFIG; `validators`, `validator`, `audiences`, `bootDecoder`: FINDING_TOKEN_REJECTED |
| [`AuthenticationProviders`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AuthenticationProviders.java#L44) | Providers and managers that check logins' credentials: the application's, JAAS, LDAP, CAS | AUTHORITY_SOURCE | `custom`, `jaas`: FINDING_OPAQUE_CONFIG |
| [`ContextRepositories`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ContextRepositories.java#L46) | Whether a chain keeps the SecurityContext between requests, per way in | AUTHORITY_SOURCE | `findings`: FINDING_OPAQUE_CONFIG |
| [`FilterAuthentication`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FilterAuthentication.java#L38) | Filters that authenticate, as ways in; code elsewhere that sets the Authentication | AUTHORITY_SOURCE | `inCode`: FINDING_AUTHORITIES_IN_CODE |
