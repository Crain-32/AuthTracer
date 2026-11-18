# Method checks

This page covers the checks that run on a method rather than on a request: Spring Security's method security and the
proxies that apply it, the checks application code decides for itself, and the hand-rolled checks the scan lists but
doesn't count. In order:

1. [Method security](#method-security): annotations, XML, advisor beans and pointcuts become Authorization Locations on
   the methods a Spring proxy guards, in the order Spring nests its interceptors; a call that skips the proxy skips
   them.
2. [Field checks: the method-security side](#field-checks-the-method-security-side): `@AuthorizeReturnObject`, proxy
   factories, and which values on a path are authorization proxies. [fields.md](fields.md) covers the fields
   themselves.
3. [Custom decisions](#custom-decisions): the code that decides a check (a custom `AuthorizationManager`, a SpEL bean,
   a `PermissionEvaluator`, a manager the code calls itself), read down to a requirement where it can be.
4. [Structure rules](#structure-rules): the checks of an authorization library AuthTracer doesn't know, described by
   their shape in `authtracer.yaml`.
5. [Hand-rolled checks](#hand-rolled-checks): code that reads the caller and denies outside every mechanism.
6. The findings these classes raise: [NOT_ENFORCED](#not_enforced), [BYPASSED](#bypassed),
   [CHECK_AFTER_COMMIT](#check_after_commit), [ALWAYS_DENIED and ALWAYS_GRANTED](#always_denied-and-always_granted)
   and [OPAQUE_CONFIG](#opaque_config). [findings.md](findings.md) lists every place each kind is raised.

Everything here is set up once per scan, in the constructor of `SpringSecurityModule`'s
[`Scan`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L86), and applied per path by its
[`RequestPath`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1172), the listener
[`CallTraversal`](../../scanner/src/main/java/dev/crain/authtracer/scan/CallTraversal.java#L44) calls as it walks from each entry
point ([call-paths.md](call-paths.md)):

```
Scan()   ExpressionHandlers.detect ─▶ ProxyFactories ─▶ MethodSecurity ─▶ Proxies, ProgrammaticChecks
                                                       ├─ MethodAdvisors (Pointcuts, AutoProxyCreators)
                                                       ├─ CustomAdvisors
                                                       └─ XmlMethodChecks
walk     RequestPath.enter/exit: MethodSecurity.checks(method), Proxies.Frame ─▶ steps, BYPASSED
         RequestPath.onCallSite: ProgrammaticChecks.detect ─▶ a step at the call
run()    bindArguments, hierarchiesAndFactories, hasPermission, DecisionCode.report, handRolledChecks
```

## Method security

Feature: [`METHOD_SECURITY`](features.md#method_security)

Each enforced method check is an Authorization Location with scope `METHOD`, an id such as
`location:METHOD:<class>#<method>(<parameters>):@PreAuthorize`, and a mechanism: `@PreAuthorize` and its kin,
`@Secured`, `@RolesAllowed`, `Advisor <bean>()`, `protect-pointcut`, `intercept-methods`, `@Query` or
`Provided check (...)`. It sits on every path that calls the method through Spring's proxy, before the method's own
steps (pre) or after them (post). It says whether a proxy applies it ([`proxied`](../../scanner/src/main/java/dev/crain/authtracer/graph/AuthorizationLocation.java#L40)),
how a denial answers (throw, `null`, a handler, a filter), and for pre/post which parameters and claims its expression
reads. An annotation nothing enforces is a NOT_ENFORCED finding instead.

**How it works**

1. The `Scan` constructor reads the expression handler first
   ([`ExpressionHandlers.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ExpressionHandlers.java#L77), step 8),
   because its role prefix goes into the SpEL reader, then builds
   [`ProxyFactories`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProxyFactories.java#L49),
   [`MethodSecurity`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L56) and
   [`Proxies`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/Proxies.java#L48).
2. [`MethodSecurity.readConfig`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L374) reads
   `@EnableMethodSecurity` (pre/post on unless turned off; `securedEnabled`, `jsr250Enabled`, `offset`,
   `mode = ASPECTJ`), else the legacy `@EnableGlobalMethodSecurity` (everything off unless turned on), else
   `@EnableReactiveMethodSecurity` (pre/post only). With none of them, the XML's `<method-security>` or
   `<global-method-security>` turns it on. The constructor then makes the pre/post reader
   ([`SpelRequirements`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpelRequirements.java#L33), with the
   handler's prefix and root and [`DecisionCode`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L54)
   for `@bean` calls), the advisors (steps 5 to 7), the transaction advice's order, and the types
   `@AuthorizeReturnObject` hands out ([next section](#field-checks-the-method-security-side)).
3. For each method of each application class (not annotation types, constructors or Kotlin's `f$suspendImpl` copies,
   since Spring proxies `f`), [`MethodSecurity.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L634):
   - finds each annotation of [`SpringNames.METHOD_SECURITY`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringNames.java#L53)
     as Spring Security 7.1.1 looks it up ([`MethodSecurity.find`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L1006)):
     the method, then the methods it overrides up the superclasses and then the interfaces
     ([`MethodSecurity.overrides`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L1069) accepts
     `delete(T)` erased to `delete(Object)`), and only then, for any method but a private or static one, the class
     and its supertypes: the class's pointcut matches every method, and the CGLIB proxy intercepts a package-private
     handler (found by `conformanceTest`).
     `@RolesAllowed`, `@PermitAll` and `@DenyAll` are looked up as one: only the closest counts.
     [`ScanContext.findAnnotation`](../../scanner/src/main/java/dev/crain/authtracer/scan/ScanContext.java#L178) also finds an
     annotation carried by a meta-annotation, and
     [`MethodSecurity.templated`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L1109) fills its
     `{value}` placeholders when there is an `AnnotationTemplateExpressionDefaults` bean;
   - asks [`MethodSecurity.notEnforcedReason`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L887)
     whether anything runs it ([NOT_ENFORCED](#not_enforced));
   - reads its requirement ([`MethodSecurity.requirement`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L678)):
     pre/post SpEL through `SpelRequirements.parse`, `@Secured`'s authorities as written, `@RolesAllowed`'s roles with
     the JSR-250 prefix, `@PermitAll`, `@DenyAll`.
     [`MethodSecurity.withAdvisors`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L756) adds
     with `and` the custom managers of advisor beans that handle the same annotation;
   - picks the denial: an advisor's manager that is also a `MethodAuthorizationDeniedHandler`, else, for
     `@PreAuthorize` and `@PostAuthorize` only (7.1.1's other managers aren't handlers, so they throw),
     `@HandleAuthorizationDenied` on the method or its class
     ([`MethodSecurity.denial`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L1242)), and a
     filter for `@PreFilter` and `@PostFilter`. Spring looks the handler up as the one bean of its class and, with
     none, fails every call of the method: a handler AuthTracer finds no bean of keeps reading as answering, with an
     [OPAQUE_CONFIG](findings.md#opaque_config) finding (`MethodSecurity.unregisteredHandler`);
   - records what a pre/post expression reads ([`MethodSecurity.read`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L1141)
     with [`ExpressionReads`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ExpressionReads.java#L45)): the
     parameters it names and the token claims (decision 0091);
   - adds the XML's checks ([`XmlMethodChecks.checks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/XmlMethodChecks.java#L118)),
     a Spring Data `@Query` whose SpEL reads the caller as a row filter
     ([`MethodSecurity.queryFilter`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L582)), the
     pointcut advisors that match ([`MethodSecurity.pointcutChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L780)),
     checks [`MethodSecurity.afterCommit`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L849),
     and adds a reviewed hand-rolled check declared as a Provided fact
     ([`MethodSecurity.providedCheck`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L875));
   - stores them as [`MethodChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L61): pre
     checks by interceptor order, lowest first; post checks highest first, because interceptors nest (the lowest runs
     first on the way in and last on the way out). The Provided check goes last among the pre checks: it runs inside
     the body.
4. [`MethodSecurity.order`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L733) places each
   annotation: [`MethodAdvisors.ORDERS`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodAdvisors.java#L97)
   (Spring's `AuthorizationInterceptorsOrder`: `@PreFilter` 100, `@PreAuthorize` 200, `@Secured` 300, JSR-250 400,
   `@PostAuthorize` 500, `@PostFilter` 600) plus the `offset`, or the lowest order of an advisor bean for it (decision
   0092). An XML `<protect-pointcut>` runs first, `<intercept-methods>` last, a `@Query` filter innermost.
5. Advisor beans: the [`MethodAdvisors`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodAdvisors.java#L51)
   constructor interprets every `@Bean` method ([`MethodAdvisors.interpret`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodAdvisors.java#L315),
   following up to three of the application's helpers) for Spring's interceptor factories
   (`AuthorizationManagerBeforeMethodInterceptor.preAuthorize()` and its siblings, the reactive ones too), the filter
   interceptors, `setOrder(..)`, and `new AuthorizationManagerBeforeMethodInterceptor(pointcut, manager)` with an
   `AspectJExpressionPointcut`. An annotation advisor turns its annotation on even with its `@EnableMethodSecurity`
   flag off; given a custom manager, that manager decides instead of the annotation's attributes
   ([`MethodAdvisors.evaluate`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodAdvisors.java#L353), with
   `DecisionCode`). A pointcut advisor guards every bean method its pointcut matches
   ([`Pointcuts.parse`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/Pointcuts.java#L45): `execution`, `within`,
   `@annotation`, `@within`, joined with `&&`, `||`, `!`). [`MethodAdvisors.add`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodAdvisors.java#L260)
   keeps an advisor only when an auto-proxy creator applies it ([`AutoProxyCreators`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AutoProxyCreators.java#L15):
   an AspectJ one applies every advisor; `@EnableMethodSecurity`'s, and Boot's without AspectJ, only those with
   `@Role(ROLE_INFRASTRUCTURE)`; `spring.aop.auto=false` turns Boot's off).
6. The application's own `AuthorizationAdvisor` beans ([`CustomAdvisors`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/CustomAdvisors.java#L42)):
   the pointcut is read when it is an `AspectJExpressionPointcut` with a constant expression or an
   `AnnotationMatchingPointcut` ([`CustomAdvisors.expression`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/CustomAdvisors.java#L157));
   the advice is not, so the methods it matches show a `custom AuthorizationAdvisor` requirement and a finding says so.
7. The XML namespace's checks without annotations ([`XmlMethodChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/XmlMethodChecks.java#L45),
   decision 0097): the first `<protect-pointcut>` that matches a bean method, read with Spring's default handler
   (`ROLE_`, no hierarchy); the legacy `<global-method-security>`'s pointcuts only where no enabled annotation applies;
   a bean's `<intercept-methods>`, where the first `<protect>` whose name matches decides and a method none matches is
   denied ([`XmlMethodChecks.interceptMethods`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/XmlMethodChecks.java#L149);
   the legacy interceptor takes the most specific name and lets the rest through).
8. A `MethodSecurityExpressionHandler` bean ([`ExpressionHandlers.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ExpressionHandlers.java#L77),
   decision 0091) replaces pre/post's own: what it is given with `setDefaultRolePrefix`, `setRoleHierarchy` and
   `setAuthorizationManagerFactory`, in its bean method or constructor or an application helper they hand it to or
   get it from (`withHelpers`), decides the prefix, hierarchy and factory pre/post builds with
   (`Scan.prePost`), and a subclass's own root answers the expressions' calls to its methods
   ([`ExpressionHandlers.root`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ExpressionHandlers.java#L169)).
9. On each path, [`CallTraversal.visit`](../../scanner/src/main/java/dev/crain/authtracer/scan/CallTraversal.java#L189) tells the
   listener whether a call is made on `this` (for Groovy, a dynamic call whose receiver is `this` too).
   [`RequestPath.enter`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1343) asks
   [`MethodSecurity.checks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L238): a call
   through a bean adds the pre checks (through `fieldChecks` for the objects of the next section); a call on `this`
   adds only the checks no proxy applies and raises [BYPASSED](#bypassed) for the rest.
   [`RequestPath.exit`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1574) does the same
   with the post checks.
10. After every path is walked, `Scan.run` calls [`MethodSecurity.bindArguments`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L1167)
    (what each request binds into the parameters an expression names), then
    [`Scan.hierarchiesAndFactories`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L807),
    which widens checks by the RoleHierarchy unless [`MethodSecurity.hierarchyAware`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L290)
    says their manager has none, then [`Scan.hasPermission`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L840).

Branches that matter: with `mode = ASPECTJ` Spring Security hands each annotation's interceptor to an aspect in
`spring-security-aspects`, which runs only where it is woven ([`MethodSecurity.woven`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L944)):
a class ajc wove (the method, or an around body its closures run, calls the aspect's `aspectOf()`), or every class
under `@EnableLoadTimeWeaving`. A woven check is not `proxied` and runs on calls on `this` and on objects that aren't
beans. Unwoven, nothing runs it: in AspectJ mode no advisor is made of the interceptors (7.1.1's
`MethodSecurityAdvisorRegistrar` is imported in PROXY mode only), so it is NOT_ENFORCED, "may never run" (a load-time
weaving agent may weave it). JSR-250's annotations have no aspect, so they never run. The walk follows ajc's closures into the around bodies
([`CallTraversal.targets`](../../scanner/src/main/java/dev/crain/authtracer/scan/CallTraversal.java#L416)), which
[`EnclosingMethods`](../../scanner/src/main/java/dev/crain/authtracer/scan/EnclosingMethods.java#L32) names by the woven
method. Reactive method security handles pre/post only; its interceptors
take the same factory calls, and a reactive after-advisor built with the constructor is ordered last.

**Relies on / relied on by.** It relies on [`CALL_PATHS`](features.md#call_paths) (the walk) and
[`REQUIREMENTS`](features.md#requirements) (`SpelRequirements`,
[`BuiltInManagers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/BuiltInManagers.java#L21), the role hierarchy
and prefix in [requirements.md](requirements.md)), on [`SpringBeans.isProxied`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringBeans.java#L97)
for which classes a proxy stands in front of, and on
[`SecurityXml`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityXml.java#L45) for the XML.
[`FIELD_CHECKS`](features.md#field_checks) and the NOT_ENFORCED, BYPASSED and CHECK_AFTER_COMMIT findings rely on it;
so do [`NoCaller`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/NoCaller.java#L28) (a method check on a path
without a caller) and [`AnonymousAuthentication`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AnonymousAuthentication.java#L45).

**Tests.** [`OrdersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/OrdersFixtureTests.java#L16)
(fixture [`orders`](../../src/fixtures/java/fixtures/orders/): normalized requirements, meta-annotations, call on
`this`, annotations that never run),
[`AnnotationOrderFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AnnotationOrderFixtureTests.java#L16),
[`TemplatesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/TemplatesFixtureTests.java#L12),
[`MethodFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/MethodFormsFixtureTests.java#L27),
[`DenialsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DenialsFixtureTests.java#L23),
[`SpelArgumentsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/SpelArgumentsFixtureTests.java#L17)
(Java, Groovy and Kotlin parameter names), [`RepositoryFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/RepositoryFixtureTests.java#L15)
(`@Query`), [`AdvisorsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AdvisorsFixtureTests.java#L14),
[`AdvisorShapesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AdvisorShapesFixtureTests.java#L22),
[`AdvisorHelpersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AdvisorHelpersFixtureTests.java#L18),
[`AdvisorProxyingFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AdvisorProxyingFixtureTests.java#L18),
[`CustomAdvisorsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/CustomAdvisorsFixtureTests.java#L21),
[`PointcutFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/PointcutFormsFixtureTests.java#L19),
[`XmlMethodsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/XmlMethodsFixtureTests.java#L18),
[`ExpressionHandlersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ExpressionHandlersFixtureTests.java#L18),
[`ReactiveMethodsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ReactiveMethodsFixtureTests.java#L13),
[`KotlinSuspendFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/KotlinSuspendFixtureTests.java#L13),
[`GroovyFixtureTests.aDynamicCallOnThisSkipsTheProxy`](../../src/test/java/dev/crain/authtracer/scan/spring/GroovyFixtureTests.java#L67),
[`AspectJModeFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AspectJModeFixtureTests.java#L15)
(its woven scan weaves the fixture with AspectJ's weaver, `FixtureScans.scanWoven`); `conformanceTest` boots the
woven classes too (`aspectj+woven`).
The example services' goldens hold their `@PreAuthorize` checks.

**Before changing it**

- Defaults, lookup order and interceptor orders are Spring Security 7.1.1's and Spring Boot 4.1.1's, read from their
  bytecode (`UniqueSecurityAnnotationScanner`, `Jsr250AuthorizationManager`, `AuthorizationInterceptorsOrder`,
  `AopAutoConfiguration`); the version is noted beside each. Check again with `javap` when the versions move.
- `proxied` is what makes a call on `this` skip a check. Anything that runs without Spring's proxy (a Provided
  check, an AspectJ-woven one, a programmatic one) must be built with it `false`.
- A manager Spring builds outside the annotation's own (an advisor's static factory, the XML's) has no RoleHierarchy:
  its check's id goes into `withoutHierarchy` (decisions 0092, 0097), or the hierarchy would widen it wrongly.
- Location ids are `location:<scope>:<method key>:<mechanism>`, and every path and golden names its steps by them:
  changing their shape rewrites every golden.
- An annotation that can't run is a finding, never a location: the graph must not show protection Spring won't give.

## Field checks: the method-security side

Feature: [`FIELD_CHECKS`](features.md#field_checks)

A method check on a getter of an object that `@AuthorizeReturnObject` or `AuthorizationProxyFactory#proxy` hands out
is a field check: scope `FIELD`, with `field` the JSON property the getter writes. It counts on a path only where the
getter is called on an authorization proxy, and only when the factory that made that proxy applies it. Returning a
proxy from a handler runs its getters' checks when the response is serialized. [fields.md](fields.md) covers the
response fields these checks guard and what a denied caller gets.

**How it works**

1. [`MethodSecurity.collectReturnObjectTypes`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L404)
   collects the types Spring proxies: what `@AuthorizeReturnObject` methods return (directly, or as the element type
   of a collection or optional), what is passed to `proxy(..)`
   ([`MethodSecurity.collectProxiedTypes`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L460)),
   and the types an `AuthorizeReturnObjectHintsRegistrar` names
   ([`MethodSecurity.hintedTypes`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L427)).
2. In `MethodSecurity.detect`, a no-argument getter of such a type that isn't a bean gets scope `FIELD`, its property
   named as the application's Jackson names it ([`MethodSecurity.getterField`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L1267)).
   Every check of that class runs only on the proxy ([`MethodSecurity.onlyOnReturnedProxy`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L233)).
   `pointcutChecks` applies the advisor beans and the application's `AuthorizationAdvisor`s to those types as well,
   since Spring Security's proxy factory bean is given every advisor bean (decision 0077).
3. [`Proxies.frame`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/Proxies.java#L95) analyses each method entered,
   given which parameters hold proxies, to a least fixpoint: a local is a proxy only when every definition of it is
   one ([`Frame.returnedProxy`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/Proxies.java#L309): an
   `@AuthorizeReturnObject` method called through Spring's proxy, not on `this`, or on a proxy; a `proxy(..)` call;
   an element taken from a proxied container; a library wrapper around proxies such as `List.of` or
   `ResponseEntity.ok`; an application method that returns one).
   [`Frame.proxiedArguments`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/Proxies.java#L138) hands proxies on to
   the next call, including the lambdas a proxied stream or optional calls with its elements and the lambdas that
   capture a proxy.
4. Each proxy carries the factory that made it (decision 0088). Spring Security's proxies an
   `@AuthorizeReturnObject` method's result with any `@EnableMethodSecurity`, whatever its flags (7.1.1's
   `MethodSecuritySelector` always imports `AuthorizationProxyConfiguration`; found by `mutationTest`), and never
   with the legacy `@EnableGlobalMethodSecurity`.
   [`ProxyFactories.of`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProxyFactories.java#L135) follows the
   receiver of a `proxy(..)` call through locals, fields, injected parameters and helpers' returns, up to three
   deep: Spring Security's bean (`Factory.SPRING`, every advisor) or one the application builds (`withDefaults()`,
   `withReactiveDefaults()`, or `new AuthorizationAdvisorProxyFactory(list)` read by
   [`ProxyFactories.created`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProxyFactories.java#L246)). When it
   can't tell, the proxy runs only what every factory the application builds applies, and an OPAQUE_CONFIG finding
   says so.
5. On a built factory's proxy, [`MethodSecurity.onBuiltProxy`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L248)
   gives the check as Spring's default interceptor reads it (`ROLE_`, no RoleHierarchy, no advisor bean, an id ending
   `:built-factory`), or none when the factory has no interceptor for its annotation.
6. [`RequestPath.fieldChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1376) counts a
   field check, or any check of a proxy-only class, when the receiver is a proxy (`Frame.onProxy`), as its factory
   applies it; otherwise it raises [BYPASSED](#bypassed).
7. When the handler returns a proxy (`Frame.returned`),
   [`SpringSecurityModule.serialized`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1108)
   adds the field checks of its getters, in name order, and of the proxies its `@AuthorizeReturnObject` getters
   return, after the handler. `deniedValues` uses [`MethodSecurity.denialHandler`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L1196)
   to find a denial handler that hands out a value derived from the one it denied (a Masked flow).

**Relies on / relied on by.** It relies on [`METHOD_SECURITY`](features.md#method_security) and on
[`RESPONSE_FIELDS`](features.md#response_fields) for the property names;
[`ResponseFields.denied`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ResponseFields.java#L96) and the field lineage
rely on its checks ([fields.md](fields.md)).

**Tests.** [`FieldsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FieldsFixtureTests.java#L12),
[`ProxiesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ProxiesFixtureTests.java#L11),
[`ProxyFlowsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ProxyFlowsFixtureTests.java#L15),
[`BuiltProxiesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/BuiltProxiesFixtureTests.java#L18)
(fixtures [`builtproxies`](../../src/fixtures/java/fixtures/builtproxies/) and its siblings),
[`ProxyAdvisorsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ProxyAdvisorsFixtureTests.java#L19),
[`DenialsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DenialsFixtureTests.java#L23).

**Before changing it**

- A local is a proxy only when all its definitions are (decision 0014). Loosening that shows field checks on paths
  that read the raw object.
- A value that may come from two factories runs only what both apply ([`Factory.and`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProxyFactories.java#L89));
  Spring's bean is the identity there.
- A factory the application builds uses Spring's defaults, not the application's prefix, hierarchy or advisor beans
  (7.1.1). That is why built-factory checks are separate locations.
- `Proxies.frame` caches by method and proxied parameters; a method already being analysed (recursion) gets an
  unanalysed frame, so it returns no proxy.

## Custom decisions

Feature: [`CUSTOM_DECISIONS`](features.md#custom_decisions)

A check decided by application code names that code in its requirement's `decidedBy`
([`Requirement.custom`](../../scanner/src/main/java/dev/crain/authtracer/graph/Requirement.java#L116)) and, where the scan can
reduce the code's body, says what it asks for: `@authz.canRead(#id)`, whose method grants when the caller's
authorities contain `ROLE_ADMIN`, asks for `ROLE_ADMIN`, decided by `Authz#canRead`. Code it can't reduce stays
custom, with an OPAQUE_CONFIG finding listing the stores it reads and the services it calls; code that always grants
or always denies is a finding. A call the code makes itself to a manager's `verify(..)` or `authorize(..)` becomes a
check at the call.

**How it works**

1. One [`DecisionCode`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L54) per scan
   ([`DecisionCode.of`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L315)) indexes the
   application's beans by name. Everything that meets decision code goes through it:
   - SpEL: `SpelRequirements` hands `@bean.method(..)` to [`DecisionCode.beanCall`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L220),
     and a call to an expression handler's own root to [`DecisionCode.rootCall`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L244).
     A library bean's methods are read as what they build
     ([`DecisionCode.providedMethods`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L417):
     `@oauth2.hasScope('x')` is `SCOPE_x`, an `AuthorizationManagerFactory` bean's `hasRole` its prefix's role);
   - managers: [`DecisionCode.created`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L259) for a
     `new` of the application's class, [`DecisionCode.injected`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L279)
     for one handed in by type or name, [`DecisionCode.lambda`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L270)
     for a lambda. Callers are `MethodAdvisors` (an advisor's manager), `ProgrammaticChecks`, and, for the request,
     message and RSocket rules, [`SecurityDsl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L68),
     [`MessageSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSecurityRules.java#L55),
     [`RSocketSecurityRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/RSocketSecurityRules.java#L53) and
     [`XmlReferences`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/XmlReferences.java#L33) ([rules.md](rules.md));
   - `hasPermission(..)`: [`DecisionCode.permission`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L335)
     (step 4).
2. [`DecisionCode.decided`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L386) reads the method
   once with [`DecisionBodies.read`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionBodies.java#L180) and
   returns its requirement decided by it, or a custom requirement when it can't be reduced.
3. `DecisionBodies` (decision 0065) walks the method's control-flow graph one path at a time
   ([`DecisionBodies.walk`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionBodies.java#L223), at most 64
   paths and 4000 steps) with symbolic values: the Authentication from its `Supplier` or the `SecurityContextHolder`,
   the expression root's functions, the authorities' `contains`, Spring's built-in managers and their
   `AuthorizationDecision`. Each return that grants adds the conditions its path took; the method decides the `or` of
   those paths ([`DecisionBodies.combined`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionBodies.java#L508)).
   A throw denies; a `null` decision abstains, which 7.1.1's interceptors let through, so it reads as a grant. A try
   block, a loop, a switch or a condition on anything else leaves the method undecided.
   [`DecisionBodies.recordReads`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionBodies.java#L202) notes the
   repositories, JDBC and `EntityManager` calls and HTTP clients on any path, decided or not.
4. [`PermissionEvaluators.configured`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/PermissionEvaluators.java#L44)
   says whether pre/post `hasPermission(..)` reaches a `PermissionEvaluator` (decision 0038: with
   `@EnableMethodSecurity`, only a `MethodSecurityExpressionHandler` bean that is given one, or the application's own
   handler; with the legacy annotation, a `PermissionEvaluator` bean; in XML, the `<expression-handler>`'s), and
   [`PermissionEvaluators.evaluator`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/PermissionEvaluators.java#L91)
   which class. `Scan.hasPermission` then replaces each `hasPermission(..)` with what that class's three- or
   four-argument `hasPermission` decides ([`PermissionEvaluators.decided`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/PermissionEvaluators.java#L142)),
   or, with no evaluator, with a denial ([ALWAYS_DENIED](#always_denied-and-always_granted)).
5. Programmatic checks (decision 0066): [`RequestPath.onCallSite`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1514)
   asks [`ProgrammaticChecks.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProgrammaticChecks.java#L92)
   about each call. `verify(..)` or `authorize(..)` on an `AuthorizationManager` or `ReactiveAuthorizationManager`,
   outside a manager's own decision method, is a check: `authorize(..)` only when its result decides a branch whose
   ways leave the method differently ([`ProgrammaticChecks.gates`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProgrammaticChecks.java#L169)),
   a reactive `verify(..)` only when its `Mono` is kept; otherwise an UNRECOGNIZED_CHECK finding says the call
   checks nothing. [`ProgrammaticChecks.manager`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProgrammaticChecks.java#L212)
   follows the receiver to a `new`, a parameter or a field (what the constructor stores, else the bean of its type), or
   one of Spring's static factories ([`BuiltInManagers.factory`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/BuiltInManagers.java#L88),
   without RoleHierarchy unless the code gives it one). The location is `AuthorizationManager#verify` (or
   `#authorize`) at the call's line, not `proxied`. On another thread `RequestPath.offThread` turns it into a denial
   ([call-paths.md](call-paths.md)).
6. [`DecisionCode.report`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L128) runs from
   `Scan.run` once requirements are final: one OPAQUE_CONFIG finding per method it couldn't reduce, ALWAYS_GRANTED and
   ALWAYS_DENIED for code that comes to `permitAll` or `denyAll`, ALWAYS_DENIED for calls to a root the annotations
   never use, OPAQUE_CONFIG for a `@bean` no bean answers. A check whose code reads a store or another service is
   marked Live (SRC-14).
7. [`DecisionCode.deciders`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L398) gives `Scan`'s
   `decisionCalls` the decision methods, whose calls to other services become Egress right after the check (a remote
   authorization manager, OPA).

**Relies on / relied on by.** It relies on [`REQUIREMENTS`](features.md#requirements) (`SpelRequirements`,
`BuiltInManagers`, [`MultiFactor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MultiFactor.java#L43)) and on
[`SpringBeans.beanName`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringBeans.java#L162). Method security, the
request, message and RSocket rules, the ALWAYS_DENIED and ALWAYS_GRANTED findings, and
[`SERVICE_CALLS`](features.md#service_calls) (a decision's own calls) rely on it.

**Tests.** [`DecisionCodeFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DecisionCodeFixtureTests.java#L23)
(fixture [`decisioncode`](../../src/fixtures/java/fixtures/decisioncode/): every shape `DecisionBodies` reads or
leaves undecided), [`DecisionFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DecisionFormsFixtureTests.java#L23),
[`SpelBeansFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/SpelBeansFixtureTests.java#L18),
[`CustomManagersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/CustomManagersFixtureTests.java#L19),
[`ManagerBeansFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ManagerBeansFixtureTests.java#L16),
[`ProgrammaticChecksFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ProgrammaticChecksFixtureTests.java#L22),
[`PermissionEvaluatorFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/PermissionEvaluatorFixtureTests.java#L16),
[`PermissionEvaluatorsTests`](../../src/test/java/dev/crain/authtracer/scan/spring/PermissionEvaluatorsTests.java#L14),
[`ExpressionHandlersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ExpressionHandlersFixtureTests.java#L18).

**Before changing it**

- Code is reduced or left custom, never guessed: any branch `DecisionBodies` can't read throws `Undecided` and the
  whole method stays custom.
- `report` must run after `hierarchiesAndFactories` and `hasPermission` and before the splits are rebuilt: it reads
  the requirements as the graph finally shows them, and reports each decision method once, however many checks it
  decides.
- `recordReads` goes in statement order, not the graph's node order, so findings are the same every scan.
- Whether the RoleHierarchy widens a check depends on who built its manager. A programmatic check's custom code is
  widened (decision 0065), a manager from Spring's static factories isn't unless the code calls
  `setRoleHierarchy(..)` on it ([`ProgrammaticChecks.hierarchyAware`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProgrammaticChecks.java#L145));
  an advisor's custom manager is widened only when it is given the hierarchy (decision 0092).
- The cache in `DecisionCode.of` holds the scan and its `DecisionCode` only weakly; the `Scan` keeps its own for as
  long as it runs, so a finished scan's view can be collected.

## Structure rules

Feature: [`STRUCTURE_RULES`](features.md#structure_rules)

A company's own authorization library (an `@RequiresPermission` its aspect enforces, a `guard.require("orders.read")`
that throws) is code AuthTracer doesn't know. A rule in `authtracer.yaml` or the Org file (decision 0120) says what
its annotation or call asks for, as SpEL with the annotation's attributes or the call's arguments as placeholders,
and every use of it becomes an Authorization Location, the way `@PreAuthorize` and a manager's `verify(..)` do:

```yaml
rules:
  - annotation: com.acme.RequiresPermission       # on a method, or on its class
    requires: "hasAuthority('PERM_{value}')"      # {value}: the annotation's value, or its default
  - call: "com.acme.Guard#require"                 # or com.acme.Guard#require(java.lang.String) for one overload
    requires: "hasAuthority('PERM_{arg0}')"       # {arg0}: the call's first argument
    combine: any                                   # several values (an array, varargs): any (default) or all
```

**How it works**

1. [`ProvidedFacts.rules`](../../scanner/src/main/java/dev/crain/authtracer/provided/ProvidedFacts.java#L173) reads each
   rule as a `RULE` fact whose subject is `annotation <class>` or `call <class>#<method>`, with `[all]` as its labels
   for `combine: all`. Rules compete as other facts do: the Org's beats the service's for one subject.
2. [`StructureRules`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/StructureRules.java#L50) holds the scan's rules. `MethodSecurity` and `ProgrammaticChecks`
   each make one.
3. Annotation rules: [`MethodSecurity`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L56) looks for each rule's annotation as it does for
   Spring's (on the method, then its class) and adds
   [`StructureRules.annotated`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/StructureRules.java#L82) before the method's other checks. The location is
   `location:METHOD:<method>:rule:@<Annotation>`, proxied unless the application weaves its aspects, so a call that
   skips the proxy skips it ([BYPASSED](#bypassed)) as it skips `@PreAuthorize`.
4. Call rules: [`ProgrammaticChecks.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProgrammaticChecks.java#L92) asks
   [`StructureRules.call`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/StructureRules.java#L103) first, for a call to the rule's method or to one overriding it
   (`SpringBeans.assignable`). The location is at the call, `location:METHOD:<caller>:rule:<Class>#<method>@<line>`.
   An argument is read when it is a string or int constant, a local set to one, an enum constant (by its name), or
   a varargs array of those.
5. [`StructureRules.requirement`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/StructureRules.java#L207) fills the placeholders and parses the SpEL with
   `SpelRequirements`, so `hasRole`, `hasAuthority` and `@bean.method(..)` read as they do in `@PreAuthorize`. A
   placeholder with several values gives one requirement per value, joined by `or` (or `and` with `combine: all`).
   One it can't read (an argument built at run time) leaves the requirement `<subject> (?)`, an expression, with an
   OPAQUE_CONFIG finding naming the placeholder.
6. The method a call rule matches is the library's check: [`ProgrammaticChecks.checks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProgrammaticChecks.java#L153)
   says so, and [Hand-rolled checks](#hand-rolled-checks) leaves it out. Inside it, no call adds a check (one
   overload calling another would otherwise be a second, opaque one): the rule stands for what it calls. A rule that matches nothing is an
   OPAQUE_CONFIG finding (`ApplicationScanner.unmatchedFacts`), so a mistyped class name isn't silently a check
   that never runs.

**Relies on / relied on by.** It relies on [`PROVIDED_FACTS`](features.md#provided_facts) for the file,
[`REQUIREMENTS`](features.md#requirements) for the SpEL, and [`CALL_PATHS`](features.md#call_paths) for the calls a
request reaches. Exposures, the diff and policies read its locations as they read any other.

**Tests.** [`StructureRulesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/StructureRulesFixtureTests.java#L25)
(fixture [`customlibrary`](../../src/fixtures/java/fixtures/customlibrary/), with its own
[`authtracer.yaml`](../../src/fixtures/resources/customlibrary/authtracer.yaml), which `FixtureScans.scan` loads),
[`ProvidedFactsTests.readsRulesAndRejectsOnesThatDontSayWhatTheyMatchOrRequire`](../../src/test/java/dev/crain/authtracer/provided/ProvidedFactsTests.java#L309).
The conformance harness (`./gradlew conformanceTest -Pfixtures=customlibrary`) runs the fixture's aspect and guard
under Spring and agrees with every rule's check.

**Before changing it**

- A rule describes what the library asks for; AuthTracer doesn't read the library's code to check it. The fixture's
  aspect is there so the conformance harness can show the rule and the code agree.
- The code that enforces an annotation rule (an aspect, a `HandlerInterceptor` reading the annotation) is not left
  out of hand-rolled checks: an interceptor the walk enters can still be reported as one.
- An unread placeholder makes the check opaque, never a guess at a weaker requirement.

## Hand-rolled checks

Feature: [`FINDING_UNRECOGNIZED_CHECK`](features.md#finding_unrecognized_check)

An UNRECOGNIZED_CHECK finding for each method a request reaches that reads who the caller is and denies by itself. It
is not a location: the path counts as no authorization there until the code moves to a recognized mechanism or a
person declares it reviewed with a Provided `CHECK` fact, which [`MethodSecurity.providedCheck`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L875)
turns into a location.

**How it works**

1. [`Scan.handRolledChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L873) runs last
   in `Scan.run`, over every method a path entered, leaving out the methods with a Provided `CHECK` fact and those that
   check with a manager ([`ProgrammaticChecks.checks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProgrammaticChecks.java#L153)).
2. [`HandRolledChecks.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HandRolledChecks.java#L148) reads a
   method together with the lambdas it creates ([`HandRolledChecks.unit`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HandRolledChecks.java#L211)),
   so reactive code that signals its error in a lambda counts. When the method alone isn't a check, its evidence is
   joined with its helpers' ([`HandRolledChecks.helpers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HandRolledChecks.java#L245):
   its own class's methods called on `this`, and the application's static methods), unless a helper is a check by
   itself, which is then reported on its own.
3. [`HandRolledChecks.read`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HandRolledChecks.java#L284) collects the
   reads (the `IDENTITY` calls such as `SecurityContext.getAuthentication()`, `Jwt.getClaim(..)`,
   `HttpServletRequest.isUserInRole(..)`; a header named like a credential; a used `@AuthenticationPrincipal` or
   `@CurrentSecurityContext` parameter) and the denials ([`HandRolledChecks.denial`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HandRolledChecks.java#L348):
   a thrown `AccessDeniedException` or `AuthenticationException`, an exception with `@ResponseStatus(FORBIDDEN)`, a
   status exception made with 401 or 403, an exception named for a denial; `Mono.error(..)` or `Flux.error(..)` of
   one; a response given status 401 or 403).
4. Both are needed. [`HandRolledChecks.finding`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HandRolledChecks.java#L183)
   names what it reads and how it denies, at the first denial's line.
5. [`ProgrammaticChecks.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProgrammaticChecks.java#L92) raises
   the same kind on the walk for a manager asked in a way that denies nothing: an `authorize(..)` whose answer no
   branch reads, a reactive `verify(..)` whose `Mono` is dropped ([Custom decisions](#custom-decisions), step 5).

**Relies on / relied on by.** It relies on [`CALL_PATHS`](features.md#call_paths) for the methods requests reach, and
on [`PROVIDED_FACTS`](features.md#provided_facts) for the checks people reviewed. The filters and interceptors a request
passes are walked into the same set of methods, so their hand-rolled checks are found too ([call-paths.md](call-paths.md)).

**Tests.** [`HandRolledFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/HandRolledFixtureTests.java#L15),
[`HandRolledFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/HandRolledFormsFixtureTests.java#L15),
[`HandRolledHelpersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/HandRolledHelpersFixtureTests.java#L15),
[`HandRolledCornersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/HandRolledCornersFixtureTests.java#L15),
[`HandRolledReactiveFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/HandRolledReactiveFixtureTests.java#L15),
[`ProgrammaticChecksFixtureTests.whatTheCodeReadsOfTheCallerToCheckWithAManagerIsNoHandRolledCheck`](../../src/test/java/dev/crain/authtracer/scan/spring/ProgrammaticChecksFixtureTests.java#L94),
[`ProvidedFactsScanTests`](../../src/test/java/dev/crain/authtracer/provided/ProvidedFactsScanTests.java#L21).

**Before changing it**

- A read without a denial (logging the user) or a denial without a read (a 404, hiding a value) is no check; the
  corner tests pin both.
- Another bean's denial is that bean's check, not its caller's: only `this` calls and static helpers join.

## NOT_ENFORCED

Feature: [`FINDING_NOT_ENFORCED`](features.md#finding_not_enforced)

Raised for a check that looks enforced but that nothing runs. Here, by:

| Where | When |
|---|---|
| [`MethodSecurity.notEnforcedReason`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L887), raised in `detect` | No method security, or its flag for the annotation is off (`prePostEnabled = false`, `@Secured` without `securedEnabled`, JSR-250 without `jsr250Enabled`, not pre/post under reactive method security), unless an advisor bean or a factory the application builds runs it; the class is no bean and no `@AuthorizeReturnObject` type; the method is private, final or static. In AspectJ mode a woven check skips the last two, an unwoven one may never run, and JSR-250's never run |
| [`MethodAdvisors.add`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodAdvisors.java#L260) | An advisor bean no auto-proxy creator applies |
| The [`CustomAdvisors`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/CustomAdvisors.java#L42) constructor | An `AuthorizationAdvisor` bean with neither an auto-proxy creator nor a proxy factory |
| [`ExpressionHandlers.root`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ExpressionHandlers.java#L169) | A handler that makes its root in `createSecurityExpressionRoot`, which `@EnableMethodSecurity` never calls |

Tests: [`NoMethodSecurityFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/NoMethodSecurityFixtureTests.java#L12),
[`OrdersFixtureTests.annotationsThatNeverRunAreFindingsNotLocations`](../../src/test/java/dev/crain/authtracer/scan/spring/OrdersFixtureTests.java#L78),
[`MethodFormsFixtureTests.theProxyCantInterceptAFinalOrStaticMethod`](../../src/test/java/dev/crain/authtracer/scan/spring/MethodFormsFixtureTests.java#L35),
[`ReactiveMethodsFixtureTests.securedNeverRunsUnderReactiveMethodSecurity`](../../src/test/java/dev/crain/authtracer/scan/spring/ReactiveMethodsFixtureTests.java#L24),
[`AdvisorProxyingFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/AdvisorProxyingFixtureTests.java#L18).

## BYPASSED

Feature: [`FINDING_BYPASSED`](features.md#finding_bypassed)

The method-security BYPASSED findings are raised by `SpringSecurityModule`'s
[`RequestPath.bypassed`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L1485) from what this
page's classes say: in `enter`, for every `proxied` check, pre or post, of a method called on `this` ("is skipped
when X calls it on this"), and in `fieldChecks`, for a field check read on an object that is no authorization proxy,
or on one from a factory without that check's interceptor. The same walk raises the BYPASSED findings of branches and
dispatch ([call-paths.md](call-paths.md)).

Tests: [`OrdersFixtureTests.selfInvocationSkipsTheProxy`](../../src/test/java/dev/crain/authtracer/scan/spring/OrdersFixtureTests.java#L71),
[`FieldsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FieldsFixtureTests.java#L12),
[`BuiltProxiesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/BuiltProxiesFixtureTests.java#L18),
[`ProxyFlowsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ProxyFlowsFixtureTests.java#L15),
[`GroovyFixtureTests.aClosureCallingItsOwnerSkipsTheProxy`](../../src/test/java/dev/crain/authtracer/scan/spring/GroovyFixtureTests.java#L103).

## CHECK_AFTER_COMMIT

Feature: [`FINDING_CHECK_AFTER_COMMIT`](features.md#finding_check_after_commit)

[`MethodSecurity.afterCommit`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L849): on a bean
method that is `@Transactional` and writes (Spring's annotation without `readOnly`, or Jakarta's), a post check whose
interceptor order is lower than the transaction advice's wraps the transaction, so it decides after the commit. The
transaction's order is `LOWEST_PRECEDENCE` unless `@EnableTransactionManagement(order)` says otherwise; method
security's orders come from step 4 of [Method security](#method-security).

Tests: [`AdvisorsFixtureTests.aPostCheckOutsideTheTransactionDecidesAfterTheCommit`](../../src/test/java/dev/crain/authtracer/scan/spring/AdvisorsFixtureTests.java#L67)
(fixtures [`transactions`](../../src/fixtures/java/fixtures/transactions/) and
[`transactionsinside`](../../src/fixtures/java/fixtures/transactionsinside/)),
[`MethodFormsFixtureTests.aPostCheckOrderedBeforeTheTransactionDecidesAfterItsCommit`](../../src/test/java/dev/crain/authtracer/scan/spring/MethodFormsFixtureTests.java#L67).

## ALWAYS_DENIED and ALWAYS_GRANTED

Features: [`FINDING_ALWAYS_DENIED`](features.md#finding_always_denied), [`FINDING_ALWAYS_GRANTED`](features.md#finding_always_granted)

| Where | Raised for |
|---|---|
| [`Scan.hasPermission`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L840), from [`MethodSecurity.permissionsDenied`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L273) and [`PermissionEvaluators.denied`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/PermissionEvaluators.java#L202) | `hasPermission(..)` with no evaluator: denied; its negation admits everyone (ALWAYS_GRANTED) |
| [`DecisionCode.report`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L128) | Decision code that always grants or always denies; a call to an expression handler's root the annotations never use |
| The [`XmlMethodChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/XmlMethodChecks.java#L45) constructor | A `<protect method="...">` with a qualified name, which 7.1.1's `PrefixBasedMethodMatcher` never matches |
| `RequestPath.offThread`, for a programmatic check | A manager asked on a thread without the caller's SecurityContext |

Tests: [`PermissionEvaluatorFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/PermissionEvaluatorFixtureTests.java#L16),
[`DecisionCodeFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DecisionCodeFixtureTests.java#L23),
[`ExpressionHandlersFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ExpressionHandlersFixtureTests.java#L18),
[`XmlMethodsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/XmlMethodsFixtureTests.java#L18),
[`ProgrammaticChecksFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ProgrammaticChecksFixtureTests.java#L22).

## OPAQUE_CONFIG

Feature: [`FINDING_OPAQUE_CONFIG`](features.md#finding_opaque_config)

What this page's classes can't read is shown, never guessed: the check stays custom or absent, and an OPAQUE_CONFIG
finding says which.

| Where | Can't read |
|---|---|
| [`MethodSecurity.read`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L1141) | `#name` in an expression when Spring finds no parameter of that name |
| [`MethodSecurity.queryFilter`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L582) | A `@Query` that reads the caller without a `SecurityEvaluationContextExtension` bean |
| [`MethodSecurity.targetVisitors`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L511), [`MethodSecurity.proxyAdvisors`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L552) | A custom `TargetVisitor`; advisors set on or added to the proxy factory |
| [`ProxyFactories.of`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProxyFactories.java#L135), [`ProxyFactories.created`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProxyFactories.java#L246) | Which factory proxies an object; interceptors a built factory lists |
| The [`MethodAdvisors`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodAdvisors.java#L51) constructor, `add` | An advisor bean, its manager, or its pointcut |
| The [`CustomAdvisors`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/CustomAdvisors.java#L42) constructor | Every `AuthorizationAdvisor`'s advice, and a pointcut outside the subset |
| The [`XmlMethodChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/XmlMethodChecks.java#L45) constructor | A `<protect-pointcut>`, an `authorization-manager-ref` |
| [`ExpressionHandlers.opaque`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ExpressionHandlers.java#L286), `root` | A prefix, factory or trust resolver the handler bean is given; its own evaluation context |
| [`ProgrammaticChecks.detect`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProgrammaticChecks.java#L92) | The manager a `verify(..)` is called on |
| [`DecisionCode.report`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L128) | Decision code that can't be reduced; a `@bean` no bean answers |

## Files

All under [`scan/spring`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/).

| File | Role | Features |
|---|---|---|
| [`MethodSecurity`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodSecurity.java#L56) | Finds the method annotations, decides whether each runs, and keeps every method's checks in order | METHOD_SECURITY, FIELD_CHECKS |
| [`Proxies`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/Proxies.java#L48) | Which values on a path are authorization proxies, and which factory made each | FIELD_CHECKS, METHOD_SECURITY |
| [`ProxyFactories`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProxyFactories.java#L49) | The factory a `proxy(..)` call is made on, and the interceptors it applies | FIELD_CHECKS, METHOD_SECURITY |
| [`MethodAdvisors`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MethodAdvisors.java#L51) | Advisor beans built from Spring's interceptors: annotations turned on, custom managers, pointcuts, orders | METHOD_SECURITY |
| [`CustomAdvisors`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/CustomAdvisors.java#L42) | The application's own `AuthorizationAdvisor` beans | METHOD_SECURITY, FIELD_CHECKS |
| [`Pointcuts`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/Pointcuts.java#L25) | The subset of AspectJ pointcut expressions advisors use, read without AspectJ | METHOD_SECURITY |
| [`AutoProxyCreators`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/AutoProxyCreators.java#L15) | Whether Boot's or AspectJ's auto-proxy creator applies advisor beans | METHOD_SECURITY |
| [`XmlMethodChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/XmlMethodChecks.java#L45) | The XML namespace's method checks: `<protect-pointcut>`, `<intercept-methods>` | METHOD_SECURITY |
| [`ExpressionHandlers`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ExpressionHandlers.java#L36) | A `MethodSecurityExpressionHandler` bean's prefix, hierarchy, factory and root | METHOD_SECURITY, REQUIREMENTS |
| [`PermissionEvaluators`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/PermissionEvaluators.java#L32) | Whether and how `hasPermission(..)` reaches an evaluator | CUSTOM_DECISIONS |
| [`DecisionCode`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionCode.java#L54) | Resolves the application code that decides a check, and reports on it | CUSTOM_DECISIONS |
| [`DecisionBodies`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/DecisionBodies.java#L54) | Reads a decision method's body, path by path, into a requirement | CUSTOM_DECISIONS |
| [`ProgrammaticChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProgrammaticChecks.java#L56) | `verify(..)` and `authorize(..)` calls the code makes itself | CUSTOM_DECISIONS |
| [`HandRolledChecks`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HandRolledChecks.java#L52) | Code that reads the caller and denies outside every mechanism | FINDING_UNRECOGNIZED_CHECK |

Methods carry their own tags where they serve more: each method that raises a finding names its kind
(`MethodSecurity.detect`, `MethodAdvisors.add`, `DecisionCode.report`, ...), `MethodSecurity.providedCheck` names
`PROVIDED_FACTS`, `MethodSecurity.denialHandler` `FIELD_LINEAGE`, and `DecisionCode.deciders` `SERVICE_CALLS`.
