package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.springframework.util.AntPathMatcher;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.expr.JNewArrayExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0045 (RX-13): Spring Security's authorization of RSocket exchanges (7.1.1). With
 * {@code @EnableRSocketSecurity} (Spring Boot's {@code RSocketSecurityAutoConfiguration} has it), a
 * {@code PayloadSocketAcceptorInterceptor} bean built from {@code RSocketSecurity} decides each exchange, or, without
 * one, {@code SecuritySocketAcceptorInterceptorConfiguration}'s default: {@code setup().authenticated()},
 * {@code anyRequest().authenticated()}, everything else permitted. {@code authorizePayload} rules are tried in order,
 * first match wins, and no match is denied ({@code PayloadExchangeMatcherReactiveAuthorizationManager}). A bean that
 * doesn't call {@code authorizePayload} authorizes nothing. A request passes the rule for its connection's
 * {@code SETUP} frame, then the one for the request: {@code route(..)} patterns are matched against the route with
 * {@code .} separating segments, as {@code RSocketMessageHandler}'s default route matcher does. Its {@code hasRole}
 * is {@code AuthorityReactiveAuthorizationManager}'s: {@code ROLE_} and no role hierarchy.
 */
@Supports(Feature.REQUEST_RULES)
final class RSocketSecurityRules {

    static final String MECHANISM = "authorizePayload (RSocket)";
    private static final String ENABLE = "org.springframework.security.config.annotation.rsocket.EnableRSocketSecurity";
    private static final String BOOT_AUTO_CONFIGURATION =
            "org.springframework.boot.security.autoconfigure.rsocket.RSocketSecurityAutoConfiguration";
    private static final String INTERCEPTOR = "org.springframework.security.rsocket.core.PayloadSocketAcceptorInterceptor";
    private static final String SECURITY = "org.springframework.security.config.annotation.rsocket.RSocketSecurity";
    private static final String SPEC = SECURITY + "$AuthorizePayloadsSpec";
    private static final String ACCESS = SPEC + "$Access";
    private static final String DEFAULTS =
            "org.springframework.security.config.annotation.rsocket.SecuritySocketAcceptorInterceptorConfiguration";
    private static final SpelRequirements ROLES = new SpelRequirements("ROLE_");
    private static final AntPathMatcher ROUTES = new AntPathMatcher(".");

    /**
     * What a rule's matcher matches: the connection's {@code SETUP} frame, any request, any exchange, a route, or a
     * {@code PayloadExchangeMatcher} that can't be evaluated statically (it never matches).
     */
    enum Kind {
        SETUP, REQUEST, ANY, ROUTE, CUSTOM
    }

    record Rule(Kind kind, String route, String label, Requirement requirement, Integer line) {

        boolean matches(boolean setup, String requestRoute) {
            return switch (kind) {
                case SETUP -> setup;
                case REQUEST -> !setup;
                case ANY -> true;
                case ROUTE -> !setup && ROUTES.match(route, requestRoute.replaceAll("\\{[^}]*}", "x"));
                case CUSTOM -> false;
            };
        }
    }

    /**
     * @param authorizes whether {@code authorizePayload} decides the exchanges, with rules AuthTracer read: then an
     *        exchange no rule matches is denied
     */
    private record Rules(CodeRef declaredIn, String key, List<Rule> rules, boolean authorizes) {
    }

    private record Security() {
    }

    /**
     * The rules an {@code authorizePayload} spec is given, and whether one of its customizers couldn't be read.
     */
    private static final class Spec {

        private final List<Rule> rules = new ArrayList<>();
        private boolean unreadable;

        List<Rule> rules() {
            return rules;
        }
    }

    private record Access(Spec spec, Kind kind, String route, String label) {
    }

    private record Lambda(MethodSignature target, List<Object> captured) {
    }

    private record Manager(Requirement requirement) {
    }

    /**
     * An array being filled, for varargs such as {@code hasAnyRole("ADMIN", "OPS")}: its constants, its managers,
     * and how many elements are neither.
     */
    private record Strings(List<String> values, List<Requirement> managers, int[] unread) {

        Strings() {
            this(new ArrayList<>(), new ArrayList<>(), new int[1]);
        }
    }

    private final ScanContext context;
    private final GraphBuilder graph;
    private final Optional<Rules> rules;
    private final Set<String> reported = new HashSet<>();

    RSocketSecurityRules(ScanContext context, GraphBuilder graph) {
        this.context = context;
        this.graph = graph;
        this.rules = detect();
    }

    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private Optional<Rules> detect() {
        boolean boot = context.findClass(BOOT_AUTO_CONFIGURATION).isPresent() && context.findClass(INTERCEPTOR)
                .isPresent() && context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION);
        if (!boot && !context.anyClassAnnotated(ENABLE)) {
            return Optional.empty();
        }
        for (JavaSootMethod method : SpringBeans.beanMethods(context, INTERCEPTOR)) {
            if (method.hasBody()) {
                Spec spec = new Spec();
                boolean authorizes = interpret(method, Map.of(), spec);
                if (authorizes && spec.unreadable) {
                    graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The PayloadSocketAcceptorInterceptor"
                            + " bean " + MethodNames.key(method.getSignature()) + " authorizes payloads with a"
                            + " customizer AuthTracer can't read: its RSocket rules are one opaque requirement",
                            MethodNames.codeRef(method.getSignature())));
                    // Its rules are unknown, not absent: every frame gets one AuthTracer can't read.
                    return Optional.of(new Rules(MethodNames.codeRef(method.getSignature()),
                            MethodNames.key(method.getSignature()), List.of(new Rule(Kind.ANY, null,
                                    "authorizePayload(customizer)", Requirement.expression(
                                            "authorizePayload(customizer)"), null)), true));
                }
                // Without authorizePayload(..), the interceptor only authenticates.
                return Optional.of(new Rules(MethodNames.codeRef(method.getSignature()),
                        MethodNames.key(method.getSignature()), authorizes ? spec.rules() : List.of(),
                        authorizes));
            }
        }
        return Optional.of(new Rules(CodeRef.ofClass(DEFAULTS), DEFAULTS, List.of(
                new Rule(Kind.SETUP, null, "setup()", Requirement.authenticated(), null),
                new Rule(Kind.REQUEST, null, "anyRequest()", Requirement.authenticated(), null),
                new Rule(Kind.ANY, null, "matcher(any exchange)", Requirement.permitAll(), null)), true));
    }

    /**
     * Reads a method's (or a lambda's) calls on {@code RSocketSecurity} and the spec, adding the rules to
     * {@code spec}; true when it calls {@code authorizePayload}.
     */
    private boolean interpret(JavaSootMethod method, Map<Integer, Object> parameters, Spec spec) {
        Map<Local, Object> values = new HashMap<>();
        boolean authorizes = false;
        for (Stmt stmt : method.getBody().getStmts()) {
            Integer line = stmt.getPositionInfo().getStmtPosition().getFirstLine();
            Value right = stmt instanceof AbstractDefinitionStmt definition ? definition.getRightOp()
                    : Locals.invoke(stmt).orElse(null);
            if (right == null) {
                continue;
            }
            if (right instanceof AbstractInstanceInvokeExpr invoke && invoke.getMethodSignature().getName()
                    .equals("authorizePayload") && values.get(invoke.getBase()) instanceof Security
                    && invoke.getArgCount() == 1) {
                authorizes = true;
                Optional<Lambda> customizer = value(invoke.getArg(0), values) instanceof Lambda lambda
                        ? Optional.of(lambda) : Optional.empty();
                Optional<JavaSootMethod> read = customizer.flatMap(lambda -> context.findMethod(lambda.target()))
                        .filter(JavaSootMethod::hasBody);
                // A customizer passed in (a bean, a field) holds rules AuthTracer doesn't see.
                spec.unreadable |= read.isEmpty();
                read.ifPresent(body -> {
                    Lambda lambda = customizer.get();
                    // A lambda that captures this is an instance method: the captured this is its receiver, not a
                    // parameter. The spec is its last parameter; unknown captured values are left to their types.
                    Map<Integer, Object> arguments = new HashMap<>();
                    int offset = body.isStatic() ? 0 : 1;
                    for (int i = offset; i < lambda.captured().size(); i++) {
                        if (lambda.captured().get(i) != null) {
                            arguments.put(i - offset, lambda.captured().get(i));
                        }
                    }
                    arguments.put(body.getParameterCount() - 1, spec);
                    interpret(body, arguments, spec);
                });
            }
            if (stmt instanceof AbstractDefinitionStmt definition && definition.getLeftOp() instanceof JArrayRef element
                    && values.get(element.getBase()) instanceof Strings array) {
                if (definition.getRightOp() instanceof StringConstant text) {
                    array.values().add(text.getValue());
                }
                else if (value(definition.getRightOp() instanceof Local local ? local : null, values)
                        instanceof Manager manager) {
                    array.managers().add(manager.requirement());
                }
                else {
                    array.unread()[0]++;
                }
                continue;
            }
            Object value = right instanceof JNewArrayExpr ? new Strings()
                    : evaluate(method, right, values, parameters, spec, line);
            if (stmt instanceof AbstractDefinitionStmt definition && definition.getLeftOp() instanceof Local local
                    && value != null) {
                values.put(local, value);
            }
        }
        return authorizes;
    }

    private static Object value(Immediate value, Map<Local, Object> values) {
        return value instanceof Local local ? values.get(local) : null;
    }

    @Supports(Feature.CUSTOM_DECISIONS)
    private Object evaluate(JavaSootMethod method, Value right, Map<Local, Object> values,
            Map<Integer, Object> parameters, Spec spec, Integer line) {
        if (right instanceof JParameterRef parameter) {
            if (parameters.containsKey(parameter.getIndex())) {
                return parameters.get(parameter.getIndex());
            }
            String type = method.getParameterType(parameter.getIndex()).toString();
            return type.equals(SECURITY) ? new Security() : type.equals(SPEC) ? spec : null;
        }
        if (right instanceof Local local) {
            return values.get(local);
        }
        if (right instanceof JDynamicInvokeExpr dynamic) {
            for (Value argument : dynamic.getBootstrapArgs()) {
                if (argument instanceof MethodHandle handle
                        && handle.getReferenceSignature() instanceof MethodSignature target
                        && context.isApplication(target.getDeclClassType())) {
                    return new Lambda(target, dynamic.getArgs().stream().map(arg -> value(arg, values)).toList());
                }
            }
            return null;
        }
        if (!(right instanceof AbstractInvokeExpr invoke)) {
            return null;
        }
        String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = invoke.getMethodSignature().getName();
        List<String> texts = new ArrayList<>();
        for (Immediate arg : invoke.getArgs()) {
            if (arg instanceof StringConstant constant) {
                texts.add(constant.getValue());
            }
            else if (arg instanceof Local local && values.get(local) instanceof Strings array) {
                texts.addAll(array.values());
            }
        }
        List<BuiltInManagers.Arg> args = managerArgs(invoke, values);
        if (!(invoke instanceof AbstractInstanceInvokeExpr instance)) {
            return BuiltInManagers.factory(owner, name, invoke.getMethodSignature().getParameterTypes().stream()
                    .map(Object::toString).toList(), args).map(Manager::new).orElse(null);
        }
        Object receiver = values.get(instance.getBase());
        if (receiver instanceof Security) {
            return receiver;
        }
        if (receiver instanceof Spec found && owner.equals(SPEC)) {
            return switch (name) {
                case "setup" -> new Access(found, Kind.SETUP, null, "setup()");
                case "anyRequest" -> new Access(found, Kind.REQUEST, null, "anyRequest()");
                case "anyExchange" -> new Access(found, Kind.ANY, null, "anyExchange()");
                case "route" -> texts.isEmpty() ? new Access(found, Kind.CUSTOM, null, "route(?)")
                        : new Access(found, Kind.ROUTE, texts.getFirst(), "route(" + texts.getFirst() + ")");
                case "matcher" -> new Access(found, Kind.CUSTOM, null, "matcher(PayloadExchangeMatcher)");
                default -> null;
            };
        }
        if (receiver instanceof Access access && owner.equals(ACCESS)) {
            // Decision 0063: the Access methods are AuthorityReactiveAuthorizationManager's; a role that isn't a
            // constant is shown as unread.
            Requirement requirement = switch (name) {
                case "access" -> invoke.getArgCount() != 1 ? null : switch (value(invoke.getArg(0), values)) {
                    case Manager manager -> manager.requirement();
                    // Decision 0064: a lambda decides the exchanges it is given.
                    case Lambda lambda when DecisionCode.isManagerLambda(lambda.target()) -> DecisionCode.of(context)
                            .lambda(lambda.target(), "access(" + lambda.target().getName() + ")");
                    case null, default -> Requirement.expression("access(ReactiveAuthorizationManager)");
                };
                case "hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority" -> BuiltInManagers.named(name, args,
                        ROLES).orElse(Requirement.expression(name + "(?)"));
                default -> BuiltInManagers.named(name, args, ROLES).orElse(null);
            };
            if (requirement != null) {
                access.spec().rules().add(new Rule(access.kind(), access.route(), access.label(), requirement, line));
            }
            return access.spec();
        }
        return null;
    }

    /**
     * RX-02: the arguments of a call to one of Spring Security's managers, e.g.
     * {@code AuthorityReactiveAuthorizationManager.hasRole("ADMIN")}, as the built-in managers' table reads them.
     */
    private static List<BuiltInManagers.Arg> managerArgs(AbstractInvokeExpr invoke, Map<Local, Object> values) {
        List<BuiltInManagers.Arg> args = new ArrayList<>();
        for (Immediate arg : invoke.getArgs()) {
            Object value = value(arg, values);
            args.add(arg instanceof StringConstant constant ? new BuiltInManagers.Text(constant.getValue())
                    : value instanceof Strings array && !array.managers().isEmpty()
                            ? new BuiltInManagers.Managers(array.managers(), array.unread()[0] == 0
                                    && array.values().isEmpty())
                            : value instanceof Strings array ? new BuiltInManagers.Texts(array.values(),
                                    array.unread()[0] == 0)
                                    : value instanceof Manager manager
                                            ? new BuiltInManagers.Manager(manager.requirement())
                                            : BuiltInManagers.UNKNOWN);
        }
        return args;
    }

    /**
     * The rule for the connection's {@code SETUP} frame, then the one for the request; the denial where none matches.
     */
    List<AuthorizationLocation> locationsFor(Ingress ingress) {
        // An authorizePayload with no rules denies everything; without one, or with rules AuthTracer can't read,
        // the graph has no RSocket check.
        if (rules.isEmpty() || rules.get().rules().isEmpty() && !rules.get().authorizes()) {
            return List.of();
        }
        List<AuthorizationLocation> locations = new ArrayList<>();
        locations.add(location(true, null));
        AuthorizationLocation request = location(false, ingress.route());
        if (!request.id().equals(locations.getFirst().id())) {
            locations.add(request);
        }
        return locations;
    }

    private AuthorizationLocation location(boolean setup, String route) {
        List<Rule> found = rules.get().rules();
        List<AuthorizationLocation> maybe = new ArrayList<>();
        for (int i = 0; i < found.size(); i++) {
            Rule rule = found.get(i);
            if (rule.matches(setup, route)) {
                return maybeFirst(maybe, ruleLocation(i, rule));
            }
            // Decision 0051: a PayloadExchangeMatcher AuthTracer can't evaluate may match first.
            if (rule.kind() == Kind.CUSTOM) {
                maybe.add(ruleLocation(i, rule));
            }
        }
        String what = setup ? "setup" : "request";
        return maybeFirst(maybe, graph.node(new AuthorizationLocation("location:HTTP_REQUEST:" + rules.get().key()
                + ":rsocket:denied:" + what, MECHANISM + " (no rule matched the " + what + ": denied)",
                AuthorizationLocation.Scope.HTTP_REQUEST, AuthorizationLocation.Phase.PRE, Requirement.denyAll(),
                rules.get().declaredIn(), null, null, AuthorizationLocation.Denial.THROW, false)));
    }

    private AuthorizationLocation ruleLocation(int index, Rule rule) {
        return graph.node(new AuthorizationLocation("location:HTTP_REQUEST:" + rules.get().key() + ":rsocket:" + index
                + ":" + rule.label(), MECHANISM, AuthorizationLocation.Scope.HTTP_REQUEST,
                AuthorizationLocation.Phase.PRE, rule.requirement(), rules.get().declaredIn().atLine(rule.line()), null,
                rule.label(), AuthorizationLocation.Denial.THROW, false));
    }

    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private AuthorizationLocation maybeFirst(List<AuthorizationLocation> maybe, AuthorizationLocation matched) {
        if (maybe.isEmpty()) {
            return matched;
        }
        maybe.stream().filter(location -> reported.add(location.id())).forEach(location -> graph.finding(new Finding(
                Finding.Kind.OPAQUE_CONFIG, "The RSocket rule " + location.routePattern() + " uses a"
                        + " PayloadExchangeMatcher AuthTracer can't evaluate: the exchanges it matches get it instead"
                        + " of the rules after it", location.target())));
        List<AuthorizationLocation> alternatives = new ArrayList<>(maybe);
        alternatives.add(matched);
        List<Requirement> requirements = alternatives.stream().map(AuthorizationLocation::requirement).distinct()
                .toList();
        return graph.node(new AuthorizationLocation("location:SPLIT:" + matched.id() + ":or:" + maybe.stream()
                .map(AuthorizationLocation::routePattern).toList(), MECHANISM + " (a matcher may match first)",
                AuthorizationLocation.Scope.HTTP_REQUEST, AuthorizationLocation.Phase.PRE,
                requirements.size() == 1 ? requirements.getFirst() : Requirement.or(requirements), matched.target(),
                null, String.join(" or ", alternatives.stream().map(location -> location.routePattern() == null
                        ? "default" : location.routePattern()).toList()), AuthorizationLocation.Denial.THROW, false));
    }
}
