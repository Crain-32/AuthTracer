package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0063 (SRC-11): who a caller who hasn't signed in is. A Servlet chain authenticates them anonymously unless
 * told not to (7.1.1 {@code HttpSecurityConfiguration} calls {@code anonymous(withDefaults())}): an
 * {@code AnonymousAuthenticationToken} with {@code ROLE_ANONYMOUS}, or the authorities
 * {@code anonymous(a -> a.authorities(..))} gives it. WebFlux does only when {@code ServerHttpSecurity.anonymous(..)}
 * is called. The token is the request's Authentication for every check on its path, method checks included, so a role
 * check whose roles it holds admits anyone. With anonymous authentication disabled there is no Authentication at all:
 * {@code AuthorizationFilter} answers a caller who hasn't signed in with an
 * {@code AuthenticationCredentialsNotFoundException}, so {@code anonymous()} admits no one.
 *
 * @param enabled whether callers who haven't signed in get the anonymous token
 * @param authorities what the token holds
 * @param custom where the application sets other authorities than {@code ROLE_ANONYMOUS}, else {@code null}
 * @param disabledAt where the application turns it off, if it does
 */
@Supports(Feature.REQUIREMENTS)
record AnonymousAuthentication(boolean enabled, Set<String> authorities, CodeRef custom, CodeRef disabledAt) {

    static final String DEFAULT_AUTHORITY = "ROLE_ANONYMOUS";
    private static final Set<String> CONFIGURERS = Set.of(
            "org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer",
            "org.springframework.security.config.web.server.ServerHttpSecurity$AnonymousSpec");
    private static final String SERVER_HTTP_SECURITY = "org.springframework.security.config.web.server.ServerHttpSecurity";
    private static final Set<String> CHAINS = Set.of(WebStack.SECURITY_FILTER_CHAIN, WebStack.SECURITY_WEB_FILTER_CHAIN);

    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    static AnonymousAuthentication detect(ScanContext context, GraphBuilder graph, boolean reactive) {
        Set<String> authorities = new TreeSet<>();
        CodeRef custom = null;
        CodeRef disabled = null;
        boolean configured = false;
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    Optional<AbstractInvokeExpr> found = Locals.invoke(stmt);
                    if (found.isEmpty()) {
                        continue;
                    }
                    AbstractInvokeExpr invoke = found.get();
                    String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
                    String name = invoke.getMethodSignature().getName();
                    CodeRef site = MethodNames.codeRef(method.getSignature(), stmt);
                    if (name.equals("anonymous") && (owner.equals(SpringNames.HTTP_SECURITY)
                            || owner.equals(SERVER_HTTP_SECURITY)) && invoke.getArgCount() == 1) {
                        configured = true;
                        if (disables(method, invoke.getArg(0))) {
                            disabled = site;
                        }
                    }
                    if (!CONFIGURERS.contains(owner)) {
                        continue;
                    }
                    if (name.equals("disable")) {
                        disabled = site;
                    }
                    if (name.equals("authorities") && invoke.getArgCount() == 1) {
                        // authorities("ROLE_GUEST"), not a List<GrantedAuthority> built elsewhere.
                        List<String> given = Locals.strings(method.getBody(), invoke.getArg(0));
                        boolean constants = invoke.getArg(0) instanceof Local array && !given.isEmpty()
                                && given.size() == Locals.elements(method.getBody(), array).size();
                        if (!constants) {
                            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, MethodNames.key(method
                                    .getSignature()) + " gives callers who haven't signed in authorities AuthTracer"
                                    + " can't read: role checks may admit them, which the graph doesn't show", site));
                            continue;
                        }
                        authorities.addAll(given);
                        if (!given.equals(List.of(DEFAULT_AUTHORITY))) {
                            custom = site;
                        }
                    }
                }
            }
        }
        if (authorities.isEmpty()) {
            authorities.add(DEFAULT_AUTHORITY);
        }
        // Turned off in one chain of several, the others still have it: the weaker reading keeps it on.
        int chains = SpringBeans.beanMethodsOf(context, CHAINS).size();
        if (disabled != null && chains > 1) {
            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "Anonymous authentication is turned off at "
                    + disabled.key() + ", in one of " + chains + " security filter chains: AuthTracer doesn't tell"
                    + " which, so callers who haven't signed in are shown as anonymous everywhere", disabled));
            disabled = null;
        }
        boolean enabled = disabled == null && (!reactive || configured);
        return new AnonymousAuthentication(enabled, authorities, custom, disabled);
    }

    /**
     * {@code anonymous(AbstractHttpConfigurer::disable)}: a method reference to {@code disable}.
     */
    private static boolean disables(JavaSootMethod method, Value customizer) {
        return customizer instanceof Local local
                && Locals.definition(method.getBody(), local).filter(JDynamicInvokeExpr.class::isInstance)
                        .map(JDynamicInvokeExpr.class::cast).stream()
                        .flatMap(dynamic -> dynamic.getBootstrapArgs().stream())
                        .anyMatch(argument -> argument instanceof MethodHandle handle
                                && handle.getReferenceSignature() instanceof MethodSignature target
                                && target.getName().equals("disable"));
    }

    /**
     * Each check as the anonymous token meets it: with it on, a role or authority check it passes also admits
     * callers who haven't signed in; with it off, {@code anonymous()} admits no one. Provided checks and the rules
     * that don't see the token (Jersey's {@code isUserInRole}, message and RSocket rules) are left as they are.
     */
    @Supports({Feature.FINDING_ALWAYS_GRANTED, Feature.FINDING_ALWAYS_DENIED})
    void apply(GraphBuilder graph) {
        for (AuthorizationLocation location : List.copyOf(graph.nodes()).stream()
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> !graph.splits().containsKey(location.id()) && seesToken(location)).toList()) {
            Requirement met = meet(location.requirement());
            if (met.equals(location.requirement())) {
                continue;
            }
            graph.replace(location.withRequirement(met));
            if (enabled && custom != null) {
                graph.finding(new Finding(Finding.Kind.ALWAYS_GRANTED, location.mechanism() + " on "
                        + location.target().key() + " asks for " + HttpSecurityRules.describe(location.requirement())
                        + ", which callers who haven't signed in hold: anonymous authentication gives them "
                        + String.join(", ", authorities) + " (" + custom.key() + ")", location.target()));
            }
            if (!enabled) {
                graph.finding(new Finding(Finding.Kind.ALWAYS_DENIED, location.mechanism() + " on "
                        + location.target().key() + " admits only callers who haven't signed in, but anonymous"
                        + " authentication is turned off (" + disabledAt.key() + "): they have no Authentication,"
                        + " so no caller passes", location.target()));
            }
        }
    }

    private static boolean seesToken(AuthorizationLocation location) {
        String mechanism = location.mechanism();
        return !mechanism.startsWith("Provided") && !mechanism.equals(JaxRsResources.MECHANISM)
                && !mechanism.startsWith(MessageSecurityRules.MECHANISM)
                && !mechanism.startsWith(RSocketSecurityRules.MECHANISM)
                && !mechanism.startsWith(GrpcSecurityRules.MECHANISM);
    }

    private Requirement meet(Requirement requirement) {
        return switch (requirement.kind()) {
            case ANONYMOUS -> enabled || disabledAt == null ? requirement
                    : Requirement.denyAll().withSource(requirement.expression() != null ? requirement.expression()
                            : "anonymous");
            case ANY_AUTHORITY -> enabled && requirement.authorities().stream().anyMatch(authorities::contains)
                    ? anonymousOr(requirement) : requirement;
            case ALL_AUTHORITIES -> enabled && authorities.containsAll(requirement.authorities())
                    ? anonymousOr(requirement) : requirement;
            case AND, OR, NOT -> {
                List<Requirement> operands = new ArrayList<>();
                requirement.operands().forEach(operand -> operands.add(meet(operand)));
                yield operands.equals(requirement.operands()) ? requirement : requirement.withOperands(operands);
            }
            default -> requirement;
        };
    }

    /**
     * The check, or a caller who hasn't signed in: {@code ROLE_GUEST} becomes {@code anonymous or ROLE_GUEST}.
     */
    private static Requirement anonymousOr(Requirement requirement) {
        return new Requirement(Requirement.Kind.OR, null, List.of(Requirement.anonymous(), new Requirement(
                requirement.kind(), requirement.authorities(), null, null)), requirement.expression(),
                requirement.decidedBy());
    }
}
