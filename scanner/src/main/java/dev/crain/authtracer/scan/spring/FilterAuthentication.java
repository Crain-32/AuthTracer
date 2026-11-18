package dev.crain.authtracer.scan.spring;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthoritySource.Freshness;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.CallTraversal;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0071: a filter that authenticates the request itself is a way in, the most common hand-written JWT or
 * API-key pattern. It sets the {@code SecurityContext}'s Authentication ({@code setAuthentication}, {@code setContext},
 * WebFlux's {@code ReactiveSecurityContextHolder.withAuthentication}), or extends Spring's
 * {@code AbstractAuthenticationProcessingFilter} (whose {@code successfulAuthentication} sets what
 * {@code attemptAuthentication} returns) or {@code AbstractPreAuthenticatedProcessingFilter}. Its authorities are live
 * when it looks the caller up on every request (a {@code UserDetailsService}, a repository, JDBC, JPA, an
 * introspection or other HTTP call), else a snapshot of what the request carries (a token it decodes).
 */
@Supports(Feature.AUTHORITY_SOURCE)
final class FilterAuthentication {

    private static final String CONTEXT = "org.springframework.security.core.context.";
    private static final Set<String> SETS_AUTHENTICATION = Set.of(CONTEXT + "SecurityContext#setAuthentication",
            CONTEXT + "SecurityContextImpl#setAuthentication", CONTEXT + "SecurityContextHolder#setContext",
            CONTEXT + "SecurityContextHolderStrategy#setContext",
            CONTEXT + "ReactiveSecurityContextHolder#withAuthentication",
            CONTEXT + "ReactiveSecurityContextHolder#withSecurityContext");
    private static final String WEB_AUTHENTICATION = "org.springframework.security.web.authentication.";
    /**
     * Library filters that set what the methods a subclass overrides return.
     */
    private static final Set<String> AUTHENTICATING_FILTERS = Set.of(
            WEB_AUTHENTICATION + "AbstractAuthenticationProcessingFilter",
            WEB_AUTHENTICATION + "preauth.AbstractPreAuthenticatedProcessingFilter");
    private static final String DIGEST = WEB_AUTHENTICATION + "www.DigestAuthenticationFilter";
    private static final Set<String> LIBRARY_AUTHENTICATING = Set.of(
            WEB_AUTHENTICATION + "AbstractAuthenticationProcessingFilter",
            WEB_AUTHENTICATION + "preauth.AbstractPreAuthenticatedProcessingFilter",
            WEB_AUTHENTICATION + "www.BasicAuthenticationFilter", DIGEST, WEB_AUTHENTICATION + "AuthenticationFilter",
            WEB_AUTHENTICATION + "rememberme.RememberMeAuthenticationFilter",
            "org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter",
            "org.springframework.security.web.server.authentication.AuthenticationWebFilter");
    private static final String AUTHENTICATION = "org.springframework.security.core.Authentication";
    private static final String AUTHORITY_UTILS = "org.springframework.security.core.authority.AuthorityUtils";
    private static final String SIMPLE_AUTHORITY = "org.springframework.security.core.authority.SimpleGrantedAuthority";
    private static final String REPOSITORY = "org.springframework.data.repository.Repository";
    /**
     * Calls that look the caller up again on every request, by declaring type (or a type it is assignable to).
     */
    private static final Set<String> LOOKUPS = Set.of(
            "org.springframework.security.core.userdetails.UserDetailsService",
            "org.springframework.security.core.userdetails.ReactiveUserDetailsService",
            "org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector",
            "org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector",
            "org.springframework.jdbc.core.JdbcTemplate", "org.springframework.jdbc.core.JdbcOperations",
            "org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate",
            "org.springframework.jdbc.core.simple.JdbcClient", "jakarta.persistence.EntityManager",
            SpringNames.REST_CLIENT, "org.springframework.web.client.RestTemplate",
            "org.springframework.web.reactive.function.client.WebClient", REPOSITORY);
    /**
     * Calls that decode a token the request carries.
     */
    private static final List<String> DECODERS = List.of("org.springframework.security.oauth2.jwt.JwtDecoder",
            "org.springframework.security.oauth2.jwt.ReactiveJwtDecoder", "io.jsonwebtoken.", "com.auth0.jwt.",
            "com.nimbusds.jwt.", "java.util.Base64$Decoder");
    /**
     * Managers whose providers decide: AuthTracer doesn't read which, so it doesn't claim they look the caller up.
     */
    private static final Set<String> MANAGERS = Set.of(
            "org.springframework.security.authentication.AuthenticationManager",
            "org.springframework.security.authentication.ReactiveAuthenticationManager");
    private static final int MAX_METHODS = 200;

    /**
     * A way in a filter adds: its label for the authority source, and how fresh its authorities are.
     *
     * @param afterRule every request passes it after its filter chain's rule, so the rule decided for a caller who
     *        hadn't signed in, and only the checks after it see what it sets
     * @param site the filter's code
     */
    record Mechanism(String label, Freshness freshness, boolean afterRule, CodeRef site) {
    }

    private FilterAuthentication() {
    }

    /**
     * The filters among those requests pass that authenticate, each once.
     */
    static List<Mechanism> detect(ScanContext context, RequestFilters filters) {
        CallTraversal calls = new CallTraversal(context);
        List<Mechanism> found = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (RequestFilters.Code filter : filters.filters()) {
            if (seen.add(filter.name())) {
                read(context, calls, filter, !filters.beforeRule(filter.name())).ifPresent(found::add);
            }
        }
        // Decision 0071 (amended): Spring's own authenticating filters, added by hand.
        for (RequestFilters.Library filter : filters.authenticating()) {
            if (seen.add(filter.name())) {
                boolean afterRule = filters.authenticating().stream().noneMatch(other -> other.name()
                        .equals(filter.name()) && other.beforeRule());
                found.add(library(context, filter, afterRule));
            }
        }
        return found;
    }

    /**
     * Whether a library filter class authenticates requests: Spring Security 7.1.1's login and pre-authentication
     * filters, HTTP Basic and Digest, the resource server's bearer token filter, remember-me, the generic
     * {@code AuthenticationFilter}, and WebFlux's {@code AuthenticationWebFilter}.
     */
    static boolean authenticates(ScanContext context, ClassType type) {
        // A CAS filter the application makes is a way in of its own (decision 0074).
        return SpringBeans.assignable(context, type, LIBRARY_AUTHENTICATING)
                && !type.getFullyQualifiedName().equals("org.springframework.security.cas.web.CasAuthenticationFilter");
    }

    /**
     * A library filter's way in: Digest looks the user up through its {@code UserDetailsService} on every request; a
     * pre-authentication filter keeps what it sets in the session; the others authenticate with the
     * {@code AuthenticationManager} they are given, whose providers AuthTracer doesn't read: a snapshot, the weaker
     * claim.
     */
    private static Mechanism library(ScanContext context, RequestFilters.Library filter, boolean afterRule) {
        List<String> parts = new ArrayList<>();
        if (afterRule) {
            parts.add("after the AuthorizationFilter");
        }
        boolean digest = SpringBeans.assignable(context, filter.type(), Set.of(DIGEST));
        boolean preAuthenticated = SpringBeans.assignable(context, filter.type(),
                Set.of(WEB_AUTHENTICATION + "preauth.AbstractPreAuthenticatedProcessingFilter"));
        parts.add(digest ? "looks the caller up on every request: its UserDetailsService"
                : preAuthenticated ? "kept in the session"
                : "authenticates with the AuthenticationManager it is given");
        return new Mechanism(filter.name() + " added by hand (" + String.join("; ", parts) + ")",
                digest ? Freshness.LIVE : Freshness.SNAPSHOT, afterRule, filter.site());
    }

    /**
     * SRC-10 (decision 0071): code outside a filter that sets the Authentication itself
     * ({@code setAuthentication}, {@code setContext}), or builds one with authorities of its own
     * ({@code Authentication#toBuilder().authorities(..)}, 7.1.1). The checks after it on that thread see what it sets,
     * so a caller may need less than its path shows.
     */
    @Supports(Feature.FINDING_AUTHORITIES_IN_CODE)
    static List<Finding> inCode(ScanContext context, Collection<JavaSootMethod> methods) {
        List<Finding> findings = new ArrayList<>();
        for (JavaSootMethod method : methods) {
            if (!method.hasBody() || SpringBeans.assignable(context, method.getDeclaringClassType(),
                    Set.of(RequestFilters.FILTER, RequestFilters.WEB_FILTER))) {
                continue;
            }
            Set<String> how = new LinkedHashSet<>();
            Set<String> tokens = new LinkedHashSet<>();
            Set<String> authorities = new LinkedHashSet<>();
            Integer line = null;
            for (Stmt stmt : method.getBody().getStmts()) {
                Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                if (invoke.isEmpty()) {
                    continue;
                }
                String owner = invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
                String name = invoke.get().getMethodSignature().getName();
                boolean sets = SETS_AUTHENTICATION.contains(owner + "#" + name)
                        || owner.equals(AUTHENTICATION + "$Builder") && name.equals("authorities");
                if (sets) {
                    how.add(MethodNames.simpleName(owner) + "#" + name);
                    line = line != null ? line : stmt.getPositionInfo().getStmtPosition().getFirstLine();
                }
                token(context, invoke.get()).ifPresent(tokens::add);
                authorities(method, invoke.get()).forEach(authorities::add);
            }
            if (how.isEmpty()) {
                continue;
            }
            List<String> what = new ArrayList<>(tokens);
            if (!authorities.isEmpty()) {
                what.add("authorities " + String.join(", ", authorities));
            }
            findings.add(new Finding(Finding.Kind.AUTHORITIES_IN_CODE, "Authorities set in code: "
                    + MethodNames.key(method.getSignature()) + " sets the Authentication itself ("
                    + String.join(", ", how) + (what.isEmpty() ? "" : "; " + String.join("; ", what)) + "): the"
                    + " checks after it on this thread see what it sets, not the caller's, so a caller may need less"
                    + " than the path shows", MethodNames.codeRef(method.getSignature()).atLine(line)));
        }
        return findings;
    }

    /**
     * The Authentication a call makes: a token's constructor or its {@code authenticated(..)} factory.
     */
    private static Optional<String> token(ScanContext context, AbstractInvokeExpr invoke) {
        ClassType declaring = invoke.getMethodSignature().getDeclClassType();
        String name = invoke.getMethodSignature().getName();
        boolean token = name.equals("<init>") && SpringBeans.assignable(context, declaring, Set.of(AUTHENTICATION))
                || (name.equals("authenticated") || name.equals("unauthenticated"))
                        && declaring.getFullyQualifiedName().endsWith("AuthenticationToken");
        return token ? Optional.of(MethodNames.simpleName(declaring.getFullyQualifiedName())) : Optional.empty();
    }

    /**
     * The constant authorities a call grants: {@code new SimpleGrantedAuthority("ROLE_X")},
     * {@code AuthorityUtils.createAuthorityList(..)} or {@code commaSeparatedStringToAuthorityList(..)}.
     */
    private static List<String> authorities(JavaSootMethod method, AbstractInvokeExpr invoke) {
        String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        if (!(owner.equals(SIMPLE_AUTHORITY) && invoke.getMethodSignature().getName().equals("<init>")
                || owner.equals(AUTHORITY_UTILS))) {
            return List.of();
        }
        List<String> authorities = new ArrayList<>();
        invoke.getArgs().forEach(argument -> constants(method, argument).forEach(authority ->
                authorities.addAll(List.of(authority.split("\\s*,\\s*")))));
        return authorities;
    }

    private static Optional<Mechanism> read(ScanContext context, CallTraversal calls, RequestFilters.Code filter,
            boolean afterRule) {
        Optional<String> library = filter.receiver() == null ? Optional.empty() : context.superClassesOf(
                filter.receiver()).stream().map(ClassType::getFullyQualifiedName)
                .filter(AUTHENTICATING_FILTERS::contains).findFirst();
        boolean sets = library.isPresent();
        Set<String> tokens = new LinkedHashSet<>();
        Set<String> authorities = new LinkedHashSet<>();
        Set<String> lookups = new LinkedHashSet<>();
        Set<String> decoders = new LinkedHashSet<>();
        Set<String> managers = new LinkedHashSet<>();
        // What the filter's methods call in the application, nearest first.
        Deque<JavaSootMethod> queue = new ArrayDeque<>(filter.methods());
        Set<String> visited = new HashSet<>();
        while (!queue.isEmpty() && visited.size() < MAX_METHODS) {
            JavaSootMethod method = queue.removeFirst();
            if (!visited.add(method.getSignature().toString())) {
                continue;
            }
            for (Stmt stmt : method.getBody().getStmts()) {
                Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                if (invoke.isEmpty()) {
                    continue;
                }
                ClassType declaring = invoke.get().getMethodSignature().getDeclClassType();
                String owner = declaring.getFullyQualifiedName();
                String name = invoke.get().getMethodSignature().getName();
                sets |= SETS_AUTHENTICATION.contains(owner + "#" + name);
                token(context, invoke.get()).ifPresent(tokens::add);
                authorities.addAll(authorities(method, invoke.get()));
                String call = MethodNames.simpleName(owner) + "#" + name;
                if (SpringBeans.assignable(context, declaring, LOOKUPS)) {
                    lookups.add(call);
                }
                else if (SpringBeans.assignable(context, declaring, MANAGERS)) {
                    managers.add(call);
                }
                else if (DECODERS.stream().anyMatch(owner::startsWith)) {
                    decoders.add(call);
                }
                calls.targets(invoke.get()).stream().filter(JavaSootMethod::hasBody).forEach(queue::addLast);
            }
        }
        if (!queue.isEmpty()) {
            context.limit("Reading what an authenticating filter calls", MAX_METHODS, filter.name());
        }
        if (!sets) {
            return Optional.empty();
        }
        List<String> parts = new ArrayList<>();
        if (afterRule) {
            parts.add("after the AuthorizationFilter");
        }
        library.ifPresent(type -> parts.add("extends " + MethodNames.simpleName(type)));
        if (!tokens.isEmpty()) {
            parts.add(String.join(", ", tokens));
        }
        if (!authorities.isEmpty()) {
            parts.add("authorities " + String.join(", ", authorities));
        }
        // A lookup on every request honors a revocation; what the request carries is fixed when it was issued. A
        // library filter authenticates some requests only: AbstractPreAuthenticatedProcessingFilter keeps what it
        // sets in the session (an HttpSessionSecurityContextRepository by default, 7.1.1), a login filter for the
        // requests its matcher takes (a RequestAttributeSecurityContextRepository, unless it is given another).
        // Otherwise a snapshot, the weaker claim.
        Freshness freshness = library.isEmpty() && !lookups.isEmpty() ? Freshness.LIVE : Freshness.SNAPSHOT;
        boolean preAuthenticated = library.filter(type -> type.endsWith("PreAuthenticatedProcessingFilter"))
                .isPresent();
        parts.add(freshness == Freshness.LIVE ? "looks the caller up on every request: " + String.join(", ", lookups)
                : preAuthenticated ? "kept in the session"
                : !decoders.isEmpty() ? "decodes a token: " + String.join(", ", decoders)
                : !managers.isEmpty() ? "authenticates with " + String.join(", ", managers)
                : !lookups.isEmpty() ? "looks the caller up when it authenticates: " + String.join(", ", lookups)
                : library.isPresent() ? "authenticates what attemptAuthentication returns"
                : "from what the request carries");
        return Optional.of(new Mechanism("Custom filter " + filter.name() + " (" + String.join("; ", parts) + ")",
                freshness, afterRule, filter.methods().isEmpty() ? null
                        : MethodNames.codeRef(filter.methods().getFirst().getSignature())));
    }

    /**
     * A string constant argument, or the constants of a varargs array.
     */
    private static List<String> constants(JavaSootMethod method, sootup.core.jimple.common.Immediate argument) {
        return argument instanceof StringConstant constant ? List.of(constant.getValue())
                : Locals.strings(method.getBody(), argument);
    }
}
