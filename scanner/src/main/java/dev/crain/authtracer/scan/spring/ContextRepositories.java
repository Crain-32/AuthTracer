package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.EnclosingMethods;
import dev.crain.authtracer.scan.GroovyCalls;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.ref.JStaticFieldRef;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootMethod;

/**
 * SRC-08 (decision 0074): whether a filter chain keeps the {@code SecurityContext} from one request to the next, so
 * that what a login put there is a snapshot, or looks the caller up again on each request. Read per chain: a chain
 * bean method with the lambdas and closures written in it.
 * <p>
 * Spring Security 7.1.1 (javap): a chain loads the context from its shared {@code SecurityContextRepository}, which
 * {@code securityContext(c -> c.securityContextRepository(..))} sets, else {@code SessionManagementConfigurer#init}:
 * a {@code RequestAttributeSecurityContextRepository} when the policy is {@code STATELESS}, else a
 * {@code DelegatingSecurityContextRepository} of the {@code HttpSession} one and the request attribute one. Form
 * login, one-time token login, remember-me (and OAuth2 and SAML 2.0 Login) save to that shared repository
 * ({@code requireExplicitSave}, the default); HTTP Basic saves to its own, a request attribute one unless
 * {@code httpBasic(b -> b.securityContextRepository(..))} gives another; the pre-authentication filters and
 * WebAuthn's filter save to the session. On WebFlux the chain loads from
 * {@code ServerHttpSecurity#securityContextRepository}, else a {@code WebSessionServerSecurityContextRepository};
 * form login and one-time token login save to their spec's repository, else the chain's, else the session; HTTP
 * Basic to its spec's, else the chain's, else {@code NoOpServerSecurityContextRepository}.
 */
@Supports(Feature.AUTHORITY_SOURCE)
final class ContextRepositories {

    private static final String CONFIGURERS = "org.springframework.security.config.annotation.web.configurers.";
    private static final String KOTLIN = "org.springframework.security.config.annotation.web.";
    private static final String SERVER = "org.springframework.security.config.web.server.";
    private static final String SERVER_HTTP = SERVER + "ServerHttpSecurity";
    static final String SESSION_MANAGEMENT = CONFIGURERS + "SessionManagementConfigurer";
    /**
     * A dynamic Groovy call on an untyped receiver, which may be the chain's or a way in's configurer.
     */
    static final String UNTYPED = "groovy.lang.untyped";
    /**
     * The calls that set a chain's own repository, which it loads the context from.
     */
    private static final Set<String> CHAIN_REPOSITORY = Set.of(CONFIGURERS + "SecurityContextConfigurer"
            + "#securityContextRepository", KOTLIN + "SecurityContextDsl#setSecurityContextRepository",
            SERVER_HTTP + "#securityContextRepository", SERVER + "ServerHttpSecurityDsl#setSecurityContextRepository");
    private static final Set<String> POLICY_SETTERS = Set.of(SESSION_MANAGEMENT + "#sessionCreationPolicy",
            KOTLIN + "SessionManagementDsl#setSessionCreationPolicy");
    /**
     * The calls that set the repository one way in saves to, by the DSL call that adds it.
     */
    private static final Map<String, String> OWN_REPOSITORY = Map.of(
            CONFIGURERS + "HttpBasicConfigurer#securityContextRepository", "httpBasic",
            SERVER_HTTP + "$HttpBasicSpec#securityContextRepository", "httpBasic",
            SERVER + "ServerHttpBasicDsl#setSecurityContextRepository", "httpBasic",
            SERVER_HTTP + "$FormLoginSpec#securityContextRepository", "formLogin",
            SERVER + "ServerFormLoginDsl#setSecurityContextRepository", "formLogin",
            SERVER_HTTP + "$OneTimeTokenLoginSpec#securityContextRepository", "oneTimeTokenLogin",
            SERVER + "ServerOneTimeTokenLoginDsl#setSecurityContextRepository", "oneTimeTokenLogin");

    private static final String WEB_CONTEXT = "org.springframework.security.web.context.";
    private static final String SERVER_CONTEXT = "org.springframework.security.web.server.context.";
    private static final Set<String> SESSION = Set.of(WEB_CONTEXT + "HttpSessionSecurityContextRepository",
            SERVER_CONTEXT + "WebSessionServerSecurityContextRepository");
    private static final Set<String> REQUEST = Set.of(WEB_CONTEXT + "RequestAttributeSecurityContextRepository",
            WEB_CONTEXT + "NullSecurityContextRepository", SERVER_CONTEXT + "NoOpServerSecurityContextRepository");
    private static final String DELEGATING = WEB_CONTEXT + "DelegatingSecurityContextRepository";

    /**
     * Whether a repository keeps the context past the request (in the session, or anywhere AuthTracer can't read).
     *
     * @param unread what the repository is when AuthTracer can't read it; it is taken to keep the context, the reading
     *        under which a login's authorities are a snapshot
     */
    record Repository(boolean keeps, String unread) {

        static final Repository KEPT = new Repository(true, null);
        static final Repository REQUEST_ONLY = new Repository(false, null);
    }

    /**
     * What one chain sets.
     */
    private static final class Chain {
        boolean stateless;
        Repository repository;
        final Map<String, Repository> own = new HashMap<>();
    }

    private final ScanContext context;
    private final boolean reactive;
    private final EnclosingMethods enclosing;
    private final BuiltValues values;
    private final Map<JavaSootMethod, Chain> chains = new HashMap<>();
    private final Map<String, CodeRef> unread = new LinkedHashMap<>();

    ContextRepositories(ScanContext context, boolean reactive, EnclosingMethods enclosing, BuiltValues values) {
        this.context = context;
        this.reactive = reactive;
        this.enclosing = enclosing;
        this.values = values;
    }

    /**
     * Records what the call sets on its chain, if it sets anything.
     *
     * @param declaring the class the call is on, as {@code AuthenticationMechanisms} reads it (Groovy's receiver)
     * @param args the call's arguments (a Groovy call's, without the receiver)
     */
    void read(JavaSootMethod method, Stmt stmt, String declaring, String name, List<Immediate> args) {
        String call = declaring + "#" + name;
        if (args.size() != 1) {
            return;
        }
        if (POLICY_SETTERS.contains(call)) {
            chain(method).stateless |= stateless(method, args.getFirst());
        }
        else if (CHAIN_REPOSITORY.contains(call)) {
            chain(method).repository = repository(method, args.getFirst(), stmt);
        }
        else if (OWN_REPOSITORY.containsKey(call)) {
            chain(method).own.put(OWN_REPOSITORY.get(call), repository(method, args.getFirst(), stmt));
        }
        else if (call.equals(UNTYPED + "#securityContextRepository")) {
            // In a closure AuthTracer doesn't tie to its configurer, it is read as HTTP Basic's, and the chain keeps
            // the context as it does by default: the reading under which authorities are a snapshot.
            chain(method).own.put("httpBasic", repository(method, args.getFirst(), stmt));
        }
    }

    /**
     * Whether a way in, added by the DSL call in the method, keeps what its login sets for the requests after it.
     *
     * @param mechanism the DSL call: {@code formLogin}, {@code httpBasic}, ...
     */
    boolean keeps(JavaSootMethod method, String mechanism) {
        Chain chain = chains.getOrDefault(enclosing.of(method), new Chain());
        Repository loaded = chain.repository != null ? chain.repository
                : !reactive && chain.stateless ? Repository.REQUEST_ONLY : Repository.KEPT;
        Repository saved = switch (mechanism) {
            case "httpBasic" -> chain.own.getOrDefault(mechanism, reactive && chain.repository != null
                    ? chain.repository : Repository.REQUEST_ONLY);
            case "formLogin", "oneTimeTokenLogin" -> reactive ? chain.own.getOrDefault(mechanism, loaded) : loaded;
            default -> loaded;
        };
        return loaded.keeps() && saved.keeps();
    }

    /**
     * OPAQUE_CONFIG for each repository AuthTracer can't read.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    List<Finding> findings() {
        List<Finding> findings = new ArrayList<>();
        unread.forEach((what, where) -> findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The security context"
                + " repository " + what + " isn't read: AuthTracer takes it to keep the SecurityContext across"
                + " requests, so the authorities a login gives are a snapshot until the session ends", where)));
        return findings;
    }

    private Chain chain(JavaSootMethod method) {
        return chains.computeIfAbsent(enclosing.of(method), key -> new Chain());
    }

    /**
     * {@code SessionCreationPolicy.STATELESS}, through a local; Groovy reads it as a static property.
     */
    private static boolean stateless(JavaSootMethod method, Immediate arg) {
        Value value = arg instanceof Local local ? Locals.definition(method.getBody(), local).orElse(arg) : arg;
        String name = value instanceof JStaticFieldRef field ? field.getFieldSignature().getName()
                : value instanceof AbstractInvokeExpr invoke ? GroovyCalls.of(invoke)
                        .filter(call -> call.type().equals("getProperty")).map(GroovyCalls.Call::name).orElse(null)
                : null;
        return "STATELESS".equals(name);
    }

    private Repository repository(JavaSootMethod method, Immediate arg, Stmt stmt) {
        Repository repository = repository(values.of(method, arg));
        if (repository.unread() != null) {
            unread.putIfAbsent(repository.unread(), enclosing.site(method, MethodNames.codeRef(method.getSignature(),
                    stmt)));
        }
        return repository;
    }

    /**
     * Of the repositories a value may be (a local each branch assigns), the one under which a login's authorities are
     * a snapshot.
     */
    private Repository repository(List<BuiltValues.Source> sources) {
        Repository stalest = Repository.REQUEST_ONLY;
        for (BuiltValues.Source source : sources) {
            Repository repository = switch (source) {
                case BuiltValues.Created created -> created.type().getFullyQualifiedName().equals(DELEGATING)
                        ? delegating(created) : of(created.type());
                // NoOpServerSecurityContextRepository.getInstance()
                case BuiltValues.Called called -> REQUEST.contains(called.call().getMethodSignature()
                        .getDeclClassType().getFullyQualifiedName()) ? Repository.REQUEST_ONLY
                        : unread(called.call().getMethodSignature().getName() + "()");
                case BuiltValues.Unread found -> unread(found.what());
            };
            stalest = stalest.unread() != null || repository.unread() == null && stalest.keeps() ? stalest
                    : repository;
        }
        return stalest;
    }

    /**
     * A repository of a class: the session's, the request's, or one AuthTracer doesn't read.
     */
    private Repository of(ClassType type) {
        if (SpringBeans.assignable(context, type, SESSION)) {
            return Repository.KEPT;
        }
        return REQUEST.contains(type.getFullyQualifiedName()) ? Repository.REQUEST_ONLY
                : unread(MethodNames.simpleName(type.getFullyQualifiedName()));
    }

    /**
     * A {@code DelegatingSecurityContextRepository} loads from the first of its repositories that has a context and
     * saves to all of them (varargs or a list): it keeps the context when one of them does.
     */
    private Repository delegating(BuiltValues.Created created) {
        List<BuiltValues.Source> parts = new ArrayList<>();
        created.calls("<init>").forEach(init -> values.parts(created.method(), init.getArg(0)).forEach(parts::addAll));
        return repository(parts);
    }

    private static Repository unread(String what) {
        return new Repository(true, what);
    }
}
