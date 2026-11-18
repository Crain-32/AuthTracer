package dev.crain.authtracer.scan.spring;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.EnclosingMethods;
import dev.crain.authtracer.scan.GroovyCalls;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * OAUTH-07 (decision 0049): a servlet resource server publishes its OAuth 2.0 Protected Resource Metadata (RFC 9728).
 * In Spring Security 7.1.1 (javap), {@code OAuth2ResourceServerConfigurer#configure} always adds an
 * {@code OAuth2ProtectedResourceMetadataFilter} before {@code AbstractPreAuthenticatedProcessingFilter}, which answers
 * {@code GET /.well-known/oauth-protected-resource/**} itself, before the chain's authorization: to anyone. It says
 * which authorization servers the resource trusts and how it takes tokens. WebFlux's resource server and the XML
 * namespace's {@code <oauth2-resource-server>} add none.
 */
@Supports(Feature.LIBRARY_ENDPOINTS)
final class ResourceServerMetadata {

    static final String PATH = "/.well-known/oauth-protected-resource";
    private static final String FILTER =
            "org.springframework.security.oauth2.server.resource.web.OAuth2ProtectedResourceMetadataFilter";
    /**
     * The DSLs whose {@code oauth2ResourceServer(..)} adds the configurer: Java's, and Kotlin's (whose
     * {@code HttpSecurityDsl#oauth2ResourceServer} calls Java's).
     */
    private static final Set<String> DSL = Set.of(SpringNames.HTTP_SECURITY,
            "org.springframework.security.config.annotation.web.HttpSecurityDsl");

    private final ScanContext context;

    ResourceServerMetadata(ScanContext context) {
        this.context = context;
    }

    /**
     * The metadata endpoint and its public check, when a chain that takes its requests configures a resource server.
     *
     * @param authorizationServer Spring Boot's authorization server chains are the application's, which replace its
     *        resource server chain
     */
    Optional<AuthorizationServerEndpoints.Endpoint> detect(HttpSecurityRules rules, boolean authorizationServer) {
        if (WebStack.reactive(context) || context.findClass(FILTER).isEmpty()) {
            return Optional.empty();
        }
        Ingress endpoint = Ingress.of("GET", PATH + "/**", CodeRef.ofClass(FILTER));
        HttpSecurityRules.Passes passes = rules.chainsFor(Ingress.of("GET", PATH, null));
        boolean served;
        if (SpringBeans.beanMethodsOf(context, Set.of(WebStack.SECURITY_FILTER_CHAIN)).isEmpty()) {
            // ignoring() takes it out of every chain.
            served = !authorizationServer && !(passes.chains().isEmpty() && passes.surely())
                    && AuthenticationMechanisms.bootResourceServerChain(context);
        }
        else {
            Set<String> configuring = configuring();
            // A helper or customizer that configures it may be any chain's.
            served = passes.chains().stream().anyMatch(chain -> configuring.contains(MethodNames.key(chain)))
                    || !passes.chains().isEmpty() && configuring.stream().anyMatch(method -> !chains().contains(
                            method));
        }
        return served ? Optional.of(new AuthorizationServerEndpoints.Endpoint(endpoint, check())) : Optional.empty();
    }

    /**
     * The methods (a chain's bean method, for its lambdas) that call {@code oauth2ResourceServer(..)}.
     */
    private Set<String> configuring() {
        EnclosingMethods enclosing = new EnclosingMethods(context);
        Set<String> methods = new HashSet<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                    if (invoke.isPresent() && configures(invoke.get())) {
                        methods.add(MethodNames.key(enclosing.of(method).getSignature()));
                    }
                }
            }
        }
        return methods;
    }

    private static boolean configures(AbstractInvokeExpr invoke) {
        MethodSignature called = invoke.getMethodSignature();
        if (called.getName().equals("oauth2ResourceServer")) {
            return DSL.contains(called.getDeclClassType().getFullyQualifiedName());
        }
        // Dynamic Groovy: http.oauth2ResourceServer { .. } on an HttpSecurity, or an untyped receiver.
        return GroovyCalls.of(invoke).filter(call -> call.name().equals("oauth2ResourceServer"))
                .filter(call -> Set.of(SpringNames.HTTP_SECURITY, "java.lang.Object")
                        .contains(call.receiverType().toString())).isPresent();
    }

    private Set<String> chains() {
        Set<String> keys = new HashSet<>();
        SpringBeans.beanMethodsOf(context, Set.of(WebStack.SECURITY_FILTER_CHAIN))
                .forEach(method -> keys.add(MethodNames.key(method.getSignature())));
        return keys;
    }

    private static AuthorizationLocation check() {
        return new AuthorizationLocation("location:HTTP_REQUEST:resource-server:metadata",
                "OAuth2 Resource Server (public: answers before authorization)",
                AuthorizationLocation.Scope.HTTP_REQUEST, AuthorizationLocation.Phase.PRE, Requirement.permitAll(),
                CodeRef.ofClass(FILTER), null, null, AuthorizationLocation.Denial.THROW, false);
    }
}
