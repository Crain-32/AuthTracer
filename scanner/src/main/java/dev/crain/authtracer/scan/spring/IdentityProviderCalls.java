package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0049: what a resource server Spring Boot configures calls on its authorization server to check tokens, so
 * the linker links the two (profile-service, employee-service and payroll-service to identity-service). With {@code jwt.jwk-set-uri}, the JWK set;
 * else, with {@code jwt.issuer-uri}, the issuer's {@code /.well-known/openid-configuration}, which names the JWK set
 * ({@code JwtDecoders.fromIssuerLocation}); with {@code opaquetoken.introspection-uri}, a {@code POST} there with the
 * client's credentials. An OAuth2 client gets each registration's tokens with a {@code POST} to its provider's
 * {@code token-uri}, or finds it from its {@code issuer-uri}'s OpenID configuration. These run while authenticating a
 * request or getting a token, not on a request path.
 */
@Supports({Feature.INFRASTRUCTURE_CALLS, Feature.FINDING_ALWAYS_DENIED})
final class IdentityProviderCalls {

    private static final String PROPERTIES = "spring.security.oauth2.resourceserver.";
    private static final String CONFIGURATION = "org.springframework.boot.security.oauth2.server.resource.autoconfigure.";
    private static final String CLIENT = "spring.security.oauth2.client.";
    private static final String CLIENT_REGISTRATION =
            "org.springframework.security.oauth2.client.registration.ClientRegistration";

    private static final String JWT = "org.springframework.security.oauth2.jwt.";
    private static final String REACTIVE_DECODER = JWT + "NimbusReactiveJwtDecoder";
    private static final Set<String> DECODERS = Set.of(JWT + "NimbusJwtDecoder", REACTIVE_DECODER,
            JWT + "JwtDecoders", JWT + "ReactiveJwtDecoders");
    private static final Set<String> JWK_SETS = Set.of("withJwkSetUri", "jwkSetUri", "setJwkSetUri");
    private static final Set<String> ISSUERS = Set.of("withIssuerLocation", "fromIssuerLocation",
            "fromOidcIssuerLocation");
    private static final String INTROSPECTION = "org.springframework.security.oauth2.server.resource.introspection.";
    private static final Set<String> INTROSPECTORS = Set.of(INTROSPECTION + "SpringOpaqueTokenIntrospector",
            INTROSPECTION + "SpringReactiveOpaqueTokenIntrospector");
    private static final Set<String> INTROSPECTION_URIS = Set.of("withIntrospectionUri", "introspectionUri",
            "setIntrospectionUri");

    private final ScanContext context;

    IdentityProviderCalls(ScanContext context) {
        this.context = context;
    }

    List<Egress> detect() {
        List<Egress> calls = new ArrayList<>(codeCalls());
        if (context.findClass(CONFIGURATION + "OAuth2ResourceServerAutoConfiguration").isEmpty()) {
            calls.addAll(clientCalls());
            return calls;
        }
        CodeRef jwt = CodeRef.ofClass(CONFIGURATION + "JwtDecoderConfiguration");
        Optional<String> jwkSet = context.properties().get(PROPERTIES + "jwt.jwk-set-uri");
        if (jwkSet.isPresent()) {
            call("JwtDecoder", "GET", jwkSet.get(), jwt).ifPresent(calls::add);
        }
        else {
            context.properties().get(PROPERTIES + "jwt.issuer-uri")
                    .flatMap(issuer -> call("JwtDecoder", "GET", issuer.replaceAll("/+$", "")
                            + "/.well-known/openid-configuration", jwt))
                    .ifPresent(calls::add);
        }
        context.properties().get(PROPERTIES + "opaquetoken.introspection-uri")
                .flatMap(uri -> call("OpaqueTokenIntrospector", "POST", uri,
                        CodeRef.ofClass(CONFIGURATION + "OpaqueTokenIntrospectionConfiguration")))
                // Set, if only from the environment.
                .map(call -> context.properties().getResolvingKnown(PROPERTIES + "opaquetoken.client-id").isPresent()
                        ? call.withCredentials(Credentials.STATIC, PROPERTIES + "opaquetoken.client-id") : call)
                .ifPresent(calls::add);
        calls.addAll(clientCalls());
        return calls;
    }

    /**
     * Decision 0073: the decoders and introspectors the application builds with a constant location:
     * {@code NimbusJwtDecoder.withJwkSetUri(..)} (and the reactive one, its constructor, the DSL's
     * {@code jwkSetUri(..)}) fetches that JWK set; {@code withIssuerLocation(..)}, {@code JwtDecoders.fromIssuerLocation}
     * and {@code fromOidcIssuerLocation} fetch the issuer's OpenID configuration first; the introspectors
     * ({@code withIntrospectionUri(..)}, the DSL's {@code introspectionUri(..)}) post each token there.
     */
    private List<Egress> codeCalls() {
        List<Egress> calls = new ArrayList<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    Locals.invoke(stmt).filter(invoke -> invoke.getArgCount() >= 1
                                    && invoke.getArg(0) instanceof StringConstant
                                    && invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName()
                                            .startsWith("org.springframework.security."))
                            .flatMap(invoke -> codeCall(invoke, MethodNames.codeRef(method.getSignature(), stmt)))
                            .ifPresent(calls::add);
                }
            }
        }
        return calls;
    }

    private static Optional<Egress> codeCall(AbstractInvokeExpr invoke, CodeRef site) {
        String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = invoke.getMethodSignature().getName();
        String location = ((StringConstant) invoke.getArg(0)).getValue();
        // A client registration's jwkSetUri is for its ID tokens, not a resource server's.
        if (JWK_SETS.contains(name) && !owner.contains(".oauth2.client.")
                || name.equals("<init>") && owner.equals(REACTIVE_DECODER)) {
            return call("JwtDecoder", "GET", location, site);
        }
        if (ISSUERS.contains(name) && DECODERS.contains(owner)) {
            return call("JwtDecoder", "GET", location.replaceAll("/+$", "") + "/.well-known/openid-configuration",
                    site);
        }
        if (INTROSPECTION_URIS.contains(name) || name.equals("<init>") && INTROSPECTORS.contains(owner)) {
            return call("OpaqueTokenIntrospector", "POST", location, site)
                    .map(found -> found.withCredentials(Credentials.STATIC, "the introspection client"));
        }
        return Optional.empty();
    }

    /**
     * Each OAuth2 client registration's provider: its token endpoint, with the client's credentials.
     */
    @Supports(Feature.FINDING_TOKEN_REJECTED)
    private List<Egress> clientCalls() {
        List<Egress> calls = new ArrayList<>();
        if (context.findClass(CLIENT_REGISTRATION).isEmpty()) {
            return calls;
        }
        CodeRef site = CodeRef.ofClass(CLIENT_REGISTRATION);
        Set<String> providers = new TreeSet<>();
        for (String name : context.properties().namesUnder(CLIENT + "registration.")) {
            String registration = name.substring(0, name.indexOf('.') < 0 ? name.length() : name.indexOf('.'));
            providers.add(context.properties().get(CLIENT + "registration." + registration + ".provider")
                    .orElse(registration));
        }
        for (String provider : providers) {
            Optional<String> tokenUri = context.properties().get(CLIENT + "provider." + provider + ".token-uri");
            Optional<Egress> call = tokenUri.isPresent()
                    ? call("OAuth2 client", "POST", tokenUri.get(), site)
                            .map(found -> found.withCredentials(Credentials.STATIC, "client registration"))
                    : context.properties().get(CLIENT + "provider." + provider + ".issuer-uri").flatMap(issuer ->
                            call("OAuth2 client", "GET", issuer.replaceAll("/+$", "")
                                    + "/.well-known/openid-configuration", site));
            call.ifPresent(calls::add);
        }
        return calls;
    }

    private static Optional<Egress> call(String client, String method, String url, CodeRef site) {
        return AbsoluteUrl.parse(url).map(found -> found.call(client, method, found.path().isEmpty() ? "/"
                : found.path(), site));
    }
}
