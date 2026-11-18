package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0049: Spring Authorization Server's endpoints (Spring Security 7.1.1), which filters serve, not
 * controllers. On with Spring Boot's auto-configuration (no {@code SecurityFilterChain} of the application's, and a
 * {@code RegisteredClientRepository} bean or {@code spring.security.oauth2.authorizationserver.client} properties;
 * OIDC on), or with {@code http.oauth2AuthorizationServer(..)} in the application's chain. What each needs depends on
 * where its filter sits: before the {@code AuthorizationFilter} the JWK set and the metadata documents answer anyone;
 * after it, the authorization server chain's {@code anyRequest().authenticated()} is met by a signed-in user
 * ({@code /oauth2/authorize}, device verification), an authenticated client (token, introspection, revocation, device
 * authorization, pushed authorization requests) or a bearer token whose scope the endpoint checks ({@code /userinfo}:
 * {@code openid}; client registration: {@code client.create}).
 */
@Supports(Feature.LIBRARY_ENDPOINTS)
final class AuthorizationServerEndpoints {

    static final String MECHANISM = "OAuth2 Authorization Server";
    private static final String BOOT_CONFIGURATION = "org.springframework.boot.security.oauth2.server.authorization"
            + ".autoconfigure.servlet.OAuth2AuthorizationServerWebSecurityConfiguration";
    private static final String BOOT_JWK_SOURCE = "org.springframework.boot.security.oauth2.server.authorization"
            + ".autoconfigure.servlet.OAuth2AuthorizationServerJwtAutoConfiguration";
    private static final String CONFIGURER = "org.springframework.security.config.annotation.web.configurers.oauth2"
            + ".server.authorization.OAuth2AuthorizationServerConfigurer";
    private static final String OIDC_CONFIGURER = "org.springframework.security.config.annotation.web.configurers.oauth2"
            + ".server.authorization.OidcConfigurer";
    private static final String SETTINGS =
            "org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings";
    private static final String SETTINGS_BUILDER =
            "org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings$Builder";
    private static final String REGISTERED_CLIENTS =
            "org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository";
    private static final String JWK_SOURCE = "com.nimbusds.jose.jwk.source.JWKSource";
    private static final String FILTERS = "org.springframework.security.oauth2.server.authorization.";
    private static final String PROPERTIES = "spring.security.oauth2.authorizationserver.";

    /**
     * What an endpoint's caller must be.
     */
    private enum Caller {
        ANYONE, USER, CLIENT, SCOPE_OPENID, SCOPE_CLIENT_CREATE
    }

    /**
     * An endpoint: its settings name and default path, Boot's property for its path, its HTTP methods, filter, and
     * caller.
     */
    private record Kind(String setting, String path, String property, List<String> methods, String filter,
            Caller caller) {
    }

    private static final Kind AUTHORIZE = new Kind("authorizationEndpoint", "/oauth2/authorize",
            "endpoint.authorization-uri", List.of("GET", "POST"), "web.OAuth2AuthorizationEndpointFilter", Caller.USER);
    private static final Kind TOKEN = new Kind("tokenEndpoint", "/oauth2/token", "endpoint.token-uri",
            List.of("POST"), "web.OAuth2TokenEndpointFilter", Caller.CLIENT);
    private static final Kind INTROSPECT = new Kind("tokenIntrospectionEndpoint", "/oauth2/introspect",
            "endpoint.token-introspection-uri", List.of("POST"), "web.OAuth2TokenIntrospectionEndpointFilter",
            Caller.CLIENT);
    private static final Kind REVOKE = new Kind("tokenRevocationEndpoint", "/oauth2/revoke",
            "endpoint.token-revocation-uri", List.of("POST"), "web.OAuth2TokenRevocationEndpointFilter", Caller.CLIENT);
    private static final Kind JWKS = new Kind("jwkSetEndpoint", "/oauth2/jwks", "endpoint.jwk-set-uri",
            List.of("GET"), "web.NimbusJwkSetEndpointFilter", Caller.ANYONE);
    private static final Kind METADATA = new Kind(null, "/.well-known/oauth-authorization-server", null,
            List.of("GET"), "web.OAuth2AuthorizationServerMetadataEndpointFilter", Caller.ANYONE);
    private static final Kind DEVICE_AUTHORIZATION = new Kind("deviceAuthorizationEndpoint",
            "/oauth2/device_authorization", "endpoint.device-authorization-uri", List.of("POST"),
            "web.OAuth2DeviceAuthorizationEndpointFilter", Caller.CLIENT);
    private static final Kind DEVICE_VERIFICATION = new Kind("deviceVerificationEndpoint",
            "/oauth2/device_verification", "endpoint.device-verification-uri", List.of("GET", "POST"),
            "web.OAuth2DeviceVerificationEndpointFilter", Caller.USER);
    private static final Kind PAR = new Kind("pushedAuthorizationRequestEndpoint", "/oauth2/par",
            "endpoint.pushed-authorization-request-uri", List.of("POST"),
            "web.OAuth2PushedAuthorizationRequestEndpointFilter", Caller.CLIENT);
    private static final Kind REGISTER = new Kind("clientRegistrationEndpoint", "/oauth2/register", null,
            List.of("POST"), "web.OAuth2ClientRegistrationEndpointFilter", Caller.SCOPE_CLIENT_CREATE);
    private static final Kind OIDC_CONFIGURATION = new Kind(null, "/.well-known/openid-configuration", null,
            List.of("GET"), "oidc.web.OidcProviderConfigurationEndpointFilter", Caller.ANYONE);
    private static final Kind USER_INFO = new Kind("oidcUserInfoEndpoint", "/userinfo", "endpoint.oidc.user-info-uri",
            List.of("GET", "POST"), "oidc.web.OidcUserInfoEndpointFilter", Caller.SCOPE_OPENID);
    private static final Kind LOGOUT = new Kind("oidcLogoutEndpoint", "/connect/logout", "endpoint.oidc.logout-uri",
            List.of("GET", "POST"), "oidc.web.OidcLogoutEndpointFilter", Caller.ANYONE);
    private static final Kind OIDC_REGISTER = new Kind("oidcClientRegistrationEndpoint", "/connect/register",
            "endpoint.oidc.client-registration-uri", List.of("POST"), "oidc.web.OidcClientRegistrationEndpointFilter",
            Caller.SCOPE_CLIENT_CREATE);

    /**
     * An endpoint as Ingress, and the check its caller passes, if any.
     */
    record Endpoint(Ingress ingress, AuthorizationLocation check) {
    }

    private final ScanContext context;

    AuthorizationServerEndpoints(ScanContext context) {
        this.context = context;
    }

    /**
     * Whether Spring Boot's authorization server chains are the application's: auto-configured, no chain of its own,
     * and clients registered by a bean or by properties.
     */
    static boolean bootChains(ScanContext context) {
        return context.findClass(BOOT_CONFIGURATION).isPresent()
                && context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION)
                && SpringBeans.beanMethodsOf(context, Set.of(WebStack.SECURITY_FILTER_CHAIN)).isEmpty()
                && (!SpringBeans.beanMethodsOf(context, Set.of(REGISTERED_CLIENTS)).isEmpty()
                        || context.properties().hasPrefix(PROPERTIES + "client."));
    }

    List<Endpoint> detect() {
        Set<String> calls = new HashSet<>();
        Map<String, String> settings = new HashMap<>();
        boolean configured = false;
        boolean jwkSource = false;
        boolean registeredClients = false;
        boolean chains = false;
        boolean settingsBean = false;
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (context.hasAnnotation(method, SpringNames.BEAN) && method.getReturnType() instanceof ClassType type) {
                    jwkSource |= type.getFullyQualifiedName().equals(JWK_SOURCE);
                    registeredClients |= type.getFullyQualifiedName().equals(REGISTERED_CLIENTS);
                    chains |= SpringBeans.assignable(context, type, Set.of(WebStack.SECURITY_FILTER_CHAIN));
                    settingsBean |= type.getFullyQualifiedName().equals(SETTINGS);
                }
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    if (stmt instanceof AbstractDefinitionStmt definition && definition.getRightOp() instanceof JNewExpr
                            created && created.getType().getFullyQualifiedName().equals(CONFIGURER)) {
                        configured = true;
                    }
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                    if (invoke.isEmpty()) {
                        continue;
                    }
                    String owner = invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
                    String name = invoke.get().getMethodSignature().getName();
                    // http.oauth2AuthorizationServer(..), or http.with(new OAuth2AuthorizationServerConfigurer(), ..).
                    configured |= name.equals("oauth2AuthorizationServer");
                    if (owner.equals(CONFIGURER) || owner.equals(OIDC_CONFIGURER)) {
                        calls.add((owner.equals(OIDC_CONFIGURER) ? "oidc." : "") + name);
                    }
                    if (owner.equals(SETTINGS_BUILDER) && invoke.get().getArgCount() == 1
                            && invoke.get().getArg(0) instanceof StringConstant path) {
                        settings.put(name, path.getValue());
                    }
                }
            }
        }
        boolean autoConfigured = context.findClass(BOOT_CONFIGURATION).isPresent()
                && context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION);
        boolean boot = !configured && !chains && autoConfigured
                && (registeredClients || context.properties().hasPrefix(PROPERTIES + "client."));
        // Boot's AuthorizationServerSettings bean, from the endpoint properties, unless the application has one, also
        // when the application configures its own chain.
        boolean bootSettings = autoConfigured && !settingsBean;
        if (!configured && !boot) {
            return List.of();
        }
        List<Kind> kinds = new ArrayList<>(List.of(AUTHORIZE, TOKEN, INTROSPECT, REVOKE, METADATA));
        // The JWK set is served when there is a JWKSource: the application's, else Boot's
        // (OAuth2AuthorizationServerJwtAutoConfiguration, 4.1.1), which it supplies whatever chain serves the
        // endpoints.
        if (jwkSource || autoConfigured && context.findClass(BOOT_JWK_SOURCE).isPresent()
                && context.findClass(JWK_SOURCE).isPresent()) {
            kinds.add(JWKS);
        }
        if (calls.contains("deviceAuthorizationEndpoint")) {
            kinds.add(DEVICE_AUTHORIZATION);
        }
        if (calls.contains("deviceVerificationEndpoint")) {
            kinds.add(DEVICE_VERIFICATION);
        }
        if (calls.contains("pushedAuthorizationRequestEndpoint")) {
            kinds.add(PAR);
        }
        if (calls.contains("clientRegistrationEndpoint")) {
            kinds.add(REGISTER);
        }
        if (boot || calls.contains("oidc")) {
            kinds.addAll(List.of(OIDC_CONFIGURATION, USER_INFO, LOGOUT));
            if (calls.contains("oidc.clientRegistrationEndpoint")) {
                kinds.add(OIDC_REGISTER);
            }
        }
        List<Endpoint> endpoints = new ArrayList<>();
        for (Kind kind : kinds) {
            String path = Optional.ofNullable(kind.setting()).map(settings::get)
                    .or(() -> Optional.ofNullable(kind.property()).filter(property -> bootSettings)
                            .flatMap(property -> context.properties().get(PROPERTIES + property)))
                    .orElse(kind.path());
            CodeRef filter = CodeRef.ofClass(FILTERS + kind.filter());
            AuthorizationLocation check = check(kind.caller());
            for (String method : kind.methods()) {
                endpoints.add(new Endpoint(Ingress.of(method, path, filter), check));
            }
        }
        return endpoints;
    }

    /**
     * One check per kind of caller, shared by the endpoints that ask for it, so they read as one.
     */
    private static AuthorizationLocation check(Caller caller) {
        String who = switch (caller) {
            case ANYONE -> "public: answers before authorization";
            case USER -> "signed-in user";
            case CLIENT -> "authenticated client";
            case SCOPE_OPENID, SCOPE_CLIENT_CREATE -> "bearer token";
        };
        Requirement requirement = switch (caller) {
            case ANYONE -> Requirement.permitAll();
            case SCOPE_OPENID -> Requirement.anyAuthority(List.of("SCOPE_openid"));
            case SCOPE_CLIENT_CREATE -> Requirement.anyAuthority(List.of("SCOPE_client.create"));
            default -> Requirement.authenticated();
        };
        return new AuthorizationLocation("location:HTTP_REQUEST:authorization-server:" + caller.name()
                .toLowerCase(Locale.ROOT), MECHANISM + " (" + who + ")", AuthorizationLocation.Scope.HTTP_REQUEST,
                AuthorizationLocation.Phase.PRE, requirement, CodeRef.ofClass(CONFIGURER), null, null,
                AuthorizationLocation.Denial.THROW, false);
    }
}
