package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Might;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthoritySource.Freshness;
import dev.crain.authtracer.graph.AuthoritySource.Kind;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.ConfigurationProperties;
import dev.crain.authtracer.scan.EnclosingMethods;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.GroovyCalls;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Where a service's authorities come from, read from its {@code HttpSecurity} or {@code ServerHttpSecurity}
 * configuration (RX-09, SRC-27 to SRC-29: the reactive DSL has the same calls), in Java, the Kotlin DSL or dynamic
 * Groovy, and from Spring gRPC's {@code GrpcSecurity} (decision 0032).
 */
@Supports(Feature.AUTHORITY_SOURCE)
final class AuthenticationMechanisms {

    private static final String SERVER_HTTP_SECURITY = "org.springframework.security.config.web.server.ServerHttpSecurity";
    private static final Set<String> RESOURCE_SERVER = Set.of(SpringNames.RESOURCE_SERVER_CONFIGURER,
            SERVER_HTTP_SECURITY + "$OAuth2ResourceServerSpec",
            "org.springframework.security.config.annotation.web.OAuth2ResourceServerDsl",
            "org.springframework.security.config.web.server.ServerOAuth2ResourceServerDsl",
            "org.springframework.grpc.server.security.OAuth2ResourceServerConfigurer");
    /**
     * The Java and Kotlin DSLs (Kotlin: {@code http { httpBasic { } }}).
     */
    private static final Set<String> HTTP = Set.of(SpringNames.HTTP_SECURITY, SERVER_HTTP_SECURITY,
            "org.springframework.security.config.annotation.web.HttpSecurityDsl",
            "org.springframework.security.config.web.server.ServerHttpSecurityDsl",
            SecurityDsl.GRPC_SECURITY);
    /**
     * The DSL of each web stack: an application runs one, and the other's chains never run.
     */
    private static final Set<String> REACTIVE_DSL = Set.of(SERVER_HTTP_SECURITY,
            SERVER_HTTP_SECURITY + "$OAuth2ResourceServerSpec",
            "org.springframework.security.config.web.server.ServerOAuth2ResourceServerDsl",
            "org.springframework.security.config.web.server.ServerHttpSecurityDsl");
    private static final Set<String> SERVLET_DSL = Set.of(SpringNames.HTTP_SECURITY,
            SpringNames.RESOURCE_SERVER_CONFIGURER,
            "org.springframework.security.config.annotation.web.OAuth2ResourceServerDsl",
            "org.springframework.security.config.annotation.web.HttpSecurityDsl");

    private static final String RESOURCE_AUTHENTICATION =
            "org.springframework.security.oauth2.server.resource.authentication.";
    /**
     * What an {@code AuthenticationManagerResolver} (multi-tenancy) hands requests to.
     */
    private static final Set<String> JWT_MANAGERS = Set.of(RESOURCE_AUTHENTICATION + "JwtAuthenticationProvider",
            RESOURCE_AUTHENTICATION + "JwtIssuerAuthenticationManagerResolver",
            RESOURCE_AUTHENTICATION + "JwtReactiveAuthenticationManager",
            RESOURCE_AUTHENTICATION + "JwtIssuerReactiveAuthenticationManagerResolver");
    private static final Set<String> OPAQUE_MANAGERS = Set.of(
            RESOURCE_AUTHENTICATION + "OpaqueTokenAuthenticationProvider",
            RESOURCE_AUTHENTICATION + "OpaqueTokenReactiveAuthenticationManager");

    /**
     * Spring Boot's OAuth2 chains, which replace its default one (4.1.1).
     */
    private static final Set<String> BOOT_RESOURCE_SERVER_CHAINS = Set.of(
            "org.springframework.boot.security.oauth2.server.resource.autoconfigure.web."
                    + "OAuth2ResourceServerWebSecurityAutoConfiguration",
            "org.springframework.boot.security.oauth2.server.resource.autoconfigure.web.reactive."
                    + "ReactiveOAuth2ResourceServerWebSecurityAutoConfiguration");
    private static final Set<String> BOOT_CLIENT_CHAINS = Set.of(
            "org.springframework.boot.security.oauth2.client.autoconfigure.servlet."
                    + "OAuth2ClientWebSecurityAutoConfiguration",
            "org.springframework.boot.security.oauth2.client.autoconfigure.reactive."
                    + "ReactiveOAuth2ClientWebSecurityAutoConfiguration");
    private static final String JWT_PROPERTIES = "spring.security.oauth2.resourceserver.jwt.";
    private static final String JWT_DECODER = "org.springframework.security.oauth2.jwt.JwtDecoder";
    private static final String REACTIVE_JWT_DECODER = "org.springframework.security.oauth2.jwt.ReactiveJwtDecoder";
    private static final String INTROSPECTION = "org.springframework.security.oauth2.server.resource.introspection.";
    private static final String INTROSPECTOR = INTROSPECTION + "OpaqueTokenIntrospector";
    private static final String REACTIVE_INTROSPECTOR = INTROSPECTION + "ReactiveOpaqueTokenIntrospector";
    private static final String REGISTRATION = "org.springframework.security.oauth2.client.registration.";
    private static final Set<String> CLIENT_REGISTRATIONS = Set.of(REGISTRATION + "ClientRegistrationRepository",
            REGISTRATION + "ReactiveClientRegistrationRepository");

    /**
     * A way in, the authorities it gives and how fresh they are; the XML namespace's element for it.
     */
    private enum Mechanism {
        JWT(Kind.JWT_CLAIMS, "OAuth2 Resource Server (JWT)", "jwt", Freshness.SNAPSHOT),
        OPAQUE_TOKEN(Kind.OPAQUE_TOKEN_INTROSPECTION, "OAuth2 Resource Server (opaque token)", "opaque-token",
                Freshness.LIVE),
        OAUTH2_LOGIN(Kind.IDENTITY_PROVIDER, "OAuth2 Login (session)", "oauth2-login", Freshness.SNAPSHOT),
        SAML2_LOGIN(Kind.IDENTITY_PROVIDER, "SAML 2.0 Login (session)", "saml2-login", Freshness.SNAPSHOT),
        /**
         * The client certificate's subject, looked up per call ({@code SslContextPreAuthenticationExtractor}).
         */
        GRPC_PREAUTH(Kind.USER_DETAILS, "gRPC client certificate (preauth)", null, Freshness.LIVE),
        /**
         * Looked up by the certificate's subject on every request: {@code X509Configurer} keeps the context per
         * request, and the reactive filter saves none.
         */
        X509(Kind.USER_DETAILS, "X.509 client certificate", "x509", Freshness.LIVE),
        /**
         * Its own repository keeps the context for the request only, unless it is given one that keeps it.
         */
        HTTP_BASIC(Kind.USER_DETAILS, "HTTP Basic", "http-basic", null),
        /**
         * Decision 0074: these look the user up when they log in, and the chain keeps what they set unless it is
         * stateless.
         */
        FORM_LOGIN(Kind.USER_DETAILS, "Form login", "form-login", null),
        /**
         * Reloads the user through the {@code UserDetailsService} when the cookie logs them in.
         */
        REMEMBER_ME(Kind.USER_DETAILS, "Remember-me", "remember-me", null),
        ONE_TIME_TOKEN(Kind.USER_DETAILS, "One-time token login", null, null),
        /**
         * {@code WebAuthnAuthenticationProvider} loads the user through the {@code UserDetailsService}.
         */
        WEBAUTHN(Kind.USER_DETAILS, "Passkeys (WebAuthn)", null, null),
        /**
         * The container's user, with the roles {@code mappableRoles} names; the pre-authentication filter saves the
         * context to the session.
         */
        JEE(Kind.USER_DETAILS, "Java EE container pre-authentication", "jee", null);

        final Kind kind;
        final String label;
        final String xmlElement;
        /**
         * {@code null} when it depends on whether the chain keeps the context.
         */
        final Freshness freshness;

        Mechanism(Kind kind, String label, String xmlElement, Freshness freshness) {
            this.kind = kind;
            this.label = label;
            this.xmlElement = xmlElement;
            this.freshness = freshness;
        }

        /**
         * The way in, in a chain that keeps what it sets for the requests after the login or doesn't.
         */
        Way way(boolean kept) {
            if (freshness != null) {
                return new Way(kind, freshness, label);
            }
            if (this == HTTP_BASIC) {
                return kept ? new Way(kind, Freshness.SNAPSHOT, label + " (session)")
                        : new Way(kind, Freshness.LIVE, label);
            }
            String how = kept ? "session" : "stateless";
            return new Way(kind, kept ? Freshness.SNAPSHOT : Freshness.LIVE, label.endsWith(")")
                    ? label.substring(0, label.length() - 1) + ", " + how + ")" : label + " (" + how + ")");
        }

        /**
         * The DSL call that adds it, which its own repository is set in.
         */
        String dsl() {
            return switch (this) {
                case HTTP_BASIC -> "httpBasic";
                case FORM_LOGIN -> "formLogin";
                case ONE_TIME_TOKEN -> "oneTimeTokenLogin";
                default -> name();
            };
        }
    }

    /**
     * A way in: the authorities it gives, how fresh they are, and how the authority source names it.
     */
    private record Way(Kind kind, Freshness freshness, String label) {
    }

    /**
     * The {@code HttpSecurity} (and {@code ServerHttpSecurity}, Kotlin DSL) calls that add a mechanism.
     */
    private static final Map<String, Mechanism> HTTP_MECHANISMS = Map.of("oauth2Login", Mechanism.OAUTH2_LOGIN,
            "saml2Login", Mechanism.SAML2_LOGIN, "x509", Mechanism.X509, "httpBasic", Mechanism.HTTP_BASIC,
            "formLogin", Mechanism.FORM_LOGIN, "rememberMe", Mechanism.REMEMBER_ME, "oneTimeTokenLogin",
            Mechanism.ONE_TIME_TOKEN, "webAuthn", Mechanism.WEBAUTHN, "jee", Mechanism.JEE);

    private static final String AUTHENTICATION = "org.springframework.security.core.Authentication";
    /**
     * A snapshot can't be revoked; what the scan can't read may be one.
     */
    private static final List<Freshness> STALEST = List.of(Freshness.SNAPSHOT, Freshness.UNKNOWN, Freshness.LIVE);

    private AuthenticationMechanisms() {
    }

    /**
     * @param filters the filters requests pass that authenticate them (decision 0071)
     */
    @Supports(Feature.FINDING_AUTHORITIES_IN_CODE)
    @Might("Record one source per SecurityFilterChain when a service mixes mechanisms")
    static AuthoritySource detect(ScanContext context, SecurityXml.Config xml, GraphBuilder graph,
            List<FilterAuthentication.Mechanism> filters) {
        List<Way> ways = new ArrayList<>();
        boolean reactive = WebStack.reactive(context);
        Set<String> otherStack = reactive ? SERVLET_DSL : REACTIVE_DSL;
        boolean managerResolver = false;
        Set<Kind> resolved = new LinkedHashSet<>();
        EnclosingMethods enclosing = new EnclosingMethods(context);
        BuiltValues values = new BuiltValues(context, enclosing);
        ContextRepositories repositories = new ContextRepositories(context, reactive, enclosing, values);
        AuthenticationProviders providers = new AuthenticationProviders(context, enclosing, values);
        Map<JavaSootMethod, Set<Mechanism>> added = new LinkedHashMap<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                    if (invoke.isEmpty()) {
                        continue;
                    }
                    String declaring = invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
                    String name = invoke.get().getMethodSignature().getName();
                    List<Immediate> args = invoke.get().getArgs();
                    Optional<GroovyCalls.Call> groovy = GroovyCalls.of(invoke.get());
                    if (groovy.isPresent()) {
                        // Dynamic Groovy: http.httpBasic(..), and it.jwt(..) in an oauth2ResourceServer closure,
                        // whose receiver is untyped.
                        name = groovy.get().name();
                        args = groovy.get().args();
                        String receiver = groovy.get().receiverType().toString();
                        declaring = receiver.equals("java.lang.Object") ? untyped(name) : receiver;
                    }
                    if (otherStack.contains(declaring)) {
                        continue;
                    }
                    Optional<Mechanism> mechanism = mechanism(declaring, name);
                    repositories.read(method, stmt, declaring, name, args);
                    providers.read(method, stmt, declaring, name, args);
                    if (mechanism.isPresent()) {
                        added.computeIfAbsent(method, key -> new LinkedHashSet<>()).add(mechanism.get());
                    }
                    else if (RESOURCE_SERVER.contains(declaring) && name.equals("authenticationManagerResolver")) {
                        managerResolver = true;
                    }
                    else if (JWT_MANAGERS.contains(declaring)) {
                        resolved.add(Kind.JWT_CLAIMS);
                    }
                    else if (OPAQUE_MANAGERS.contains(declaring)) {
                        resolved.add(Kind.OPAQUE_TOKEN_INTROSPECTION);
                    }
                }
            }
        }
        // Decision 0074: each way in a chain adds, as fresh as that chain keeps it.
        added.forEach((method, mechanisms) -> mechanisms.forEach(mechanism -> ways.add(mechanism.way(
                repositories.keeps(method, mechanism.dsl())))));
        repositories.findings().forEach(graph::finding);
        // Decision 0036: the XML namespace's login elements, whose chains keep the context in the session.
        for (String element : xml.mechanisms()) {
            Arrays.stream(Mechanism.values()).filter(mechanism -> element.equals(mechanism.xmlElement)).findFirst()
                    .ifPresent(mechanism -> ways.add(mechanism.way(mechanism != Mechanism.HTTP_BASIC)));
        }
        if (managerResolver) {
            // The resolver picks a manager per request (per tenant); each of them is a way in.
            for (Kind kind : resolved) {
                Mechanism mechanism = kind == Kind.JWT_CLAIMS ? Mechanism.JWT : Mechanism.OPAQUE_TOKEN;
                ways.add(new Way(kind, mechanism.freshness, "OAuth2 Resource Server (" + (kind == Kind.JWT_CLAIMS
                        ? "JWT" : "opaque token") + ", per AuthenticationManagerResolver)"));
            }
        }
        boolean defaultChain = ways.isEmpty() && defaultChain(context, reactive);
        if (defaultChain) {
            Optional<Mechanism> boot = bootOAuth2Chain(context);
            boot.ifPresent(mechanism -> ways.add(mechanism.way(true)));
            if (!reactive && boot.filter(mechanism -> mechanism != Mechanism.OAUTH2_LOGIN).isPresent()
                    && clientRegistrations(context)) {
                graph.finding(competingBootChains());
            }
        }
        if (defaultChain && ways.isEmpty()) {
            // The default chain (Boot's, or Spring Security's for @EnableWebSecurity/@EnableWebFluxSecurity) logs in
            // with a form or HTTP Basic, and keeps the context in the session.
            ways.add(Mechanism.FORM_LOGIN.way(true));
            ways.add(Mechanism.HTTP_BASIC.way(false));
        }
        // Decision 0074: what checks the credentials, when it isn't the UserDetailsService. The global manager's
        // providers check what form login and HTTP Basic are given.
        boolean passwords = ways.stream().anyMatch(way -> way.label().startsWith(Mechanism.FORM_LOGIN.label)
                || way.label().startsWith(Mechanism.HTTP_BASIC.label));
        List<AuthenticationProviders.Provider> applied = providers.providers().stream()
                .filter(provider -> !provider.global() || passwords).toList();
        applied.forEach(provider -> ways.add(new Way(provider.kind(), provider.freshness(), provider.label())));
        // Decision 0056: WS-Security's UsernameToken, looked up through the UserDetailsService for each SOAP message.
        WsSecurity.detect(context).forEach(found -> ways.add(new Way(Kind.USER_DETAILS, found.freshness(),
                found.label())));
        providers.findings(applied).forEach(graph::finding);
        // Decision 0071: filters of the application's own that authenticate, beside any chain, the default one too.
        for (FilterAuthentication.Mechanism filter : filters) {
            ways.add(new Way(Kind.CUSTOM_FILTER, filter.freshness(), filter.label()));
            if (filter.afterRule()) {
                // The checks after it see what it sets, so it stays a way in; the request rules never do.
                graph.finding(new Finding(Finding.Kind.AUTHORITIES_IN_CODE, filter.label() + " authenticates after"
                        + " the AuthorizationFilter: the request rules have already decided, for a caller who hadn't"
                        + " signed in, so what it sets counts only for the checks after them (method security, the"
                        + " handler's own)", filter.site()));
            }
        }
        if (ways.isEmpty()) {
            return AuthoritySource.UNKNOWN;
        }
        // A request may come in through any of them: the service's authorities are as stale as the stalest way's, and
        // its kind is that way's.
        Way stalest = ways.stream().min(Comparator.comparing(way -> STALEST.indexOf(way.freshness()))).orElseThrow();
        Freshness freshness = stalest.freshness();
        Kind kind = stalest.kind();
        StringBuilder detail = new StringBuilder(String.join(", ", ways.stream().map(Way::label).distinct()
                .toList()));
        Set<Kind> kinds = ways.stream().map(Way::kind).collect(Collectors.toSet());
        if (!kinds.contains(Kind.JWT_CLAIMS)) {
            return new AuthoritySource(kind, freshness, detail.toString());
        }
        JwtSettings.Read jwt = JwtSettings.read(context, graph, reactive);
        detail.append("; ").append(jwt.text());
        // Decision 0073: when tokens are the only way in, and the scan reads how each becomes authorities.
        boolean onlyTokens = kinds.equals(Set.of(Kind.JWT_CLAIMS)) && !xml.mechanisms().contains("jwt");
        return new AuthoritySource(kind, freshness, detail.toString(), null,
                onlyTokens && jwt.read() ? granted(jwt.jwt()) : null, jwt.jwt());
    }

    /**
     * What a request with a JWT can carry: each claim's values with its prefix, the {@code FACTOR_BEARER} factor
     * {@code JwtAuthenticationConverter} adds, and, for a request without a token, the {@code ROLE_ANONYMOUS} of
     * {@code AnonymousAuthenticationFilter}; any authority when a claim's values are kept as they are (prefix
     * {@code ""}).
     */
    private static SortedSet<String> granted(AuthoritySource.Jwt jwt) {
        SortedSet<String> granted = new TreeSet<>(List.of("FACTOR_BEARER", "ROLE_ANONYMOUS"));
        for (AuthoritySource.ClaimAuthorities claim : jwt.authorities()) {
            if (claim.prefix() == null || claim.prefix().isEmpty()) {
                return null;
            }
            granted.add(claim.prefix() + "*");
        }
        return granted;
    }

    /**
     * Decision 0073: a check that asks for authorities no request can carry, e.g. {@code hasRole('ADMIN')} where the
     * service's JWTs map only {@code scope} to {@code SCOPE_*}, denies every caller. Run once the role hierarchy has
     * widened the checks; the requirement is left as written. Provided checks are enforced outside Spring Security,
     * and Splits are judged by their parts.
     */
    @Supports(Feature.FINDING_ALWAYS_DENIED)
    static void ungranted(GraphBuilder graph, AuthoritySource source) {
        if (source.granted() == null) {
            return;
        }
        for (AuthorizationLocation location : List.copyOf(graph.nodes()).stream()
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> !location.mechanism().startsWith("Provided")
                        && !graph.splits().containsKey(location.id()))
                .toList()) {
            SortedSet<String> missing = source.unmet(location.requirement());
            if (!missing.isEmpty()) {
                String where = location.routePattern() != null ? location.routePattern() : location.target().key();
                graph.finding(new Finding(Finding.Kind.ALWAYS_DENIED, location.mechanism() + " on " + where
                        + " asks for " + String.join(" or ", missing) + ", which no request carries: the service's"
                        + " JWTs grant only " + String.join(", ", source.granted()) + ", so it denies every caller",
                        location.target()));
            }
        }
    }

    /**
     * The mechanism a DSL call adds: a resource server's {@code jwt}/{@code opaqueToken}, gRPC's {@code preauth}, or a
     * login call on the chain.
     */
    private static Optional<Mechanism> mechanism(String declaring, String name) {
        if (RESOURCE_SERVER.contains(declaring)) {
            return name.equals("jwt") ? Optional.of(Mechanism.JWT)
                    : name.equals("opaqueToken") ? Optional.of(Mechanism.OPAQUE_TOKEN) : Optional.empty();
        }
        if (declaring.equals(SecurityDsl.GRPC_SECURITY) && name.equals("preauth")) {
            return Optional.of(Mechanism.GRPC_PREAUTH);
        }
        return HTTP.contains(declaring) ? Optional.ofNullable(HTTP_MECHANISMS.get(name)) : Optional.empty();
    }

    /**
     * Spring Boot's OAuth2 chains, which take the default chain's place: a resource server's when a JWT decoder or an
     * introspector comes from properties or the application, else OAuth2 Login when client registrations do. Boot's
     * {@code @ConditionalOnBean(JwtDecoder.class)} and the others match a bean of the type or a subtype, as its
     * {@code @Bean} method declares it (4.1.1 {@code OnBeanCondition}: {@code getBeanNamesForType}), so a
     * {@code RestClientOpaqueTokenIntrospector} or a decoder class of the application's counts; the reactive chains ask
     * for the reactive types.
     */
    private static Optional<Mechanism> bootOAuth2Chain(ScanContext context) {
        if (!context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION)) {
            return Optional.empty();
        }
        ConfigurationProperties properties = context.properties();
        boolean reactive = WebStack.reactive(context);
        if (onClasspath(context, BOOT_RESOURCE_SERVER_CHAINS)) {
            if (Set.of("jwk-set-uri", "issuer-uri", "public-key-location").stream()
                    .anyMatch(key -> properties.get(JWT_PROPERTIES + key).isPresent())
                    || declaresBean(context, reactive ? REACTIVE_JWT_DECODER : JWT_DECODER)) {
                return Optional.of(Mechanism.JWT);
            }
            if (properties.get("spring.security.oauth2.resourceserver.opaquetoken.introspection-uri").isPresent()
                    || declaresBean(context, reactive ? REACTIVE_INTROSPECTOR : INTROSPECTOR)) {
                return Optional.of(Mechanism.OPAQUE_TOKEN);
            }
        }
        return clientRegistrations(context) ? Optional.of(Mechanism.OAUTH2_LOGIN) : Optional.empty();
    }

    /**
     * Boot's OAuth2 client chain applies: its auto-configuration, Spring Security's client (its
     * {@code @ConditionalOnClass}) and registrations.
     */
    private static boolean clientRegistrations(ScanContext context) {
        return onClasspath(context, BOOT_CLIENT_CHAINS) && context.findClass(REGISTRATION + "ClientRegistration")
                .isPresent()
                && (context.properties().hasPrefix("spring.security.oauth2.client.registration.")
                        || !SpringBeans.beanMethodsOf(context, CLIENT_REGISTRATIONS).isEmpty());
    }

    /**
     * Both of Boot's servlet chains apply: each is {@code @ConditionalOnDefaultWebSecurity}, so the first made is the
     * one, and 4.1.1's {@code AutoConfigurationSorter} leaves the two in the order it found them (both go before
     * {@code SecurityAutoConfiguration}, and nothing orders them between themselves): their jars' order on the
     * classpath. The graph keeps the resource server's, the weaker reading (its metadata answers anyone).
     */
    private static Finding competingBootChains() {
        return new Finding(Finding.Kind.OPAQUE_CONFIG, "Spring Boot makes either its resource server chain or its"
                + " OAuth2 Login chain here, since a resource server and OAuth2 client registrations are both"
                + " configured: whichever auto-configuration's jar comes first on the classpath. The graph shows the"
                + " resource server's; with OAuth2 Login's, callers sign in through the identity provider, and "
                + ResourceServerMetadata.PATH + " needs a login like every other request",
                CodeRef.ofClass(BOOT_CLIENT_CHAINS.stream().filter(name -> name.contains(".servlet.")).findFirst()
                        .orElseThrow()));
    }

    /**
     * Whether one of Spring Boot's OAuth2 chains takes the default chain's place: a resource server's, OAuth2 Login's
     * or the authorization server's. Boot 4.1.1 configures each before {@code ManagementWebSecurityAutoConfiguration}
     * (and its reactive twin), so Actuator's own chain, which lets everyone reach health, isn't made.
     */
    static boolean bootOAuth2DefaultChain(ScanContext context) {
        boolean reactive = WebStack.reactive(context);
        return defaultChain(context, reactive) && (bootOAuth2Chain(context).isPresent()
                || !reactive && AuthorizationServerEndpoints.bootChains(context));
    }

    /**
     * Whether Spring Boot's servlet resource server chain is the application's: no chain of its own, and a JWT or
     * opaque token resource server configured.
     */
    @Supports(Feature.LIBRARY_ENDPOINTS)
    static boolean bootResourceServerChain(ScanContext context) {
        return !WebStack.reactive(context) && defaultChain(context, false) && bootOAuth2Chain(context)
                .filter(mechanism -> mechanism == Mechanism.JWT || mechanism == Mechanism.OPAQUE_TOKEN).isPresent();
    }

    private static boolean onClasspath(ScanContext context, Set<String> classes) {
        return classes.stream().anyMatch(name -> context.findClass(name).isPresent());
    }

    private static boolean declaresBean(ScanContext context, String type) {
        return !SpringBeans.beanMethodsOf(context, Set.of(type)).isEmpty();
    }

    /**
     * Whether the application gets a default filter chain: security is enabled for its web stack (by annotation, or
     * by Boot's auto-configuration) and it declares no chain of that stack. A chain of the other stack never runs.
     */
    private static boolean defaultChain(ScanContext context, boolean reactive) {
        boolean enabled = context.anyClassAnnotated(reactive ? WebStack.ENABLE_WEBFLUX_SECURITY
                : WebStack.ENABLE_WEB_SECURITY) || context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION);
        boolean declaresChain = !SpringBeans.beanMethodsOf(context, Set.of(reactive
                ? WebStack.SECURITY_WEB_FILTER_CHAIN : WebStack.SECURITY_FILTER_CHAIN)).isEmpty();
        return enabled && !declaresChain && context.findClass(AUTHENTICATION).isPresent();
    }

    /**
     * The class a dynamic Groovy call on an untyped receiver (a closure's {@code it}) is read as being on, by its name.
     */
    private static String untyped(String name) {
        return switch (name) {
            case "jwt", "opaqueToken", "authenticationManagerResolver" -> SpringNames.RESOURCE_SERVER_CONFIGURER;
            case "sessionCreationPolicy" -> ContextRepositories.SESSION_MANAGEMENT;
            case "securityContextRepository" -> ContextRepositories.UNTYPED;
            default -> SpringNames.HTTP_SECURITY;
        };
    }
}
