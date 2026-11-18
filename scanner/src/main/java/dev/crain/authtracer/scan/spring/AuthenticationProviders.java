package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthoritySource.Freshness;
import dev.crain.authtracer.graph.AuthoritySource.Kind;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.EnclosingMethods;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0074: what checks the logins' credentials when it isn't the {@code UserDetailsService}: an
 * {@code AuthenticationProvider} or {@code AuthenticationManager} of the application's (SRC-25 also a
 * {@code RememberMeServices}), a JAAS login (SRC-24), an LDAP directory (SRC-20), CAS. What AuthTracer can't read is
 * an OPAQUE_CONFIG finding and a way in whose authorities, and how fresh they are, are unknown.
 * <p>
 * Spring Security 7.1.1 (javap): the global {@code AuthenticationManager} takes the application's one
 * {@code AuthenticationProvider} bean ({@code InitializeAuthenticationProviderBeanManagerConfigurer}; none when there
 * are several), which keeps the {@code UserDetailsService} bean out; else that bean
 * ({@code InitializeUserDetailsBeanManagerConfigurer}); else, when that builds nothing, the
 * {@code AuthenticationManager} bean ({@code AuthenticationConfiguration#getAuthenticationManager}). Every chain's
 * manager has it as its parent, after the chain's own providers. Form login and HTTP Basic hand it their
 * {@code UsernamePasswordAuthenticationToken}; the other ways in add providers of their own.
 * {@code AbstractJaasAuthenticationProvider} logs in through a {@code LoginContext} and grants what its
 * {@code AuthorityGranter}s return for the subject's principals; {@code CasAuthenticationFilter} saves the context to
 * the session.
 */
@Supports(Feature.AUTHORITY_SOURCE)
final class AuthenticationProviders {

    private static final String AUTHENTICATION = "org.springframework.security.authentication.";
    private static final String CONFIGURERS = "org.springframework.security.config.annotation.web.configurers.";
    private static final String RESOURCE_SERVER = CONFIGURERS + "oauth2.server.resource.OAuth2ResourceServerConfigurer";
    private static final String KOTLIN = "org.springframework.security.config.annotation.web.";
    private static final String SERVER = "org.springframework.security.config.web.server.";
    private static final String MANAGER_BUILDER =
            "org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder";
    /**
     * The calls that give a chain, or a resource server's tokens, their own provider or manager.
     */
    private static final Set<String> CHAIN = Set.of(SpringNames.HTTP_SECURITY + "#authenticationProvider",
            SpringNames.HTTP_SECURITY + "#authenticationManager", SERVER + "ServerHttpSecurity#authenticationManager",
            KOTLIN + "HttpSecurityDsl#setAuthenticationManager", SERVER + "ServerHttpSecurityDsl#setAuthenticationManager",
            SERVER + "ServerHttpSecurity$FormLoginSpec#authenticationManager",
            SERVER + "ServerHttpSecurity$HttpBasicSpec#authenticationManager",
            RESOURCE_SERVER + "$JwtConfigurer#authenticationManager",
            RESOURCE_SERVER + "$OpaqueTokenConfigurer#authenticationManager",
            KOTLIN + "oauth2.resourceserver.JwtDsl#setAuthenticationManager",
            KOTLIN + "oauth2.resourceserver.OpaqueTokenDsl#setAuthenticationManager",
            SERVER + "ServerHttpSecurity$OAuth2ResourceServerSpec$JwtSpec#authenticationManager");
    private static final Set<String> REMEMBER_ME = Set.of(CONFIGURERS + "RememberMeConfigurer#rememberMeServices",
            KOTLIN + "RememberMeDsl#setRememberMeServices");
    private static final Set<String> GLOBAL = Set.of(MANAGER_BUILDER + "#authenticationProvider",
            MANAGER_BUILDER + "#parentAuthenticationManager");

    private static final Set<String> PROVIDER_TYPES = Set.of(AUTHENTICATION + "AuthenticationProvider");
    private static final Set<String> MANAGER_TYPES = Set.of(AUTHENTICATION + "AuthenticationManager",
            AUTHENTICATION + "ReactiveAuthenticationManager");
    private static final String PROVIDER_MANAGER = AUTHENTICATION + "ProviderManager";
    private static final Set<String> JAAS = Set.of(AUTHENTICATION + "jaas.DefaultJaasAuthenticationProvider",
            AUTHENTICATION + "jaas.JaasAuthenticationProvider");
    private static final String LDAP = "org.springframework.security.ldap.authentication.";
    private static final Set<String> LDAP_PROVIDERS = Set.of(LDAP + "LdapAuthenticationProvider",
            LDAP + "ad.ActiveDirectoryLdapAuthenticationProvider");
    private static final Set<String> LDAP_FACTORIES = Set.of(
            "org.springframework.security.config.ldap.LdapBindAuthenticationManagerFactory",
            "org.springframework.security.config.ldap.LdapPasswordComparisonAuthenticationManagerFactory");
    private static final String CAS_FILTER = "org.springframework.security.cas.web.CasAuthenticationFilter";
    private static final String WEB_AUTHENTICATION = "org.springframework.security.web.authentication.";
    private static final String RESOURCE_AUTHENTICATION =
            "org.springframework.security.oauth2.server.resource.authentication.";
    /**
     * Spring's providers, managers and remember-me services that read what the way in they serve does, or what the
     * {@code UserDetailsService} has: the way in already says.
     */
    private static final Set<String> READ = Set.of(AUTHENTICATION + "dao.DaoAuthenticationProvider",
            AUTHENTICATION + "AnonymousAuthenticationProvider", AUTHENTICATION + "RememberMeAuthenticationProvider",
            AUTHENTICATION + "ott.OneTimeTokenAuthenticationProvider",
            AUTHENTICATION + "UserDetailsRepositoryReactiveAuthenticationManager",
            RESOURCE_AUTHENTICATION + "JwtAuthenticationProvider",
            RESOURCE_AUTHENTICATION + "JwtReactiveAuthenticationManager",
            RESOURCE_AUTHENTICATION + "OpaqueTokenAuthenticationProvider",
            RESOURCE_AUTHENTICATION + "OpaqueTokenReactiveAuthenticationManager",
            WEB_AUTHENTICATION + "preauth.PreAuthenticatedAuthenticationProvider",
            "org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationProvider",
            "org.springframework.security.cas.authentication.CasAuthenticationProvider",
            WEB_AUTHENTICATION + "rememberme.TokenBasedRememberMeServices",
            WEB_AUTHENTICATION + "rememberme.PersistentTokenBasedRememberMeServices",
            WEB_AUTHENTICATION + "NullRememberMeServices");
    /**
     * Library calls that return the manager Spring builds anyway.
     */
    private static final Set<String> BUILT = Set.of(
            "org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration"
                    + "#getAuthenticationManager",
            SpringNames.HTTP_SECURITY + "#getSharedObject", MANAGER_BUILDER + "#build", MANAGER_BUILDER + "#getObject",
            MANAGER_BUILDER + "#getOrBuild");

    /**
     * A way the logins' credentials are checked.
     *
     * @param global the global {@code AuthenticationManager}'s, which the chains' form login and HTTP Basic reach;
     *        else a chain's, a resource server's or remember-me's own
     */
    record Provider(Kind kind, Freshness freshness, String label, boolean global) {
    }

    private final ScanContext context;
    private final EnclosingMethods enclosing;
    private final BuiltValues values;
    private final Map<String, Provider> providers = new LinkedHashMap<>();
    /**
     * The OPAQUE_CONFIG findings for what each provider's way in leaves unread.
     */
    private final Map<String, List<Finding>> unread = new LinkedHashMap<>();

    AuthenticationProviders(ScanContext context, EnclosingMethods enclosing, BuiltValues values) {
        this.context = context;
        this.enclosing = enclosing;
        this.values = values;
    }

    /**
     * Records the provider, manager or remember-me services the call hands Spring, if it hands one.
     *
     * @param declaring the class the call is on, as {@code AuthenticationMechanisms} reads it
     */
    void read(JavaSootMethod method, Stmt stmt, String declaring, String name, List<Immediate> args) {
        String call = declaring + "#" + name;
        CodeRef site = enclosing.site(method, MethodNames.codeRef(method.getSignature(), stmt));
        if (call.equals(MANAGER_BUILDER + "#ldapAuthentication")) {
            add(ldap());
        }
        else if (args.size() == 1 && (CHAIN.contains(call) || GLOBAL.contains(call))) {
            classify(values.of(method, args.getFirst()), GLOBAL.contains(call), site, "Authenticated by ");
        }
        else if (args.size() == 1 && REMEMBER_ME.contains(call)) {
            classify(values.of(method, args.getFirst()), false, site, "Remember-me through ");
        }
    }

    /**
     * The ways the logins' credentials are checked, with the beans the global manager takes and the CAS filters the
     * application makes.
     */
    List<Provider> providers() {
        List<JavaSootMethod> providerBeans = beanMethods(PROVIDER_TYPES);
        List<JavaSootClass> providerComponents = components(PROVIDER_TYPES);
        boolean oneProvider = providerBeans.size() + providerComponents.size() == 1;
        beans(oneProvider ? providerBeans : beanMethods(MANAGER_TYPES),
                oneProvider ? providerComponents : components(MANAGER_TYPES));
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (method.hasBody() && method.getBody().getStmts().stream().anyMatch(stmt -> stmt instanceof
                        AbstractDefinitionStmt definition && definition.getRightOp() instanceof JNewExpr created
                        && created.getType().getFullyQualifiedName().equals(CAS_FILTER))) {
                    add(new Provider(Kind.IDENTITY_PROVIDER, Freshness.SNAPSHOT, "CAS (session)", false));
                }
            }
        }
        return List.copyOf(providers.values());
    }

    /**
     * The OPAQUE_CONFIG findings for the providers whose ways in the service has.
     */
    List<Finding> findings(List<Provider> applied) {
        List<Finding> findings = new ArrayList<>();
        applied.forEach(provider -> findings.addAll(unread.getOrDefault(provider.label(), List.of())));
        return findings;
    }

    private List<JavaSootMethod> beanMethods(Set<String> types) {
        return SpringBeans.beanMethodsOf(context, types).stream().filter(JavaSootMethod::hasBody).toList();
    }

    private List<JavaSootClass> components(Set<String> types) {
        return context.applicationClasses().stream().filter(cls -> context.hasAnnotation(cls, SpringNames.COMPONENT)
                && SpringBeans.assignable(context, cls.getType(), types)).toList();
    }

    private void beans(List<JavaSootMethod> beans, List<JavaSootClass> components) {
        for (JavaSootMethod bean : beans) {
            classify(values.returnedBy(bean), true, MethodNames.codeRef(bean.getSignature()), "Authenticated by ");
        }
        for (JavaSootClass component : components) {
            custom(MethodNames.simpleName(component.getName()), true, CodeRef.ofClass(component.getName()),
                    "Authenticated by ");
        }
    }

    /**
     * @param how how a provider AuthTracer can't read is named: {@code Authenticated by }
     */
    private void classify(List<BuiltValues.Source> sources, boolean global, CodeRef site, String how) {
        for (BuiltValues.Source source : sources) {
            switch (source) {
                case BuiltValues.Created created -> created(created, global, site, how);
                case BuiltValues.Called called -> {
                    String owner = called.call().getMethodSignature().getDeclClassType().getFullyQualifiedName();
                    String name = called.call().getMethodSignature().getName();
                    if (LDAP_FACTORIES.contains(owner)) {
                        add(ldap());
                    }
                    else if (!BUILT.contains(owner + "#" + name)) {
                        custom(name + "()", global, site, how);
                    }
                }
                case BuiltValues.Unread found -> custom(found.what(), global, site, how);
            }
        }
    }

    private void created(BuiltValues.Created created, boolean global, CodeRef site, String how) {
        String type = created.type().getFullyQualifiedName();
        if (type.equals(PROVIDER_MANAGER)) {
            created.calls("<init>").forEach(init -> values.parts(created.method(), init.getArg(0))
                    .forEach(part -> classify(part, global, site, how)));
        }
        else if (JAAS.contains(type)) {
            jaas(created, site);
        }
        else if (LDAP_PROVIDERS.contains(type)) {
            add(ldap());
        }
        else if (!READ.contains(type)) {
            custom(MethodNames.simpleName(type), global, site, how);
        }
    }

    /**
     * A JAAS login, named by its {@code AuthorityGranter}s; one AuthTracer can't follow is reported.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private void jaas(BuiltValues.Created created, CodeRef site) {
        Set<String> granters = new LinkedHashSet<>();
        List<Finding> findings = new ArrayList<>();
        created.calls("setAuthorityGranters").forEach(set -> values.parts(created.method(), set.getArg(0))
                .forEach(part -> part.forEach(granter -> {
                    switch (granter) {
                        case BuiltValues.Created made -> granters.add(MethodNames.simpleName(
                                made.type().getFullyQualifiedName()));
                        case BuiltValues.Unread found when found.what().startsWith("a lambda") -> granters.add(
                                found.what());
                        default -> {
                            String what = granter instanceof BuiltValues.Unread found ? found.what()
                                    : ((BuiltValues.Called) granter).call().getMethodSignature().getName() + "()";
                            granters.add(what + " (not read)");
                            findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The JAAS AuthorityGranter " + what
                                    + " isn't read: AuthTracer can't tell which authorities it grants", site));
                        }
                    }
                })));
        Provider provider = new Provider(Kind.USER_DETAILS, Freshness.LIVE, "JAAS login" + (granters.isEmpty() ? ""
                : " (authority granters: " + String.join(", ", granters) + ")"), true);
        add(provider);
        unread.computeIfAbsent(provider.label(), key -> new ArrayList<>()).addAll(findings);
    }

    private static Provider ldap() {
        return new Provider(Kind.USER_DETAILS, Freshness.LIVE, "LDAP directory", true);
    }

    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private void custom(String what, boolean global, CodeRef site, String how) {
        Provider provider = new Provider(Kind.UNKNOWN, Freshness.UNKNOWN, how + what + " (not read)", global);
        add(provider);
        unread.computeIfAbsent(provider.label(), key -> new ArrayList<>(List.of(new Finding(Finding.Kind.OPAQUE_CONFIG,
                (how.startsWith("Remember-me") ? "The RememberMeServices " : "The authentication provider ") + what
                        + " isn't read: AuthTracer can't tell which authorities the logins it checks give, or how"
                        + " fresh they are", site))));
    }

    /**
     * A provider both given to a chain and the global manager's reaches the chain's ways in.
     */
    private void add(Provider provider) {
        providers.merge(provider.label(), provider, (one, other) -> one.global() ? other : one);
    }
}
