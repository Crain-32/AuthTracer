package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Issuer;
import dev.crain.authtracer.scan.ConfigurationProperties;
import dev.crain.authtracer.scan.EnclosingMethods;
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
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ArrayType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * SRC-19 (decision 0075): the clients an authorization server registers and the scopes each can be granted, from
 * {@code RegisteredClient} builders in the code or Boot's {@code spring.security.oauth2.authorizationserver.client.*}
 * properties.
 * <p>
 * Spring Authorization Server (Security 7.1.1, javap) grants a client only scopes it is registered with:
 * {@code OAuth2ClientCredentialsAuthenticationValidator} and {@code OAuth2AuthorizationCodeRequestAuthenticationValidator}
 * reject a requested scope the {@code RegisteredClient}'s {@code getScopes()} doesn't contain. Boot 4.1.1's
 * {@code OAuth2AuthorizationServerConfiguration} makes an {@code InMemoryRegisteredClientRepository} of the properties'
 * clients ({@code OAuth2AuthorizationServerPropertiesMapper#asRegisteredClients}, {@code registration.scopes}) when the
 * application has no {@code RegisteredClientRepository} bean. What could let a token carry other scopes is recorded as
 * unread: a client store AuthTracer can't read, clients registered at run time, a token customizer that writes the
 * {@code scope} claim, an authentication validator or token endpoint provider of the application's.
 */
@Supports({Feature.CALL_CREDENTIALS, Feature.FINDING_TOKEN_REJECTED, Feature.FINDING_ALWAYS_DENIED})
final class RegisteredClients {

    private static final String AUTHORIZATION = "org.springframework.security.oauth2.server.authorization.";
    private static final String CLIENT = AUTHORIZATION + "client.RegisteredClient";
    private static final String REPOSITORY = AUTHORIZATION + "client.RegisteredClientRepository";
    private static final String IN_MEMORY = AUTHORIZATION + "client.InMemoryRegisteredClientRepository";
    private static final String GENERATOR = AUTHORIZATION + "token.OAuth2TokenGenerator";
    private static final String CONFIGURERS =
            "org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.";
    private static final String JWT_CLAIMS = "org.springframework.security.oauth2.jwt.JwtClaimsSet$Builder";
    private static final String TOKEN_CLAIMS = AUTHORIZATION + "token.OAuth2TokenClaimsSet$Builder";
    private static final String TOKEN_ENDPOINT = CONFIGURERS + "OAuth2TokenEndpointConfigurer";
    private static final String SERVER = CONFIGURERS + "OAuth2AuthorizationServerConfigurer";
    private static final Set<String> SCOPE_CLAIMS = Set.of("scope", "scp");
    private static final String PROPERTIES = "spring.security.oauth2.authorizationserver.client.";
    private static final String WRITES = "the claims a token customizer in %s writes";
    private static final String PROVIDERS = "the tokens the token endpoint's own providers in %s issue";
    private static final String REGISTERED = "the clients registered at run time (client registration endpoint in %s)";
    /**
     * The calls, by {@code owner#name}, that may let a token carry a scope its client isn't registered with.
     */
    private static final Map<String, String> EXTENSIONS = Map.ofEntries(
            Map.entry(JWT_CLAIMS + "#claims", WRITES),
            Map.entry(TOKEN_CLAIMS + "#claims", WRITES),
            Map.entry(TOKEN_ENDPOINT + "#authenticationProvider", PROVIDERS),
            Map.entry(TOKEN_ENDPOINT + "#authenticationProviders", PROVIDERS),
            Map.entry(TOKEN_ENDPOINT + "#accessTokenRequestConverter", PROVIDERS),
            Map.entry(TOKEN_ENDPOINT + "#accessTokenRequestConverters", PROVIDERS),
            Map.entry(SERVER + "#tokenGenerator", "the tokens a token generator set in %s issues"),
            Map.entry(SERVER + "#clientRegistrationEndpoint", REGISTERED),
            Map.entry(CONFIGURERS + "OidcConfigurer#clientRegistrationEndpoint", REGISTERED));

    private final ScanContext context;
    private final EnclosingMethods enclosing;
    private final SortedMap<String, SortedSet<String>> clients = new TreeMap<>();
    private final SortedSet<String> claims = new TreeSet<>();
    private final SortedSet<String> unread = new TreeSet<>();

    private RegisteredClients(ScanContext context) {
        this.context = context;
        this.enclosing = new EnclosingMethods(context);
    }

    static Issuer read(ScanContext context) {
        RegisteredClients read = new RegisteredClients(context);
        read.repository();
        read.code();
        return new Issuer(read.clients, read.claims, read.unread);
    }

    /**
     * The application's client store, or Boot's of the properties' clients.
     */
    private void repository() {
        List<JavaSootMethod> beans = SpringBeans.beanMethodsOf(context, Set.of(REPOSITORY)).stream()
                .filter(JavaSootMethod::hasBody).toList();
        BuiltValues values = new BuiltValues(context, enclosing);
        for (JavaSootMethod bean : beans) {
            for (BuiltValues.Source source : values.returnedBy(bean)) {
                if (source instanceof BuiltValues.Created created) {
                    if (!created.type().getFullyQualifiedName().equals(IN_MEMORY)) {
                        unread.add("the clients " + MethodNames.simpleName(created.type().getFullyQualifiedName())
                                + " stores");
                    }
                }
                else {
                    unread.add("the clients " + where(bean) + " returns");
                }
            }
        }
        for (JavaSootClass cls : context.applicationClasses()) {
            if (SpringBeans.assignable(context, cls.getType(), Set.of(REPOSITORY))) {
                unread.add("the clients " + MethodNames.simpleName(cls.getName()) + " stores");
            }
            if (SpringBeans.assignable(context, cls.getType(), Set.of(GENERATOR))) {
                unread.add("the tokens " + MethodNames.simpleName(cls.getName()) + " generates");
            }
        }
        if (beans.isEmpty()) {
            ConfigurationProperties properties = context.properties();
            properties.namesUnder(PROPERTIES).stream().map(name -> name.split("\\.", 2)[0]).distinct()
                    .forEach(key -> {
                        String registration = PROPERTIES + key + ".registration.";
                        clients.computeIfAbsent(properties.get(registration + "client-id").orElse(key),
                                id -> new TreeSet<>()).addAll(properties.list(registration + "scopes"));
                    });
        }
    }

    /**
     * The clients the code builds, and what it does that may let a token carry other scopes.
     */
    private void code() {
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (method.hasBody()) {
                    read(method);
                }
            }
        }
    }

    /**
     * A builder's calls are made on the local {@code withId(..)} returns, or on what each call returns.
     */
    private void read(JavaSootMethod method) {
        Map<Local, Builder> builders = new HashMap<>();
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> found = Locals.invoke(stmt);
            Local base = found.filter(AbstractInstanceInvokeExpr.class::isInstance)
                    .map(invoke -> ((AbstractInstanceInvokeExpr) invoke).getBase()).orElse(null);
            // A builder handed on (to a helper, a field, the caller) may be given scopes AuthTracer doesn't see.
            stmt.getUses().stream().filter(use -> !use.equals(base)).map(builders::get).filter(Objects::nonNull)
                    .forEach(builder -> builder.unread = true);
            if (found.isEmpty()) {
                continue;
            }
            AbstractInvokeExpr invoke = found.get();
            String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
            String name = invoke.getMethodSignature().getName();
            Local result = stmt instanceof AbstractDefinitionStmt definition
                    && definition.getLeftOp() instanceof Local local ? local : null;
            Builder builder = builders.get(base);
            if (owner.equals(CLIENT) && (name.equals("withId") || name.equals("from"))) {
                builder = new Builder(where(method));
                if (name.equals("from")) {
                    // The scopes of the client it copies are another builder's.
                    builder.unread = true;
                }
            }
            else if (builder != null) {
                builder.call(method, name, invoke);
            }
            else {
                other(method, owner, name, invoke);
            }
            if (builder != null && result != null && !name.equals("build")) {
                builders.put(result, builder);
            }
        }
        builders.values().stream().distinct().forEach(builder -> {
            if (builder.unread) {
                unread.add("the scopes of a client " + builder.where + " builds");
            }
            clients.computeIfAbsent(builder.id != null ? builder.id : "a client " + builder.where + " builds",
                    id -> new TreeSet<>()).addAll(builder.scopes);
        });
    }

    /**
     * What else may let a token carry a scope its client isn't registered with.
     */
    private void other(JavaSootMethod method, String owner, String name, AbstractInvokeExpr invoke) {
        String call = owner + "#" + name;
        if (call.equals(JWT_CLAIMS + "#claim") || call.equals(TOKEN_CLAIMS + "#claim")) {
            Optional<String> claim = constant(method, invoke.getArg(0));
            if (claim.isEmpty() || SCOPE_CLAIMS.contains(claim.get())) {
                unread.add(WRITES.formatted(where(method)));
            }
            claim.ifPresent(claims::add);
        }
        else if (EXTENSIONS.containsKey(call)) {
            unread.add(EXTENSIONS.get(call).formatted(where(method)));
        }
        else if (name.equals("setAuthenticationValidator")) {
            // The token endpoint's and authorization endpoint's providers: which scopes a request may ask for.
            unread.add("the scopes an authentication validator set in " + where(method) + " allows");
        }
    }

    /**
     * One client's builder.
     */
    private final class Builder {
        final String where;
        String id;
        final SortedSet<String> scopes = new TreeSet<>();
        boolean unread;

        Builder(String where) {
            this.where = where;
        }

        void call(JavaSootMethod method, String name, AbstractInvokeExpr invoke) {
            switch (name) {
                case "clientId" -> id = constant(method, invoke.getArg(0)).orElse(null);
                case "scope" -> constant(method, invoke.getArg(0)).ifPresentOrElse(scopes::add, () -> unread = true);
                case "scopes" -> unread |= !consumer(method, invoke.getArg(0), scopes);
                default -> {
                }
            }
        }
    }

    /**
     * {@code scopes(s -> s.add("a"))}, {@code s.addAll(Set.of("a", "b"))}: the scopes a consumer lambda adds; false
     * when it does anything else to them.
     */
    private boolean consumer(JavaSootMethod method, Immediate arg, Set<String> scopes) {
        Optional<JavaSootMethod> lambda = definition(method, arg).filter(JDynamicInvokeExpr.class::isInstance)
                .map(JDynamicInvokeExpr.class::cast)
                .flatMap(dynamic -> dynamic.getBootstrapArgs().stream()
                        .filter(handle -> handle instanceof MethodHandle body && body.getReferenceSignature()
                                instanceof MethodSignature)
                        .map(handle -> context.findMethod((MethodSignature) ((MethodHandle) handle)
                                .getReferenceSignature()))
                        .flatMap(Optional::stream).filter(JavaSootMethod::hasBody).findFirst());
        if (lambda.isEmpty()) {
            return false;
        }
        boolean read = true;
        for (Stmt stmt : lambda.get().getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            String name = invoke.map(found -> found.getMethodSignature().getName()).orElse("");
            if (name.equals("add")) {
                Optional<String> scope = constant(lambda.get(), invoke.get().getArg(0));
                scope.ifPresent(scopes::add);
                read &= scope.isPresent();
            }
            else if (name.equals("addAll")) {
                List<String> added = strings(lambda.get(), invoke.get().getArg(0));
                scopes.addAll(added);
                read &= !added.isEmpty();
            }
            else if (Set.of("remove", "removeAll", "clear", "retainAll", "removeIf").contains(name)) {
                read = false;
            }
        }
        return read;
    }

    /**
     * The constants a {@code Set.of(..)}, {@code Arrays.asList(..)} or Kotlin's {@code setOf(..)} holds; none when it
     * holds anything else.
     */
    private static List<String> strings(JavaSootMethod method, Immediate arg) {
        if (!(definition(method, arg).orElse(arg) instanceof AbstractInvokeExpr call)) {
            return List.of();
        }
        List<Value> parts = new ArrayList<>();
        for (Immediate part : call.getArgs()) {
            if (part.getType() instanceof ArrayType) {
                parts.addAll(Locals.elements(method.getBody(), (Local) part));
            }
            else {
                parts.add(definition(method, part).orElse(part));
            }
        }
        return parts.stream().allMatch(StringConstant.class::isInstance)
                ? parts.stream().map(part -> ((StringConstant) part).getValue()).toList() : List.of();
    }

    private static Optional<String> constant(JavaSootMethod method, Immediate arg) {
        return definition(method, arg).or(() -> Optional.of(arg)).filter(StringConstant.class::isInstance)
                .map(constant -> ((StringConstant) constant).getValue());
    }

    /**
     * The value first assigned to a local.
     */
    private static Optional<Value> definition(JavaSootMethod method, Immediate arg) {
        return Optional.of(arg).filter(Local.class::isInstance)
                .flatMap(local -> Locals.definition(method.getBody(), (Local) local));
    }

    private String where(JavaSootMethod method) {
        JavaSootMethod outer = enclosing.of(method);
        return MethodNames.simpleName(outer.getDeclaringClassType().getFullyQualifiedName()) + "#" + outer.getName();
    }
}
