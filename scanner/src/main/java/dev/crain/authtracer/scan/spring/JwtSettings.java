package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Might;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthoritySource.ClaimAuthorities;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.ConfigurationProperties;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.GroovyCalls;
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
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.Body;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ArrayType;
import sootup.core.types.ClassType;
import sootup.core.types.Type;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0073: how a resource server reads the JWTs it accepts. SRC-02: which claims become which authorities, as
 * {@code JwtGrantedAuthoritiesConverter} ({@code setAuthoritiesClaimName}, {@code setAuthorityPrefix},
 * {@code setAuthoritiesClaimDelimiter}), {@code ExpressionJwtGrantedAuthoritiesConverter} and
 * {@code DelegatingJwtGrantedAuthoritiesConverter} set them, or Spring Boot's {@code jwt.*} properties; a converter
 * of the application's own isn't read. SRC-04: a principal converter's authorities, which
 * {@code JwtAuthenticationConverter#convert} adds to the token's. SRC-03: the claims a
 * {@code MappedJwtClaimSetConverter} rewrites before they are read.
 * <p>
 * From the 7.1.1 bytecode: {@code JwtGrantedAuthoritiesConverter} reads {@code scope}, else {@code scp}, prefixes
 * each value with {@code SCOPE_} and splits a string claim on a space; {@code ExpressionJwtGrantedAuthoritiesConverter}
 * prefixes with {@code SCOPE_} too. {@code JwtAuthenticationConverter#convert} (final) returns the converter's
 * authorities, {@code FACTOR_BEARER} and the principal converter's {@code getAuthorities()} (the default principal has
 * none). The DSL's {@code jwt()} uses the converter it is given, else the {@code JwtAuthenticationConverter} bean
 * ({@code ReactiveJwtAuthenticationConverter} for WebFlux), else a new one. Boot 4.1.1 defines that bean from
 * {@code authority-prefix}, {@code authorities-claim-name}, {@code authorities-claim-delimiter} and
 * {@code authorities-claim-expressions} when one of the prefix, the claim name, the expressions or
 * {@code principal-claim-name} is set and the application has no such bean ({@code JwtConverterConfiguration}).
 * <p>
 * The converters the application builds are read wherever they are built, and all of them count: a service with
 * several chains grants what any of them does.
 */
@Supports(Feature.AUTHORITY_SOURCE)
final class JwtSettings {

    static final String DEFAULT_PREFIX = "SCOPE_";
    private static final List<String> DEFAULT_CLAIMS = List.of("scope", "scp");
    private static final ClaimAuthorities DEFAULT = new ClaimAuthorities(DEFAULT_CLAIMS, null, DEFAULT_PREFIX, null);

    private static final String AUTHENTICATION = "org.springframework.security.oauth2.server.resource.authentication.";
    private static final String GRANTED = AUTHENTICATION + "JwtGrantedAuthoritiesConverter";
    private static final String EXPRESSION = AUTHENTICATION + "ExpressionJwtGrantedAuthoritiesConverter";
    private static final String DELEGATING = AUTHENTICATION + "DelegatingJwtGrantedAuthoritiesConverter";
    private static final String GRANTED_ADAPTER = AUTHENTICATION + "ReactiveJwtGrantedAuthoritiesConverterAdapter";
    private static final String CONVERTER = AUTHENTICATION + "JwtAuthenticationConverter";
    private static final String REACTIVE_CONVERTER = AUTHENTICATION + "ReactiveJwtAuthenticationConverter";
    private static final String CONVERTER_ADAPTER = AUTHENTICATION + "ReactiveJwtAuthenticationConverterAdapter";
    private static final String PROVIDER = AUTHENTICATION + "JwtAuthenticationProvider";
    private static final String REACTIVE_MANAGER = AUTHENTICATION + "JwtReactiveAuthenticationManager";
    /**
     * The converters whose authorities are read where they are built. The delegating converter isn't final, so a
     * subclass of it is the application's own; {@code JwtAuthenticationConverter#convert} is final, so a subclass of
     * it converts as it does.
     */
    private static final Set<String> READ = Set.of(GRANTED, EXPRESSION, DELEGATING, GRANTED_ADAPTER,
            REACTIVE_CONVERTER, CONVERTER_ADAPTER, PROVIDER, REACTIVE_MANAGER);
    /**
     * Where the DSL takes the converter: {@code jwt(j -> j.jwtAuthenticationConverter(..))} in Java, the Kotlin DSL's
     * {@code jwtAuthenticationConverter = ..}, Spring gRPC's.
     */
    private static final Set<String> CONFIGURERS = Set.of(
            "org.springframework.security.config.annotation.web.configurers.oauth2.server.resource."
                    + "OAuth2ResourceServerConfigurer$JwtConfigurer",
            "org.springframework.security.config.web.server.ServerHttpSecurity$OAuth2ResourceServerSpec$JwtSpec",
            "org.springframework.security.config.annotation.web.oauth2.resourceserver.JwtDsl",
            "org.springframework.security.config.web.server.ServerJwtDsl",
            "org.springframework.grpc.server.security.OAuth2ResourceServerConfigurer$JwtConfigurer");
    private static final Set<String> DECODERS = Set.of("org.springframework.security.oauth2.jwt.NimbusJwtDecoder",
            "org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder");
    private static final String MAPPED_CLAIMS = "org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter";
    /**
     * Dynamic Groovy calls that configure a converter: their receivers and arguments aren't followed.
     */
    private static final Set<String> GROOVY_SETTERS = Set.of("setAuthorityPrefix", "authorityPrefix",
            "setAuthoritiesClaimName", "authoritiesClaimName", "setAuthoritiesClaimDelimiter",
            "authoritiesClaimDelimiter", "setJwtGrantedAuthoritiesConverter", "jwtGrantedAuthoritiesConverter",
            "setJwtPrincipalConverter", "jwtPrincipalConverter", "jwtAuthenticationConverter",
            "setJwtAuthenticationConverter");
    private static final String JWT = "org.springframework.security.oauth2.jwt.";
    private static final String JWT_VALIDATORS = JWT + "JwtValidators";
    private static final String AT_JWT = JWT + "JwtValidators$AtJwtBuilder";
    private static final String DELEGATING_VALIDATOR =
            "org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator";
    /**
     * Spring's validators, read where they are built.
     */
    private static final Set<String> VALIDATORS = Set.of(DELEGATING_VALIDATOR, JWT + "JwtClaimValidator",
            JWT + "JwtAudienceValidator", JWT + "JwtIssuerValidator", JWT + "JwtTimestampValidator",
            JWT + "JwtTypeValidator", JWT + "JwtIssuedAtValidator", JWT + "X509CertificateThumbprintValidator");
    private static final Set<String> VALIDATOR_FACTORIES = Set.of(JWT_VALIDATORS, AT_JWT,
            JWT + "JwtValidators$RequireClaimValidator");
    private static final String TOKEN_VALIDATOR = "org.springframework.security.oauth2.core.OAuth2TokenValidator";
    private static final String GROOVY_PROPERTIES = "org.codehaus.groovy.runtime.ScriptBytecodeAdapter";
    private static final String PROPERTIES = "spring.security.oauth2.resourceserver.jwt.";

    /**
     * What the scan read.
     *
     * @param jwt the claims read as authorities, and the claims rewritten first
     * @param text the claims and their prefixes, for the authority source's detail
     * @param read whether every authority a token can grant is in {@code jwt}: no converter the scan can't read, no
     *        prefix it can't read, no principal converter
     */
    record Read(AuthoritySource.Jwt jwt, String text, boolean read) {
    }

    /**
     * A {@code JwtGrantedAuthoritiesConverter} or {@code ExpressionJwtGrantedAuthoritiesConverter} the application
     * builds, as its setters leave it.
     */
    private static final class Claims {
        List<String> claims;
        String expression;
        String prefix = DEFAULT_PREFIX;
        boolean prefixRead = true;
        String delimiter;
        CodeRef site;

        Claims(List<String> claims, CodeRef site) {
            this.claims = claims;
            this.site = site;
        }

        ClaimAuthorities authorities() {
            return new ClaimAuthorities(claims, expression, prefixRead ? prefix : null, delimiter);
        }
    }

    /**
     * Something that converts with a default {@code JwtGrantedAuthoritiesConverter} until it is given another: a
     * {@code JwtAuthenticationConverter} (or reactive), a {@code JwtAuthenticationProvider}, a
     * {@code JwtReactiveAuthenticationManager}.
     */
    private static final class Holder {
        boolean given;
    }

    /**
     * A converter or adapter whose parts are read where it is built.
     */
    private static final Object PARTS = new Object();

    private final ScanContext context;
    private final GraphBuilder graph;
    private final Map<JavaSootMethod, Map<Local, Object>> scanned = new HashMap<>();
    private final Set<JavaSootMethod> scanning = new HashSet<>();
    private final List<Claims> claims = new ArrayList<>();
    private final List<Holder> holders = new ArrayList<>();
    /**
     * The converters the scan can't read, each with where it is given.
     */
    private final Map<String, CodeRef> unread = new LinkedHashMap<>();
    private final Set<String> principals = new LinkedHashSet<>();
    private final SortedSet<String> rewritten = new TreeSet<>();
    private final SortedSet<String> unreadClaimSets = new TreeSet<>();
    private final SortedSet<String> audiences = new TreeSet<>();
    private final SortedSet<String> validators = new TreeSet<>();
    /**
     * The validators the scan can't read, each with where it is given.
     */
    private final Map<String, CodeRef> unreadValidators = new LinkedHashMap<>();
    private boolean dsl;

    private JwtSettings(ScanContext context, GraphBuilder graph) {
        this.context = context;
        this.graph = graph;
    }

    /**
     * Reads the application's JWT settings; reports a converter it can't read as OPAQUE_CONFIG.
     *
     * @param reactive whether the service runs on WebFlux, whose {@code jwt()} looks up the reactive converter bean
     */
    @Might("Follow which chain each converter is given to, rather than counting every converter the application builds")
    static Read read(ScanContext context, GraphBuilder graph, boolean reactive) {
        JwtSettings settings = new JwtSettings(context, graph);
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                settings.scan(method);
            }
        }
        return settings.result(reactive);
    }

    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private Read result(boolean reactive) {
        List<ClaimAuthorities> authorities = new ArrayList<>(claims.stream().map(Claims::authorities).toList());
        if (holders.stream().anyMatch(holder -> !holder.given)) {
            authorities.add(DEFAULT);
        }
        Optional<List<ClaimAuthorities>> boot = dsl ? Optional.empty() : boot(reactive);
        boot.ifPresent(authorities::addAll);
        if (authorities.isEmpty() && unread.isEmpty()) {
            // Spring's own JwtAuthenticationConverter.
            authorities.add(DEFAULT);
        }
        List<ClaimAuthorities> distinct = authorities.stream().distinct()
                .sorted(Comparator.comparing(JwtSettings::text)).toList();
        unread.forEach((converter, site) -> graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The JWT"
                + " authorities come from " + converter + ", which the scan doesn't read: which authorities a token"
                + " grants is unknown, so a check no token can pass isn't told apart", site)));
        claims.stream().filter(claim -> !claim.prefixRead).forEach(claim -> graph.finding(new Finding(
                Finding.Kind.OPAQUE_CONFIG, "A JwtGrantedAuthoritiesConverter's authority prefix isn't a constant:"
                        + " which authorities a token grants is unknown", claim.site)));
        List<String> parts = new ArrayList<>(distinct.stream().map(JwtSettings::text).toList());
        unread.keySet().stream().sorted().forEach(converter -> parts.add(converter + " (not read)"));
        StringBuilder text = new StringBuilder("authorities: ").append(String.join(", ", parts));
        principals.forEach(principal -> text.append("; plus, per request, the authorities of the principal from ")
                .append(principal));
        if (!rewritten.isEmpty() || !unreadClaimSets.isEmpty()) {
            text.append("; claims rewritten first: ").append(String.join(", ", rewritten.isEmpty()
                    ? unreadClaimSets : rewritten));
        }
        boolean read = unread.isEmpty() && principals.isEmpty() && claims.stream().allMatch(claim -> claim.prefixRead)
                && boot.map(found -> found.stream().allMatch(claim -> claim.prefix() != null)).orElse(true);
        bootDecoder(reactive);
        unreadValidators.forEach((validator, site) -> graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The"
                + " JWTs the service accepts are also checked by " + validator + ", which the scan doesn't read:"
                + " whether a token another service relays passes is unknown", site)));
        if (!audiences.isEmpty()) {
            text.append("; tokens for: ").append(String.join(", ", audiences));
        }
        SortedSet<String> unreadParts = new TreeSet<>(unreadClaimSets);
        unreadParts.addAll(unreadValidators.keySet());
        return new Read(new AuthoritySource.Jwt(distinct, audiences, validators, unreadParts, rewritten),
                text.toString(), read);
    }

    /**
     * Spring Boot's decoder, when the application has none of its own: it checks the issuer, the
     * {@code jwt.audiences} (a token must name one of them), and every {@code OAuth2TokenValidator<Jwt>} bean (4.1.1
     * {@code JwtDecoderConfiguration#getValidator}).
     */
    @Supports(Feature.FINDING_TOKEN_REJECTED)
    private void bootDecoder(boolean reactive) {
        ConfigurationProperties properties = context.properties();
        boolean configured = List.of("jwk-set-uri", "issuer-uri", "public-key-location").stream()
                .anyMatch(key -> properties.getResolvingKnown(PROPERTIES + key).isPresent());
        if (!configured || !context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION)
                || !SpringBeans.beanMethodsOf(context, Set.of(reactive ? JWT + "ReactiveJwtDecoder"
                        : JWT + "JwtDecoder")).isEmpty()) {
            return;
        }
        if (properties.getResolvingKnown(PROPERTIES + "issuer-uri").isPresent()) {
            validators.add("issuer");
        }
        audiences.addAll(properties.list(PROPERTIES + "audiences"));
        for (JavaSootMethod bean : SpringBeans.beanMethodsOf(context, Set.of(TOKEN_VALIDATOR))) {
            if (!bean.hasBody()) {
                continue;
            }
            Map<Local, Object> values = scan(bean);
            bean.getBody().getStmts().stream().filter(JReturnStmt.class::isInstance)
                    .forEach(stmt -> validator(bean, ((JReturnStmt) stmt).getOp(), values,
                            MethodNames.codeRef(bean.getSignature(), stmt)));
        }
    }

    /**
     * Spring Boot's converter bean, when it defines one and the application has none of its own.
     */
    private Optional<List<ClaimAuthorities>> boot(boolean reactive) {
        ConfigurationProperties properties = context.properties();
        boolean set = List.of("authority-prefix", "authorities-claim-name", "principal-claim-name").stream()
                .anyMatch(key -> properties.getResolvingKnown(PROPERTIES + key).isPresent())
                || !properties.list(PROPERTIES + "authorities-claim-expressions").isEmpty();
        if (!set || !context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION)
                || !SpringBeans.beanMethodsOf(context, Set.of(reactive ? REACTIVE_CONVERTER : CONVERTER)).isEmpty()) {
            return Optional.empty();
        }
        // Set, but from the environment: unknown.
        String prefix = properties.getResolvingKnown(PROPERTIES + "authority-prefix").isEmpty() ? DEFAULT_PREFIX
                : properties.get(PROPERTIES + "authority-prefix").orElse(null);
        List<String> expressions = properties.list(PROPERTIES + "authorities-claim-expressions");
        if (!expressions.isEmpty()) {
            return Optional.of(expressions.stream().map(expression -> new ClaimAuthorities(List.of(), expression,
                    prefix, null)).toList());
        }
        List<String> claim = properties.get(PROPERTIES + "authorities-claim-name").map(List::of)
                .orElse(DEFAULT_CLAIMS);
        String delimiter = properties.get(PROPERTIES + "authorities-claim-delimiter").filter(found -> !found
                .equals(" ")).orElse(null);
        return Optional.of(List.of(new ClaimAuthorities(claim, null, prefix, delimiter)));
    }

    /**
     * {@code roles → ROLE_*}, {@code scope (split on ",") → SCOPE_*}.
     */
    static String text(ClaimAuthorities claim) {
        String from = claim.expression() != null ? claim.expression()
                : claim.claims().isEmpty() ? "a claim the scan can't read" : claim.claims().getFirst();
        String split = claim.delimiter() == null ? "" : " (split on \"" + claim.delimiter() + "\")";
        return from + split + " → " + (claim.prefix() == null ? "?" : claim.prefix() + "*");
    }

    /**
     * The values the method builds, by local; scans it once.
     */
    private Map<Local, Object> scan(JavaSootMethod method) {
        Map<Local, Object> values = scanned.get(method);
        if (values != null || !method.hasBody() || !scanning.add(method)) {
            return values == null ? Map.of() : values;
        }
        values = new HashMap<>();
        Body body = method.getBody();
        for (Stmt stmt : body.getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt definition && definition.getLeftOp() instanceof Local left) {
                Value right = definition.getRightOp();
                Object value = right instanceof JNewExpr created ? created(created.getType(), method, stmt)
                        : right instanceof Local other ? values.get(other)
                                : right instanceof JCastExpr cast && cast.getOp() instanceof Local other
                                        ? values.get(other) : null;
                if (value != null) {
                    values.put(left, value);
                }
            }
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isPresent()) {
                call(method, stmt, invoke.get(), values);
            }
        }
        scanning.remove(method);
        scanned.put(method, values);
        return values;
    }

    private Object created(ClassType type, JavaSootMethod method, Stmt stmt) {
        String name = type.getFullyQualifiedName();
        if (name.equals(GRANTED) || name.equals(EXPRESSION)) {
            Claims claim = new Claims(name.equals(GRANTED) ? DEFAULT_CLAIMS : List.of(),
                    MethodNames.codeRef(method.getSignature(), stmt));
            claims.add(claim);
            return claim;
        }
        if (name.equals(REACTIVE_CONVERTER) || name.equals(PROVIDER) || name.equals(REACTIVE_MANAGER)
                || SpringBeans.assignable(context, type, Set.of(CONVERTER))) {
            Holder holder = new Holder();
            holders.add(holder);
            return holder;
        }
        return READ.contains(name) ? PARTS : null;
    }

    private void call(JavaSootMethod method, Stmt stmt, AbstractInvokeExpr invoke, Map<Local, Object> values) {
        Optional<GroovyCalls.Call> groovy = GroovyCalls.of(invoke);
        CodeRef site = MethodNames.codeRef(method.getSignature(), stmt);
        if (groovy.isPresent()) {
            if (GROOVY_SETTERS.contains(groovy.get().name())) {
                unread.putIfAbsent(groovy(method), site);
            }
            return;
        }
        String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = invoke.getMethodSignature().getName();
        // Groovy writes a property through ScriptBytecodeAdapter.setProperty(value, class, receiver, (String) "name").
        if (owner.equals(GROOVY_PROPERTIES) && name.startsWith("set") && invoke.getArgCount() > 0
                && constant(method, invoke.getArg(invoke.getArgCount() - 1)).filter(GROOVY_SETTERS::contains)
                        .isPresent()) {
            unread.putIfAbsent(groovy(method), site);
            return;
        }
        Object base = invoke instanceof AbstractInstanceInvokeExpr instance ? values.get(instance.getBase()) : null;
        boolean converter = owner.equals(CONVERTER) || owner.equals(REACTIVE_CONVERTER);
        if ((owner.equals(GRANTED) || owner.equals(EXPRESSION)) && invoke.getArgCount() == 1) {
            // A converter built where the scan doesn't follow (a parameter) still has the prefix it is given here.
            Claims claim = base instanceof Claims built ? built : untracked(site);
            if (base == null && invoke instanceof AbstractInstanceInvokeExpr instance) {
                values.put(instance.getBase(), claim);
            }
            Immediate arg = invoke.getArg(0);
            switch (name) {
                case "<init>" -> claim.expression = expression(method, arg).orElse("an expression the scan can't"
                        + " read");
                case "setAuthoritiesClaimName" -> claim.claims = arg instanceof StringConstant constant
                        ? List.of(constant.getValue()) : List.of();
                case "setAuthorityPrefix" -> {
                    claim.prefixRead = arg instanceof StringConstant;
                    claim.prefix = arg instanceof StringConstant constant ? constant.getValue() : null;
                }
                case "setAuthoritiesClaimDelimiter" -> claim.delimiter = arg instanceof StringConstant constant
                        ? constant.getValue().equals(" ") ? null : constant.getValue() : "?";
                default -> {
                }
            }
        }
        else if (converter && name.equals("setJwtGrantedAuthoritiesConverter")
                || (owner.equals(PROVIDER) || owner.equals(REACTIVE_MANAGER))
                        && name.equals("setJwtAuthenticationConverter")) {
            if (base instanceof Holder holder) {
                holder.given = true;
            }
            given(method, invoke.getArg(0), values, site);
        }
        else if (converter && name.equals("setJwtPrincipalConverter")) {
            principals.add(unread(method, invoke.getArg(0), values, 0, false).orElse("a JwtAuthenticationConverter"));
        }
        else if (CONFIGURERS.contains(owner) && (name.equals("jwtAuthenticationConverter")
                || name.equals("setJwtAuthenticationConverter"))) {
            dsl = true;
            given(method, invoke.getArg(0), values, site);
        }
        else if (name.equals("<init>") && (owner.equals(DELEGATING) || owner.equals(GRANTED_ADAPTER)
                || owner.equals(CONVERTER_ADAPTER)) && invoke.getArgCount() == 1) {
            for (Immediate part : parts(method, invoke.getArg(0))) {
                given(method, part, values, site);
            }
        }
        else if (DECODERS.contains(owner) && name.equals("setClaimSetConverter")) {
            claimSet(method, invoke.getArg(0));
        }
        else if (DECODERS.contains(owner) && name.equals("setJwtValidator")) {
            validator(method, invoke.getArg(0), values, site);
        }
        else {
            validators(method, owner, name, invoke, values, site);
        }
    }

    /**
     * OAUTH-06: the validators a token must pass, as Spring's are built: {@code JwtValidators}' factories and
     * {@code createAtJwtValidator()} builder, {@code JwtAudienceValidator}, {@code JwtIssuerValidator},
     * {@code JwtTypeValidator}, {@code JwtClaimValidator} and {@code DelegatingOAuth2TokenValidator}.
     */
    @Supports(Feature.FINDING_TOKEN_REJECTED)
    private void validators(JavaSootMethod method, String owner, String name, AbstractInvokeExpr invoke,
            Map<Local, Object> values, CodeRef site) {
        boolean created = name.equals("<init>");
        if (owner.equals(JWT + "JwtAudienceValidator") && created
                || owner.equals(AT_JWT) && name.equals("audience")) {
            Optional<String> audience = constant(method, invoke.getArg(0));
            audience.ifPresent(audiences::add);
            if (audience.isEmpty()) {
                unreadValidators.putIfAbsent("an audience that isn't a constant, in " + where(method), site);
            }
        }
        else if (owner.equals(AT_JWT) && (name.equals("issuer") || name.equals("clientId"))) {
            validators.add(name.equals("issuer") ? "issuer" : "client_id");
        }
        else if (owner.equals(JWT + "JwtIssuerValidator") && created
                || owner.equals(JWT_VALIDATORS) && name.equals("createDefaultWithIssuer")) {
            validators.add("issuer");
        }
        else if (owner.equals(JWT_VALIDATORS) && name.equals("createAtJwtValidator")) {
            validators.add("typ at+jwt");
        }
        else if (owner.equals(JWT + "JwtTypeValidator") && (created || name.equals("jwt"))) {
            validators.add("typ");
        }
        else if (owner.equals(JWT + "JwtClaimValidator") && created && invoke.getArgCount() == 2) {
            Optional<String> claim = constant(method, invoke.getArg(0));
            if (claim.filter("aud"::equals).isPresent()) {
                List<String> named = audiences(method, invoke.getArg(1));
                audiences.addAll(named);
                if (named.isEmpty()) {
                    unreadValidators.putIfAbsent("a JwtClaimValidator on aud in " + where(method), site);
                }
            }
            else {
                validators.add("claim " + claim.orElse("?"));
            }
        }
        else if (created && owner.equals(DELEGATING_VALIDATOR) && invoke.getArgCount() == 1
                || owner.equals(JWT_VALIDATORS) && name.equals("createDefaultWithValidators")) {
            for (Immediate part : parts(method, invoke.getArg(0))) {
                validator(method, part, values, site);
            }
        }
    }

    /**
     * The audiences an {@code aud -> aud.contains("orders")} lambda names: the constants it compares with, also when
     * the lambda captures them; empty when it names none the scan can read.
     */
    @Supports(Feature.FINDING_TOKEN_REJECTED)
    private List<String> audiences(JavaSootMethod method, Immediate predicate) {
        Optional<JDynamicInvokeExpr> lambda = predicate instanceof Local local ? Locals.definition(method.getBody(),
                local).filter(JDynamicInvokeExpr.class::isInstance).map(JDynamicInvokeExpr.class::cast)
                : Optional.empty();
        Optional<JavaSootMethod> body = lambda.flatMap(found -> found.getBootstrapArgs().stream()
                .filter(MethodHandle.class::isInstance).map(MethodHandle.class::cast)
                .filter(handle -> handle.getReferenceSignature() instanceof MethodSignature)
                .map(handle -> (MethodSignature) handle.getReferenceSignature()).findFirst())
                .flatMap(context::findMethod).filter(JavaSootMethod::hasBody);
        List<String> named = new ArrayList<>();
        if (body.isEmpty()) {
            return named;
        }
        for (Stmt stmt : body.get().getBody().getStmts()) {
            Optional<AbstractInvokeExpr> compare = Locals.invoke(stmt).filter(call -> Set.of("contains", "equals")
                    .contains(call.getMethodSignature().getName()) && call.getArgCount() == 1);
            if (compare.isEmpty()) {
                continue;
            }
            Immediate arg = compare.get().getArg(0);
            OptionalInt captured = arg instanceof Local local ? Locals.parameterIndex(body.get().getBody(), local)
                    : OptionalInt.empty();
            Optional<String> audience = captured.isPresent() && captured.getAsInt() < lambda.get().getArgCount()
                    ? constant(method, lambda.get().getArg(captured.getAsInt()))
                    : constant(body.get(), arg);
            audience.ifPresent(named::add);
        }
        return named;
    }

    private Claims untracked(CodeRef site) {
        Claims claim = new Claims(List.of(), site);
        claims.add(claim);
        return claim;
    }

    /**
     * A converter handed to the DSL, a converter or an adapter: reported when the scan can't read it.
     */
    private void given(JavaSootMethod method, Immediate converter, Map<Local, Object> values, CodeRef site) {
        unread(method, converter, values, 0, false).ifPresent(found -> unread.putIfAbsent(found, site));
    }

    /**
     * OAUTH-06: a validator handed to a decoder or combined with others: reported when the scan can't read it.
     */
    @Supports(Feature.FINDING_TOKEN_REJECTED)
    private void validator(JavaSootMethod method, Immediate validator, Map<Local, Object> values, CodeRef site) {
        unread(method, validator, values, 0, true).ifPresent(found -> unreadValidators.putIfAbsent(found, site));
    }

    /**
     * The delegating converter's parts, varargs or a {@code List.of(..)}; the adapters' one.
     */
    private static List<Immediate> parts(JavaSootMethod method, Immediate arg) {
        if (arg instanceof Local local && local.getType() instanceof ArrayType) {
            return method.getBody().getStmts().stream()
                    .filter(stmt -> stmt instanceof AbstractDefinitionStmt definition
                            && definition.getLeftOp() instanceof JArrayRef element && element.getBase().equals(local))
                    .map(stmt -> ((AbstractDefinitionStmt) stmt).getRightOp())
                    .filter(Immediate.class::isInstance).map(Immediate.class::cast).toList();
        }
        if (arg instanceof Local local) {
            Optional<Value> definition = Locals.definition(method.getBody(), local);
            if (definition.isPresent() && definition.get() instanceof AbstractInvokeExpr list
                    && list.getMethodSignature().getDeclClassType().getFullyQualifiedName().equals("java.util.List")
                    && list.getMethodSignature().getName().equals("of")) {
                return list.getArgs();
            }
        }
        return List.of(arg);
    }

    /**
     * What a converter (or a validator) is when the scan can't read it ({@code KeycloakRoleConverter}, {@code a
     * lambda in Config#converter}); empty when it is one the scan reads where it is built.
     */
    private Optional<String> unread(JavaSootMethod method, Immediate arg, Map<Local, Object> values, int depth,
            boolean validator) {
        if (!(arg instanceof Local local) || values.containsKey(local) || read(local.getType(), validator)) {
            return Optional.empty();
        }
        List<Value> definitions = Locals.definitions(method.getBody(), local);
        if (definitions.isEmpty()) {
            return Optional.of("a value the scan can't follow");
        }
        for (Value definition : definitions) {
            Optional<String> found = unreadValue(method, definition, values, depth, validator);
            if (found.isPresent()) {
                return found;
            }
        }
        return Optional.empty();
    }

    private Optional<String> unreadValue(JavaSootMethod method, Value value, Map<Local, Object> values, int depth,
            boolean validator) {
        return switch (value) {
            case JNewExpr created -> read(created.getType(), validator) ? Optional.empty()
                    : Optional.of(MethodNames.simpleName(created.getType().getFullyQualifiedName()));
            case Local local -> unread(method, local, values, depth, validator);
            case JCastExpr cast when cast.getOp() instanceof Local local -> unread(method, local, values, depth,
                    validator);
            case JParameterRef parameter -> read(parameter.getType(), validator) ? Optional.empty()
                    : Optional.of("an injected " + MethodNames.simpleName(parameter.getType().toString()));
            case JDynamicInvokeExpr dynamic -> Optional.of(GroovyCalls.of(dynamic).isPresent() ? groovy(method)
                    : "a lambda in " + where(method));
            case AbstractInvokeExpr call -> returned(call, depth, validator);
            case JFieldRef field -> Optional.of("the field " + field.getFieldSignature().getName());
            default -> Optional.of("a value the scan can't follow");
        };
    }

    /**
     * What an application method returns, when it returns a converter (or validator) the scan can't read; Spring's
     * validator factories ({@code JwtValidators}) are read where they are called.
     */
    private Optional<String> returned(AbstractInvokeExpr call, int depth, boolean validator) {
        if (read(call.getMethodSignature().getType(), validator) || validator && VALIDATOR_FACTORIES.contains(
                call.getMethodSignature().getDeclClassType().getFullyQualifiedName())) {
            return Optional.empty();
        }
        Optional<JavaSootMethod> callee = context.findMethod(call.getMethodSignature())
                .filter(found -> found.hasBody() && context.isApplication(found.getDeclaringClassType()));
        if (callee.isEmpty() || depth > 3) {
            return Optional.of(call.getMethodSignature().getName() + "()");
        }
        Map<Local, Object> values = scan(callee.get());
        for (Stmt stmt : callee.get().getBody().getStmts()) {
            if (stmt instanceof JReturnStmt returned) {
                Optional<String> found = unread(callee.get(), returned.getOp(), values, depth + 1, validator);
                if (found.isPresent()) {
                    return found;
                }
            }
        }
        return Optional.empty();
    }

    private static String groovy(JavaSootMethod method) {
        return "Groovy code in " + where(method) + " that configures a converter dynamically";
    }

    /**
     * {@code Config#converter}: the method a lambda's or closure's body is in, by the name it is written in.
     */
    private static String where(JavaSootMethod method) {
        String className = MethodNames.simpleName(method.getDeclaringClassType().getFullyQualifiedName());
        String name = method.getName();
        // Groovy's Config$_converter_closure1#doCall.
        int closure = className.indexOf("$_");
        if (closure > 0) {
            String outer = className.substring(closure + 2);
            return className.substring(0, closure) + "#" + outer.substring(0, Math.max(outer.indexOf("_closure"), 0));
        }
        // javac's lambda$converter$0, and lambda$converter$1 for one nested in it.
        return className + "#" + (name.startsWith("lambda$") ? name.split("\\$")[1] : name);
    }

    /**
     * Whether the type is a converter (or a validator) the scan reads where it is built.
     */
    private boolean read(Type type, boolean validator) {
        if (!(type instanceof ClassType classType)) {
            return false;
        }
        return validator ? VALIDATORS.contains(classType.getFullyQualifiedName())
                : READ.contains(classType.getFullyQualifiedName())
                        || SpringBeans.assignable(context, classType, Set.of(CONVERTER));
    }

    /**
     * A string constant, also through a local that casts it.
     */
    private static Optional<String> constant(JavaSootMethod method, Immediate arg) {
        Value value = arg instanceof Local local ? Locals.definition(method.getBody(), local).orElse(arg) : arg;
        if (value instanceof JCastExpr cast) {
            value = cast.getOp();
        }
        return value instanceof StringConstant constant ? Optional.of(constant.getValue()) : Optional.empty();
    }

    /**
     * The text of {@code new SpelExpressionParser().parseExpression("..")}.
     */
    private static Optional<String> expression(JavaSootMethod method, Immediate arg) {
        if (arg instanceof Local local) {
            return Locals.definition(method.getBody(), local).filter(AbstractInvokeExpr.class::isInstance)
                    .map(AbstractInvokeExpr.class::cast)
                    .filter(parse -> parse.getMethodSignature().getName().equals("parseExpression")
                            && parse.getArgCount() >= 1 && parse.getArg(0) instanceof StringConstant)
                    .map(parse -> ((StringConstant) parse.getArg(0)).getValue());
        }
        return Optional.empty();
    }

    /**
     * SRC-03: the claims {@code MappedJwtClaimSetConverter.withDefaults(Map.of("roles", ..))} rewrites; another claim
     * set converter, or a map the scan can't read, is recorded as unread.
     */
    private void claimSet(JavaSootMethod method, Immediate arg) {
        Optional<AbstractInvokeExpr> mapped = arg instanceof Local local
                ? Locals.definition(method.getBody(), local).filter(AbstractInvokeExpr.class::isInstance)
                        .map(AbstractInvokeExpr.class::cast)
                        .filter(call -> call.getMethodSignature().getDeclClassType().getFullyQualifiedName()
                                .equals(MAPPED_CLAIMS))
                : Optional.empty();
        Optional<List<String>> keys = mapped.filter(call -> call.getArgCount() == 1).flatMap(call -> mapKeys(method,
                call.getArg(0)));
        if (keys.isPresent()) {
            rewritten.addAll(keys.get());
        }
        else {
            unreadClaimSets.add(mapped.isPresent() ? "a MappedJwtClaimSetConverter the scan can't read"
                    : unread(method, arg, Map.of(), 0, false).orElse("a claim set converter"));
        }
    }

    /**
     * The keys of {@code Map.of("a", x, "b", y)} or {@code Collections.singletonMap("a", x)}.
     */
    private static Optional<List<String>> mapKeys(JavaSootMethod method, Immediate map) {
        if (!(map instanceof Local local)) {
            return Optional.empty();
        }
        return Locals.definition(method.getBody(), local).filter(AbstractInvokeExpr.class::isInstance)
                .map(AbstractInvokeExpr.class::cast)
                .filter(call -> call.getMethodSignature().getName().equals("of")
                        && call.getMethodSignature().getDeclClassType().getFullyQualifiedName().equals("java.util.Map")
                        || call.getMethodSignature().getName().equals("singletonMap"))
                .map(call -> {
                    List<String> keys = new ArrayList<>();
                    for (int i = 0; i < call.getArgCount(); i += 2) {
                        if (!(call.getArg(i) instanceof StringConstant key)) {
                            return null;
                        }
                        keys.add(key.getValue());
                    }
                    return keys;
                });
    }
}
