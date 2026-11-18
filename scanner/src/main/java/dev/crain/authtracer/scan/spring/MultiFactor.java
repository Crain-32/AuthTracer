package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0037: multi-factor authentication (AUTHZ-07 to AUTHZ-10). An {@code AuthorizationManagerFactory} built by
 * {@code AuthorizationManagerFactories.multiFactor()} (or {@code @EnableMultiFactorAuthentication(authorities)}, which
 * registers one) adds its required factors to every rule it builds: {@code hasRole("ADMIN")} needs
 * {@code ROLE_ADMIN} and all of {@code FACTOR_PASSWORD}, {@code FACTOR_OTT}. Spring Security 7.1.1's
 * {@code DefaultAuthorizationManagerFactory} adds them to its role, authority and authentication managers, not to
 * {@code permitAll} or {@code denyAll}. A {@code when(..)} condition (or {@code when = WEBAUTHN_REGISTERED}) asks for
 * the factors only of some callers, so the factors are or'ed with {@code permitAll} (decision 0018); so is a
 * {@code RequiredAuthoritiesAuthorizationManager}, which asks named users for more.
 */
@Supports(Feature.REQUIREMENTS)
final class MultiFactor {

    static final String FACTORIES = "org.springframework.security.authorization.AuthorizationManagerFactories";
    static final String ADDITIONAL_BUILDER = FACTORIES + "$AdditionalRequiredFactorsBuilder";
    static final String ALL_FACTORS = "org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager";
    static final String ALL_FACTORS_BUILDER = ALL_FACTORS + "$Builder";
    static final String REQUIRED_FACTOR = "org.springframework.security.authorization.RequiredFactor";
    static final String REQUIRED_FACTOR_BUILDER = REQUIRED_FACTOR + "$Builder";
    static final String REQUIRED_AUTHORITIES =
            "org.springframework.security.authorization.RequiredAuthoritiesAuthorizationManager";
    private static final String MAP_REPOSITORY =
            "org.springframework.security.authorization.MapRequiredAuthoritiesRepository";
    private static final String ENABLE =
            "org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication";
    private static final String CUSTOMIZER = "org.springframework.security.config.Customizer";
    /**
     * {@code RequiredFactor.Builder}'s shorthands, {@code FactorGrantedAuthority}'s constants.
     */
    private static final Map<String, String> FACTOR_METHODS = Map.of(
            "authorizationCodeAuthority", "FACTOR_AUTHORIZATION_CODE", "bearerTokenAuthority", "FACTOR_BEARER",
            "casAuthority", "FACTOR_CAS", "passwordAuthority", "FACTOR_PASSWORD", "ottAuthority", "FACTOR_OTT",
            "samlAuthority", "FACTOR_SAML_RESPONSE", "webauthnAuthority", "FACTOR_WEBAUTHN",
            "x509Authority", "FACTOR_X509");
    private static final Set<String> FACTOR_MANAGERS = Set.of("hasRole", "hasAnyRole", "hasAllRoles",
            "hasAuthority", "hasAnyAuthority", "hasAllAuthorities", "authenticated", "fullyAuthenticated",
            "rememberMe", "anonymous");
    private static final int MAX_DEPTH = 3;

    /**
     * The factors a builder asks for.
     *
     * @param conditions what {@code when(..)} asks first, if anything
     * @param timed whether a factor must be recent ({@code validDuration})
     */
    static final class Factors {
        final SortedSet<String> authorities = new TreeSet<>();
        final List<String> conditions = new ArrayList<>();
        boolean timed;

        void add(Factors other) {
            authorities.addAll(other.authorities);
            conditions.addAll(other.conditions);
            timed |= other.timed;
        }

        /**
         * What the factors add to a rule.
         */
        Requirement requirement() {
            String names = String.join(", ", authorities);
            Requirement factors = authorities.isEmpty() ? Requirement.expression("required factors")
                    : Requirement.allAuthorities(List.copyOf(authorities)).withSource("factors " + names
                            + (timed ? " (recent)" : ""));
            if (conditions.isEmpty()) {
                return factors;
            }
            return Requirement.or(List.of(factors, Requirement.permitAll())).withSource("factors " + names
                    + " when " + String.join(" and ", conditions));
        }
    }

    private MultiFactor() {
    }

    /**
     * Whether the factory method builds a manager the factory adds its factors to.
     */
    static boolean addsFactors(String name) {
        return FACTOR_MANAGERS.contains(name);
    }

    static Optional<String> factorAuthority(String builderMethod) {
        return Optional.ofNullable(FACTOR_METHODS.get(builderMethod));
    }

    /**
     * Decision 0093: the factor a method reference to one of {@code RequiredFactor.Builder}'s shorthands asks for, as
     * the {@code Consumer<RequiredFactor.Builder>} of {@code requireFactor(..)}.
     */
    static Optional<String> referenced(MethodSignature target) {
        return factorAuthority(target.getName()).filter(authority -> target.getDeclClassType()
                .getFullyQualifiedName().equals(REQUIRED_FACTOR_BUILDER));
    }

    /**
     * The rule as a factory with this additional requirement builds it: each role, authority and authentication check
     * in it also needs the factors.
     */
    static Requirement require(Requirement rule, Requirement additional) {
        Requirement required = withFactors(rule, additional);
        if (required == rule) {
            return rule;
        }
        String source = rule.expression() != null ? rule.expression() : HttpSecurityRules.describe(rule);
        return new Requirement(required.kind(), required.authorities(), required.operands(), source + " with "
                + additional.expression(), rule.decidedBy());
    }

    private static Requirement withFactors(Requirement rule, Requirement additional) {
        return switch (rule.kind()) {
            // 7.1.1's factory adds them to anonymous() too, which no anonymous token can then pass.
            case ANY_AUTHORITY, ALL_AUTHORITIES, AUTHENTICATED, FULLY_AUTHENTICATED, REMEMBER_ME, ANONYMOUS ->
                    Requirement.and(List.of(rule, additional));
            case AND, OR, NOT -> {
                List<Requirement> operands = rule.operands().stream().map(operand -> withFactors(operand, additional))
                        .toList();
                yield operands.equals(rule.operands()) ? rule : rule.withOperands(operands);
            }
            default -> rule;
        };
    }

    /**
     * What the multi-factor builders in a bean method (and its lambdas) ask for, if it uses one.
     */
    static Optional<Requirement> built(ScanContext context, JavaSootMethod method) {
        Factors factors = new Factors();
        boolean[] used = {false};
        scan(context, method, factors, used, 0, new HashSet<>());
        return used[0] ? Optional.of(factors.requirement()) : Optional.empty();
    }

    /**
     * The factors a lambda passed to {@code requireFactor(..)} or {@code requireFactors(..)} asks for.
     */
    static Factors lambda(ScanContext context, MethodSignature lambda) {
        Factors factors = new Factors();
        context.findMethod(lambda).filter(JavaSootMethod::hasBody).ifPresent(body -> scan(context, body, factors,
                new boolean[1], 0, new HashSet<>()));
        return factors;
    }

    private static void scan(ScanContext context, JavaSootMethod method, Factors factors, boolean[] used, int depth,
            Set<MethodSignature> seen) {
        if (!seen.add(method.getSignature())) {
            return;
        }
        if (depth > MAX_DEPTH) {
            context.limit("Reading the factors a multi-factor manager is built with", MAX_DEPTH,
                    MethodNames.key(method.getSignature()));
            return;
        }
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt definition
                    && definition.getRightOp() instanceof JDynamicInvokeExpr dynamic) {
                for (Value argument : dynamic.getBootstrapArgs()) {
                    if (!(argument instanceof MethodHandle handle)
                            || !(handle.getReferenceSignature() instanceof MethodSignature target)) {
                        continue;
                    }
                    if (context.isApplication(target.getDeclClassType())) {
                        context.findMethod(target).filter(JavaSootMethod::hasBody).ifPresent(body -> scan(context,
                                body, factors, used, depth + 1, seen));
                    }
                    else {
                        // Decision 0093: requireFactor(RequiredFactor.Builder::passwordAuthority).
                        referenced(target).ifPresent(factors.authorities::add);
                    }
                }
            }
            Optional<AbstractInvokeExpr> found = Locals.invoke(stmt);
            if (found.isEmpty()) {
                continue;
            }
            AbstractInvokeExpr invoke = found.get();
            String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
            String name = invoke.getMethodSignature().getName();
            switch (owner) {
                case FACTORIES -> used[0] |= name.equals("multiFactor");
                case ALL_FACTORS -> used[0] |= name.equals("builder");
                case ADDITIONAL_BUILDER, ALL_FACTORS_BUILDER -> {
                    used[0] = true;
                    if (name.equals("when") || name.equals("withWhen")) {
                        factors.conditions.add("a condition");
                    }
                    else if (name.equals("requireFactors") && invoke.getArgCount() == 1
                            && invoke.getArg(0) instanceof Local array) {
                        factors.authorities.addAll(Locals.strings(method.getBody(), array));
                    }
                }
                case REQUIRED_FACTOR_BUILDER -> {
                    factorAuthority(name).ifPresent(factors.authorities::add);
                    if (name.equals("authority") && invoke.getArgCount() == 1
                            && invoke.getArg(0) instanceof StringConstant authority) {
                        factors.authorities.add(authority.getValue());
                    }
                    factors.timed |= name.equals("validDuration");
                }
                case REQUIRED_FACTOR -> {
                    if (name.equals("withAuthority") && invoke.getArgCount() == 1
                            && invoke.getArg(0) instanceof StringConstant authority) {
                        factors.authorities.add(authority.getValue());
                    }
                }
                default -> {
                }
            }
        }
    }

    /**
     * AUTHZ-07: {@code @EnableMultiFactorAuthentication(authorities = ..)} registers a raw
     * {@code DefaultAuthorizationManagerFactory} (7.1.1 {@code AuthorizationManagerFactoryConfiguration}) with those
     * factors, customized by the {@code Customizer<AdditionalRequiredFactorsBuilder>} beans; without authorities it
     * registers none.
     */
    static Optional<Requirement> annotated(ScanContext context) {
        for (JavaSootClass cls : context.applicationClasses()) {
            Optional<AnnotationUsage> annotation = context.findAnnotation(cls, ENABLE);
            if (annotation.isEmpty()) {
                continue;
            }
            Factors factors = new Factors();
            factors.authorities.addAll(Annotations.strings(annotation.get(), "authorities"));
            if (factors.authorities.isEmpty()) {
                return Optional.empty();
            }
            if (Annotations.strings(annotation.get(), "when").stream().anyMatch(when -> when.endsWith(
                    "WEBAUTHN_REGISTERED"))) {
                factors.conditions.add("WebAuthn is registered");
            }
            for (JavaSootMethod method : SpringBeans.beanMethods(context, CUSTOMIZER)) {
                if (method.hasBody() && context.classFiles().genericReturnType(method.getSignature())
                                .filter(generic -> generic.arguments().size() == 1 && generic.arguments()
                                        .getFirst().name().replace('.', '$').endsWith(
                                                "AuthorizationManagerFactories$AdditionalRequiredFactorsBuilder"))
                                .isPresent()) {
                    Factors customized = new Factors();
                    scan(context, method, customized, new boolean[1], 0, new HashSet<>());
                    factors.add(customized);
                }
            }
            return Optional.of(factors.requirement());
        }
        return Optional.empty();
    }

    /**
     * AUTHZ-10: a {@code RequiredAuthoritiesAuthorizationManager} asks the users named in its
     * {@code MapRequiredAuthoritiesRepository} for more authorities, everyone else for none.
     */
    static Requirement perUser(ScanContext context) {
        Factors factors = new Factors();
        List<String> users = new ArrayList<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                    if (invoke.isPresent() && invoke.get().getMethodSignature().getDeclClassType()
                            .getFullyQualifiedName().equals(MAP_REPOSITORY)
                            && invoke.get().getMethodSignature().getName().equals("saveRequiredAuthorities")
                            && invoke.get().getArgCount() == 2) {
                        if (invoke.get().getArg(0) instanceof StringConstant user) {
                            users.add(user.getValue());
                        }
                        if (invoke.get().getArg(1) instanceof Local list) {
                            factors.authorities.addAll(listed(method, list));
                        }
                    }
                }
            }
        }
        factors.conditions.add(users.isEmpty() ? "the user is listed" : "the user is " + String.join(" or ", users));
        return factors.requirement();
    }

    /**
     * The constants of {@code List.of(..)} or {@code Arrays.asList(..)}.
     */
    private static List<String> listed(JavaSootMethod method, Local list) {
        Optional<Value> definition = Locals.definition(method.getBody(), list);
        if (definition.isPresent() && definition.get() instanceof AbstractInvokeExpr call) {
            List<String> values = new ArrayList<>();
            for (Value arg : call.getArgs()) {
                if (arg instanceof StringConstant constant) {
                    values.add(constant.getValue());
                }
                else if (arg instanceof Local array) {
                    values.addAll(Locals.strings(method.getBody(), array));
                }
            }
            return values;
        }
        return List.of();
    }
}
