package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.expr.JSpecialInvokeExpr;
import sootup.core.jimple.common.expr.JStaticInvokeExpr;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.ref.JStaticFieldRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.JThrowStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.MethodModifier;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootMethod;

/**
 * Check-like code outside Spring Security's mechanisms: code that reads who the caller is and denies by itself.
 * MVP.md counts these as No Authorization but lists them, so owners can move them to a recognized mechanism or
 * declare them as a Provided fact. A method is read together with the lambdas it creates (RX-15: reactive code reads
 * the caller and signals its error in them), and a check split between a method and a helper it calls (one of its
 * own class's, or a static method) is the method's.
 */
@Supports(Feature.FINDING_UNRECOGNIZED_CHECK)
final class HandRolledChecks {

    private static final String CONTEXT = "org.springframework.security.core.context.";
    /**
     * Calls that read the caller's identity, by declaring type.
     */
    private static final Map<String, Set<String>> IDENTITY = Map.ofEntries(
            Map.entry(CONTEXT + "SecurityContext", Set.of("getAuthentication")),
            Map.entry(CONTEXT + "ReactiveSecurityContextHolder", Set.of("getContext")),
            Map.entry("org.springframework.web.server.ServerWebExchange", Set.of("getPrincipal")),
            Map.entry("org.springframework.security.core.Authentication",
                    Set.of("getAuthorities", "getName", "getPrincipal", "getDetails")),
            Map.entry("org.springframework.security.core.GrantedAuthority", Set.of("getAuthority")),
            Map.entry("jakarta.servlet.http.HttpServletRequest",
                    Set.of("isUserInRole", "getUserPrincipal", "getRemoteUser")),
            Map.entry("java.security.Principal", Set.of("getName")),
            Map.entry("org.springframework.security.oauth2.jwt.Jwt", Set.of("getClaim", "getClaimAsString",
                    "getClaimAsStringList", "getSubject", "getClaims")),
            Map.entry("org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken",
                    Set.of("getToken", "getTokenAttributes", "getName", "getAuthorities")),
            // The principal itself, and the Authentication types code declares concretely.
            Map.entry("org.springframework.security.core.userdetails.UserDetails",
                    Set.of("getUsername", "getAuthorities")),
            Map.entry("org.springframework.security.core.userdetails.User", Set.of("getUsername", "getAuthorities")),
            Map.entry("org.springframework.security.oauth2.core.user.OAuth2User",
                    Set.of("getAttribute", "getAttributes", "getName", "getAuthorities")),
            Map.entry("org.springframework.security.oauth2.core.oidc.user.OidcUser",
                    Set.of("getAttribute", "getAttributes", "getName", "getAuthorities", "getSubject", "getEmail",
                            "getClaims", "getClaim", "getPreferredUsername")),
            Map.entry("org.springframework.security.authentication.UsernamePasswordAuthenticationToken",
                    Set.of("getAuthorities", "getName", "getPrincipal", "getDetails")),
            Map.entry("org.springframework.security.authentication.AbstractAuthenticationToken",
                    Set.of("getAuthorities", "getName", "getPrincipal", "getDetails")),
            Map.entry("org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken",
                    Set.of("getAuthorities", "getName", "getPrincipal", "getAuthorizedClientRegistrationId")));
    /**
     * Reads of a request header, which count as reading the caller when the header carries a credential.
     */
    private static final Map<String, String> HEADERS = Map.of("jakarta.servlet.http.HttpServletRequest", "getHeader",
            "org.springframework.http.HttpHeaders", "getFirst");
    private static final List<String> CREDENTIAL_HEADERS = List.of("authorization", "key", "token", "auth");
    /**
     * Parameters Spring fills with the caller.
     */
    private static final Set<String> CALLER_PARAMETERS = Set.of(
            "org.springframework.security.core.annotation.AuthenticationPrincipal",
            "org.springframework.security.core.annotation.CurrentSecurityContext");

    private static final Set<String> DENIAL_EXCEPTIONS = Set.of(
            "org.springframework.security.access.AccessDeniedException",
            "org.springframework.security.core.AuthenticationException");
    private static final Set<String> STATUS_EXCEPTIONS = Set.of(
            "org.springframework.web.server.ResponseStatusException", "org.springframework.web.ErrorResponseException");
    private static final String RESPONSE_STATUS = "org.springframework.web.bind.annotation.ResponseStatus";
    private static final Set<String> SIGNALS = Set.of("reactor.core.publisher.Mono", "reactor.core.publisher.Flux");
    /**
     * Calls whose first argument is the response's status.
     */
    private static final Map<String, Set<String>> STATUS_CALLS = Map.of(
            "org.springframework.http.ResponseEntity", Set.of("status", "<init>"),
            "jakarta.servlet.http.HttpServletResponse", Set.of("sendError", "setStatus"),
            "org.springframework.http.server.reactive.ServerHttpResponse", Set.of("setStatusCode", "setRawStatusCode"),
            "org.springframework.web.servlet.function.ServerResponse", Set.of("status"),
            "org.springframework.web.reactive.function.server.ServerResponse", Set.of("status"));
    private static final Set<String> DENIAL_STATUSES = Set.of("FORBIDDEN", "UNAUTHORIZED");
    private static final Set<Integer> DENIAL_CODES = Set.of(401, 403);

    /**
     * What a method (with its lambdas) reads of the caller and how it denies.
     */
    private record Evidence(Set<String> reads, Set<String> denials, Integer denialLine) {

        boolean check() {
            return !reads.isEmpty() && !denials.isEmpty();
        }

        Evidence and(Evidence other) {
            Set<String> reads = new LinkedHashSet<>(this.reads);
            reads.addAll(other.reads);
            Set<String> denials = new LinkedHashSet<>(this.denials);
            denials.addAll(other.denials);
            return new Evidence(reads, denials, denialLine != null ? denialLine : other.denialLine);
        }
    }

    private final ScanContext context;
    private final Map<String, Evidence> evidence = new LinkedHashMap<>();

    HandRolledChecks(ScanContext context) {
        this.context = context;
    }

    /**
     * The hand-rolled checks among the methods requests reach. A lambda is read as part of the method that creates
     * it; a helper's part is reported with its caller unless the helper is a check by itself.
     */
    List<Finding> detect(Collection<JavaSootMethod> methods) {
        Set<String> lambdas = new HashSet<>();
        methods.forEach(method -> lambdas(method).forEach(lambda -> lambdas.add(lambda.getSignature().toString())));
        List<Finding> findings = new ArrayList<>();
        for (JavaSootMethod method : methods) {
            if (!method.hasBody() || lambdas.contains(method.getSignature().toString())) {
                continue;
            }
            Evidence own = evidence(method);
            if (own.check()) {
                findings.add(finding(method, own, List.of()));
                continue;
            }
            Evidence combined = own;
            List<String> via = new ArrayList<>();
            for (JavaSootMethod helper : helpers(method)) {
                Evidence part = evidence(helper);
                if (part.check()) {
                    // Reported as the helper's own.
                    combined = own;
                    via.clear();
                    break;
                }
                if (!part.reads().isEmpty() || !part.denials().isEmpty()) {
                    combined = combined.and(part);
                    via.add(MethodNames.key(helper.getSignature()));
                }
            }
            if (combined.check()) {
                findings.add(finding(method, combined, via));
            }
        }
        return findings;
    }

    private static Finding finding(JavaSootMethod method, Evidence evidence, List<String> via) {
        String where = MethodNames.key(method.getSignature()) + (via.isEmpty() ? ""
                : via.size() == 1 ? " and its helper " + via.getFirst() : " and its helpers " + String.join(", ", via));
        return new Finding(Finding.Kind.UNRECOGNIZED_CHECK, "Hand-rolled check in " + where + ": reads "
                + String.join(", ", evidence.reads()) + " and denies with " + String.join(", ", evidence.denials())
                + ". AuthTracer counts it as No Authorization; use a recognized mechanism (e.g. @PreAuthorize)"
                + " or declare it as a Provided check", MethodNames.codeRef(method.getSignature())
                        .atLine(evidence.denialLine()));
    }

    /**
     * The method's own evidence, with its lambdas'.
     */
    private Evidence evidence(JavaSootMethod method) {
        Evidence found = evidence.get(method.getSignature().toString());
        if (found == null) {
            found = new Evidence(new LinkedHashSet<>(), new LinkedHashSet<>(), null);
            for (JavaSootMethod part : unit(method)) {
                found = found.and(read(part));
            }
            evidence.put(method.getSignature().toString(), found);
        }
        return found;
    }

    /**
     * The method and the lambdas it creates, theirs too.
     */
    private List<JavaSootMethod> unit(JavaSootMethod method) {
        List<JavaSootMethod> unit = new ArrayList<>(List.of(method));
        for (int i = 0; i < unit.size(); i++) {
            lambdas(unit.get(i)).stream().filter(lambda -> !unit.contains(lambda)).forEach(unit::add);
        }
        return unit;
    }

    /**
     * The synthetic methods of the method's class its lambdas run.
     */
    private List<JavaSootMethod> lambdas(JavaSootMethod method) {
        List<JavaSootMethod> lambdas = new ArrayList<>();
        if (!method.hasBody()) {
            return lambdas;
        }
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isPresent() && invoke.get() instanceof JDynamicInvokeExpr dynamic) {
                for (MethodSignature referenced : handles(dynamic)) {
                    context.findMethod(referenced).filter(JavaSootMethod::hasBody)
                            .filter(lambda -> lambda.getDeclaringClassType().equals(method.getDeclaringClassType())
                                    && (MethodModifier.isSynthetic(lambda.getModifiers())
                                            || lambda.getName().contains("lambda$")))
                            .ifPresent(lambdas::add);
                }
            }
        }
        return lambdas;
    }

    /**
     * The application methods the method and its lambdas call that are helpers: its own class's, or static ones.
     */
    private List<JavaSootMethod> helpers(JavaSootMethod method) {
        Set<JavaSootMethod> unit = new HashSet<>(unit(method));
        List<JavaSootMethod> helpers = new ArrayList<>();
        for (JavaSootMethod part : unit) {
            for (Stmt stmt : part.getBody().getStmts()) {
                Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                if (invoke.isEmpty() || invoke.get() instanceof JDynamicInvokeExpr) {
                    continue;
                }
                MethodSignature called = invoke.get().getMethodSignature();
                boolean own = called.getDeclClassType().equals(method.getDeclaringClassType())
                        && (invoke.get() instanceof JSpecialInvokeExpr || invoke.get() instanceof JStaticInvokeExpr
                                || !part.isStatic() && invoke.get() instanceof AbstractInstanceInvokeExpr instance
                                        && part.getBody().getThisLocal().equals(instance.getBase()));
                boolean helper = own || invoke.get() instanceof JStaticInvokeExpr
                        && context.isApplication(called.getDeclClassType());
                if (helper && !called.getName().startsWith("<")) {
                    context.findMethod(called).filter(JavaSootMethod::hasBody)
                            .filter(found -> !unit.contains(found) && !helpers.contains(found)).ifPresent(helpers::add);
                }
            }
        }
        return helpers;
    }

    private static List<MethodSignature> handles(JDynamicInvokeExpr dynamic) {
        List<MethodSignature> handles = new ArrayList<>();
        for (Value argument : dynamic.getBootstrapArgs()) {
            if (argument instanceof MethodHandle handle && handle.isMethodRef()
                    && handle.getReferenceSignature() instanceof MethodSignature signature) {
                handles.add(signature);
            }
        }
        return handles;
    }

    /**
     * One method's reads and denials, without its lambdas'.
     */
    private Evidence read(JavaSootMethod method) {
        Set<String> reads = new LinkedHashSet<>(callerParameters(method));
        Set<String> denials = new LinkedHashSet<>();
        Integer denialLine = null;
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<String> denial = denial(method, stmt);
            if (denial.isPresent()) {
                denials.add(denial.get());
                denialLine = denialLine != null ? denialLine : stmt.getPositionInfo().getStmtPosition().getFirstLine();
            }
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isEmpty()) {
                continue;
            }
            List<MethodSignature> called = invoke.get() instanceof JDynamicInvokeExpr dynamic ? handles(dynamic)
                    : List.of(invoke.get().getMethodSignature());
            for (MethodSignature signature : called) {
                String owner = signature.getDeclClassType().getFullyQualifiedName();
                if (IDENTITY.getOrDefault(owner, Set.of()).contains(signature.getName())) {
                    reads.add(MethodNames.simpleName(owner) + "." + signature.getName() + "()");
                }
            }
            String owner = invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
            if (invoke.get().getMethodSignature().getName().equals(HEADERS.get(owner)) && invoke.get().getArgCount() == 1
                    && invoke.get().getArg(0) instanceof StringConstant header && CREDENTIAL_HEADERS.stream()
                            .anyMatch(header.getValue().toLowerCase(Locale.ROOT)::contains)) {
                reads.add(MethodNames.simpleName(owner) + "." + invoke.get().getMethodSignature().getName() + "("
                        + header.getValue() + ")");
            }
        }
        return new Evidence(reads, denials, denialLine);
    }

    /**
     * The parameters Spring fills with the caller ({@code @AuthenticationPrincipal Account account}) that the method
     * uses.
     */
    private List<String> callerParameters(JavaSootMethod method) {
        List<String> reads = new ArrayList<>();
        for (int i = 0; i < method.getParameterCount(); i++) {
            Set<String> annotations = context.classFiles().parameterAnnotations(method.getSignature(), i);
            Optional<String> annotation = CALLER_PARAMETERS.stream().filter(annotations::contains).findFirst();
            if (annotation.isPresent() && used(method, i)) {
                reads.add("@" + MethodNames.simpleName(annotation.get()) + " "
                        + MethodNames.simpleName(method.getParameterType(i).toString()));
            }
        }
        return reads;
    }

    private static boolean used(JavaSootMethod method, int index) {
        Local parameter = null;
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt definition && definition.getRightOp() instanceof JParameterRef ref
                    && ref.getIndex() == index && definition.getLeftOp() instanceof Local local) {
                parameter = local;
            }
            else if (parameter != null && stmt.getUses().contains(parameter)) {
                return true;
            }
        }
        return false;
    }

    private Optional<String> denial(JavaSootMethod method, Stmt stmt) {
        if (stmt instanceof JThrowStmt thrown && thrown.getOp() instanceof Local local) {
            return deniedWith(method, local).map(type -> "throw " + type);
        }
        Optional<AbstractInvokeExpr> found = Locals.invoke(stmt);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        AbstractInvokeExpr invoke = found.get();
        String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = invoke.getMethodSignature().getName();
        // RX-15: Mono.error(new AccessDeniedException(..)), or a supplier of one.
        if (SIGNALS.contains(owner) && name.equals("error") && invoke.getArgCount() == 1
                && invoke.getArg(0) instanceof Local signal) {
            return deniedWith(method, signal).or(() -> supplied(method, signal))
                    .map(type -> MethodNames.simpleName(owner) + ".error(" + type + ")");
        }
        if (!STATUS_CALLS.getOrDefault(owner, Set.of()).contains(name)) {
            return Optional.empty();
        }
        // new ResponseEntity<>(body, headers, FORBIDDEN): the status is the last argument.
        Optional<String> status = invoke.getArgs().stream().map(argument -> status(method, argument))
                .filter(java.util.Objects::nonNull).findFirst();
        return status.map(found1 -> (name.equals("<init>") ? "new " + MethodNames.simpleName(owner)
                : MethodNames.simpleName(owner) + "." + name) + "(" + found1 + ")");
    }

    /**
     * The exception a local holds when it is one that denies: Spring Security's (AccessDeniedException,
     * AuthenticationException, or a subclass), a status exception made with 401 or 403, one annotated
     * {@code @ResponseStatus(FORBIDDEN|UNAUTHORIZED)} (its class or a superclass), or one named for a denial.
     */
    private Optional<String> deniedWith(JavaSootMethod method, Local local) {
        Optional<ClassType> created = Locals.created(method.getBody(), local);
        if (created.isEmpty()) {
            return Optional.empty();
        }
        List<ClassType> hierarchy = new ArrayList<>(List.of(created.get()));
        hierarchy.addAll(context.superClassesOf(created.get()));
        boolean denies = hierarchy.stream().anyMatch(type -> DENIAL_EXCEPTIONS.contains(type.getFullyQualifiedName())
                || respondsWithDenial(type))
                || hierarchy.stream().anyMatch(type -> STATUS_EXCEPTIONS.contains(type.getFullyQualifiedName()))
                        && constructedWithDenialStatus(method, local)
                || deniedByName(created.get().getFullyQualifiedName());
        return denies ? Optional.of(MethodNames.simpleName(created.get().getFullyQualifiedName())) : Optional.empty();
    }

    private boolean respondsWithDenial(ClassType type) {
        Optional<AnnotationUsage> annotation = context.isApplication(type) ? context.findClass(type)
                .flatMap(cls -> context.findAnnotation(cls, RESPONSE_STATUS)) : Optional.empty();
        return annotation.isPresent() && DENIAL_STATUSES.stream().anyMatch(status -> Annotations.string(
                annotation.get(), "value").or(() -> Annotations.string(annotation.get(), "code"))
                .filter(value -> value.endsWith(status)).isPresent());
    }

    /**
     * {@code Mono.error(() -> new AccessDeniedException(..))}: what the supplier's lambda returns.
     */
    private Optional<String> supplied(JavaSootMethod method, Local supplier) {
        if (!(Locals.definition(method.getBody(), supplier).orElse(null) instanceof JDynamicInvokeExpr dynamic)) {
            return Optional.empty();
        }
        for (MethodSignature signature : handles(dynamic)) {
            Optional<JavaSootMethod> lambda = context.findMethod(signature).filter(JavaSootMethod::hasBody);
            for (Stmt stmt : lambda.map(found -> found.getBody().getStmts()).orElse(List.of())) {
                if (stmt instanceof JReturnStmt returned && returned.getOp() instanceof Local value) {
                    Optional<String> denied = deniedWith(lambda.get(), value);
                    if (denied.isPresent()) {
                        return denied;
                    }
                }
            }
        }
        return Optional.empty();
    }

    private static boolean constructedWithDenialStatus(JavaSootMethod method, Local exception) {
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isPresent() && invoke.get().getMethodSignature().getName().equals("<init>")
                    && invoke.get().getUses().contains(exception)
                    && invoke.get().getArgs().stream().anyMatch(arg -> status(method, arg) != null)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The denial status a value names: 401 or 403, {@code HttpStatus.FORBIDDEN}, its {@code value()}, or
     * {@code HttpStatus.valueOf(403)}; {@code null} for any other.
     */
    private static String status(JavaSootMethod method, Immediate value) {
        if (value instanceof IntConstant code) {
            return DENIAL_CODES.contains(code.getValue()) ? String.valueOf(code.getValue()) : null;
        }
        Value definition = value instanceof Local local ? Locals.definition(method.getBody(), local).orElse(value)
                : value;
        // HttpStatus.FORBIDDEN.value()
        if (definition instanceof AbstractInstanceInvokeExpr call && call.getMethodSignature().getName().equals("value")
                && call.getArgCount() == 0) {
            definition = Locals.definition(method.getBody(), call.getBase()).orElse(definition);
        }
        // HttpStatus.valueOf(403), HttpStatusCode.valueOf(403)
        if (definition instanceof JStaticInvokeExpr call && call.getMethodSignature().getName().equals("valueOf")
                && call.getArgCount() == 1 && call.getArg(0) instanceof IntConstant code) {
            return DENIAL_CODES.contains(code.getValue()) ? String.valueOf(code.getValue()) : null;
        }
        if (definition instanceof JStaticFieldRef field
                && DENIAL_STATUSES.contains(field.getFieldSignature().getName())) {
            return field.getFieldSignature().getName();
        }
        return null;
    }

    private static boolean deniedByName(String type) {
        String name = MethodNames.simpleName(type);
        return List.of("AccessDenied", "Forbidden", "Unauthorized", "NotAuthorized").stream().anyMatch(name::contains);
    }
}
