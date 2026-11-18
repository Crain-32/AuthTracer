package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation.Argument;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.ScanContext;
import org.springframework.expression.ParseException;
import org.springframework.expression.spel.SpelNode;
import org.springframework.expression.spel.ast.CompoundExpression;
import org.springframework.expression.spel.ast.Indexer;
import org.springframework.expression.spel.ast.MethodReference;
import org.springframework.expression.spel.ast.PropertyOrFieldReference;
import org.springframework.expression.spel.ast.StringLiteral;
import org.springframework.expression.spel.ast.VariableReference;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.ClassType;
import sootup.core.types.PrimitiveType;
import sootup.core.types.Type;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0091: what a pre/post expression reads besides the caller's authorities. EXPR-02: the method's parameters
 * it names ({@code #id}, {@code #p0}), as Spring names them when it evaluates the expression, and what the request
 * binds into them. EXPR-04: the token claims it reads ({@code principal.claims['aud']}).
 */
@Supports(Feature.REQUIREMENTS)
final class ExpressionReads {

    private static final SpelExpressionParser PARSER = new SpelExpressionParser();
    /**
     * 7.1.1 {@code DefaultSecurityParameterNameDiscoverer} asks these annotations first; when any parameter has one,
     * their names are the only ones ({@code PrioritizedParameterNameDiscoverer} takes the first answer).
     */
    private static final List<String> NAME_ANNOTATIONS = List.of("org.springframework.security.core.parameters.P",
            "org.springframework.security.access.method.P", "org.springframework.data.repository.query.Param");
    /**
     * Spring Framework 7.0.9 {@code MethodBasedEvaluationContext#lazyLoadArguments}: every argument is also
     * {@code #a<i>} and {@code #p<i>}.
     */
    private static final Pattern POSITIONAL = Pattern.compile("[ap](\\d+)");
    private static final String KOTLIN_REFLECT = "kotlin.reflect.full.KClasses";
    /**
     * Where the token's claims are read: a {@code Jwt}'s {@code claims}, a {@code JwtAuthenticationToken}'s
     * {@code tokenAttributes}, an introspected or OAuth2 principal's {@code attributes}.
     */
    private static final Set<String> CLAIM_MAPS = Set.of("claims", "tokenAttributes", "attributes");
    private static final Set<String> CLAIM_METHODS = Set.of("getClaim", "getClaimAsString", "getClaimAsStringList",
            "getClaimAsBoolean", "getClaimAsInstant", "getClaimAsURL", "getClaimAsMap", "hasClaim", "getAttribute");
    /**
     * A {@code Jwt}'s getters for its registered claims.
     */
    private static final Map<String, String> REGISTERED_CLAIMS = Map.of("subject", "sub", "audience", "aud",
            "issuer", "iss", "expiresAt", "exp", "issuedAt", "iat", "notBefore", "nbf");
    private static final Set<String> CALLER_ROOTS = Set.of("principal", "authentication");

    /**
     * What a handler parameter's annotation binds into it, and whether the binding is named.
     */
    private record Binding(String what, boolean named) {
    }

    private static final Map<String, Binding> BINDINGS = bindings();
    private static final Set<String> CALLER_TYPES = Set.of("java.security.Principal",
            "org.springframework.security.core.Authentication");
    private static final Set<String> SIMPLE_TYPES = Set.of("java.lang.String", "java.lang.Long", "java.lang.Integer",
            "java.lang.Short", "java.lang.Byte", "java.lang.Double", "java.lang.Float", "java.lang.Boolean",
            "java.lang.Character", "java.math.BigDecimal", "java.math.BigInteger", "java.util.UUID",
            "java.time.LocalDate", "java.time.LocalDateTime", "java.time.Instant");
    /**
     * How many calls deep a handler's parameter is followed to the checked method.
     */
    private static final int DEPTH = 3;

    private record CallSite(JavaSootMethod caller, AbstractInvokeExpr invoke) {
    }

    private final ScanContext context;
    private Map<String, List<CallSite>> callSites;

    ExpressionReads(ScanContext context) {
        this.context = context;
    }

    /**
     * EXPR-02: the variables the expression names, each with the method's parameter Spring gives it.
     */
    List<Argument> arguments(JavaSootMethod method, String expression) {
        Set<String> variables = new LinkedHashSet<>();
        parse(expression).ifPresent(ast -> variables(ast, variables));
        if (variables.isEmpty()) {
            return List.of();
        }
        List<String> names = names(method);
        List<Argument> arguments = new ArrayList<>();
        for (String variable : variables) {
            Matcher positional = POSITIONAL.matcher(variable);
            int index = positional.matches() && Integer.parseInt(positional.group(1)) < method.getParameterCount()
                    ? Integer.parseInt(positional.group(1)) : names.indexOf(variable);
            arguments.add(new Argument(variable, index < 0 ? null : index, null));
        }
        return arguments;
    }

    /**
     * Why Spring gives a variable of the expression no parameter of the method.
     */
    String unnamed(JavaSootMethod method) {
        return annotatedNames(method).isPresent()
                ? "some of its parameters have @P names, and then Spring takes no other names"
                : "no parameter has @P, and the class file has no parameter names, as it isn't compiled with"
                        + " -parameters";
    }

    /**
     * EXPR-04: the token claims the expression reads, in order.
     */
    static List<String> claims(String expression) {
        Set<String> claims = new LinkedHashSet<>();
        parse(expression).ifPresent(ast -> claims(ast, claims));
        return List.copyOf(claims);
    }

    /**
     * What the request binds into the method's parameter: the handler's binding when the method is one, else the one
     * binding every application call to it passes along from a handler's parameter; {@code null} when AuthTracer can't
     * tell.
     */
    String binding(JavaSootMethod method, int parameter, Set<JavaSootMethod> handlers) {
        return binding(method, parameter, handlers, DEPTH);
    }

    private String binding(JavaSootMethod method, int parameter, Set<JavaSootMethod> handlers, int depth) {
        if (handlers.contains(method)) {
            return handlerBinding(method, parameter);
        }
        List<CallSite> sites = depth == 0 ? List.of() : callSites(method);
        String agreed = null;
        for (CallSite site : sites) {
            Value argument = site.invoke().getArg(parameter);
            OptionalInt passed = argument instanceof Local local
                    ? Locals.parameterIndex(site.caller().getBody(), local) : OptionalInt.empty();
            String bound = passed.isPresent() ? binding(site.caller(), passed.getAsInt(), handlers, depth - 1) : null;
            if (bound == null || agreed != null && !agreed.equals(bound)) {
                return null;
            }
            agreed = bound;
        }
        return agreed;
    }

    /**
     * The binding of a handler's parameter: its annotation's, the caller for a {@code Principal} or
     * {@code Authentication}, or for a simple value on a request mapping a request parameter of its name (Spring MVC's
     * default resolution).
     */
    private String handlerBinding(JavaSootMethod handler, int parameter) {
        Set<String> annotations = context.classFiles().parameterAnnotations(handler.getSignature(), parameter);
        for (Map.Entry<String, Binding> binding : BINDINGS.entrySet()) {
            if (annotations.contains(binding.getKey())) {
                return binding.getValue().named() ? binding.getValue().what() + " " + boundName(handler, parameter,
                        binding.getKey()) : binding.getValue().what();
            }
        }
        Type type = handler.getParameterType(parameter);
        if (type instanceof ClassType classType && SpringBeans.assignable(context, classType, CALLER_TYPES)) {
            return "the caller";
        }
        boolean simple = type instanceof PrimitiveType || type instanceof ClassType classType
                && (SIMPLE_TYPES.contains(classType.getFullyQualifiedName())
                        || context.findClass(classType).map(JavaSootClass::isEnum).orElse(false));
        return simple && context.hasAnnotation(handler, SpringNames.REQUEST_MAPPING)
                ? "request parameter " + parameterName(handler, parameter) : null;
    }

    /**
     * The name a binding annotation gives ({@code @PathVariable("id")}, {@code name = "id"}), else the parameter's.
     */
    private String boundName(JavaSootMethod handler, int parameter, String annotation) {
        return context.classFiles().parameterAnnotationValue(handler.getSignature(), parameter, annotation)
                .or(() -> context.classFiles().parameterAnnotationElement(handler.getSignature(), parameter,
                        annotation, "name"))
                .filter(name -> !name.isEmpty()).orElseGet(() -> parameterName(handler, parameter));
    }

    private String parameterName(JavaSootMethod method, int parameter) {
        List<String> names = names(method);
        return parameter < names.size() && names.get(parameter) != null ? names.get(parameter)
                : method.getBody().getParameterLocal(parameter).getName();
    }

    /**
     * The parameter names Spring discovers for the method ({@code null} where it finds none): those of {@code @P}
     * (or Spring Data's {@code @Param}) on it or the interface method it implements, else the class file's
     * {@code MethodParameters}, else for a Kotlin class with kotlin-reflect present Kotlin's own; none otherwise.
     */
    private List<String> names(JavaSootMethod method) {
        Optional<List<String>> annotated = annotatedNames(method);
        if (annotated.isPresent()) {
            return annotated.get();
        }
        Optional<List<String>> declared = context.classFiles().declaredParameterNames(method.getSignature());
        if (declared.isPresent()) {
            return declared.get();
        }
        boolean kotlin = context.classFiles().classAnnotations(method.getDeclaringClassType().getFullyQualifiedName())
                .containsKey("kotlin.Metadata");
        if (kotlin && context.findClass(KOTLIN_REFLECT).isPresent() && method.hasBody()) {
            List<String> names = new ArrayList<>();
            for (int i = 0; i < method.getParameterCount(); i++) {
                names.add(method.getBody().getParameterLocal(i).getName());
            }
            return names;
        }
        return List.of();
    }

    private Optional<List<String>> annotatedNames(JavaSootMethod method) {
        List<JavaSootMethod> declarations = new ArrayList<>(List.of(method));
        for (ClassType type : context.interfacesOf(method.getDeclaringClassType())) {
            context.findClass(type).flatMap(cls -> cls.getMethod(method.getSubSignature()))
                    .ifPresent(declarations::add);
        }
        for (JavaSootMethod declaration : declarations) {
            List<String> names = new ArrayList<>();
            boolean any = false;
            for (int i = 0; i < declaration.getParameterCount(); i++) {
                int parameter = i;
                Optional<String> name = NAME_ANNOTATIONS.stream().flatMap(annotation -> context.classFiles()
                        .parameterAnnotationValue(declaration.getSignature(), parameter, annotation).stream())
                        .findFirst();
                any |= name.isPresent();
                names.add(name.orElse(null));
            }
            if (any) {
                return Optional.of(names);
            }
        }
        return Optional.empty();
    }

    /**
     * The application's calls to the method: to it, or to the method of a type it implements or extends that it
     * overrides.
     */
    private List<CallSite> callSites(JavaSootMethod method) {
        if (callSites == null) {
            callSites = new HashMap<>();
            for (JavaSootClass cls : context.applicationClasses()) {
                for (JavaSootMethod caller : cls.getMethods()) {
                    if (!caller.hasBody()) {
                        continue;
                    }
                    for (Stmt stmt : caller.getBody().getStmts()) {
                        Locals.invoke(stmt).ifPresent(invoke -> callSites.computeIfAbsent(invoke.getMethodSignature()
                                .getSubSignature().toString(), key -> new ArrayList<>()).add(new CallSite(caller,
                                        invoke)));
                    }
                }
            }
        }
        ClassType owner = method.getDeclaringClassType();
        return callSites.getOrDefault(method.getSubSignature().toString(), List.of()).stream()
                .filter(site -> SpringBeans.assignable(context, owner, Set.of(site.invoke().getMethodSignature()
                        .getDeclClassType().getFullyQualifiedName())))
                .toList();
    }

    private static Optional<SpelNode> parse(String expression) {
        try {
            return Optional.of(PARSER.parseRaw(expression).getAST());
        }
        catch (ParseException ex) {
            return Optional.empty();
        }
    }

    private static void variables(SpelNode node, Set<String> found) {
        if (node instanceof VariableReference) {
            String name = node.toStringAST().substring(1);
            if (!name.equals("this") && !name.equals("root")) {
                found.add(name);
            }
        }
        for (int i = 0; i < node.getChildCount(); i++) {
            variables(node.getChild(i), found);
        }
    }

    /**
     * Claims in a chain that starts at the caller: {@code principal.claims['aud']}, {@code principal.claims.aud},
     * {@code authentication.token.getClaim('tenant')}, a registered claim's getter on the principal or the token
     * ({@code principal.subject}).
     */
    private static void claims(SpelNode node, Set<String> found) {
        if (node instanceof CompoundExpression && node.getChild(0) instanceof PropertyOrFieldReference first
                && CALLER_ROOTS.contains(first.getName())) {
            for (int i = 1; i < node.getChildCount(); i++) {
                SpelNode step = node.getChild(i);
                SpelNode next = i + 1 < node.getChildCount() ? node.getChild(i + 1) : null;
                if (step instanceof PropertyOrFieldReference property && CLAIM_MAPS.contains(property.getName())) {
                    if (next instanceof Indexer indexer && indexer.getChild(0) instanceof StringLiteral literal) {
                        found.add(String.valueOf(literal.getLiteralValue().getValue()));
                    }
                    else if (next instanceof PropertyOrFieldReference claim) {
                        found.add(claim.getName());
                    }
                }
                else if (step instanceof MethodReference method && CLAIM_METHODS.contains(method.getName())
                        && method.getChildCount() > 0 && method.getChild(0) instanceof StringLiteral literal) {
                    found.add(String.valueOf(literal.getLiteralValue().getValue()));
                }
                else if (step instanceof PropertyOrFieldReference property && REGISTERED_CLAIMS.containsKey(
                        property.getName()) && node.getChild(i - 1) instanceof PropertyOrFieldReference previous
                        && Set.of("principal", "token").contains(previous.getName())) {
                    found.add(REGISTERED_CLAIMS.get(property.getName()));
                }
            }
        }
        for (int i = 0; i < node.getChildCount(); i++) {
            claims(node.getChild(i), found);
        }
    }

    private static Map<String, Binding> bindings() {
        String web = "org.springframework.web.bind.annotation.";
        String messaging = "org.springframework.messaging.handler.annotation.";
        Map<String, Binding> bindings = new LinkedHashMap<>();
        bindings.put(web + "PathVariable", new Binding("path variable", true));
        bindings.put(web + "RequestParam", new Binding("request parameter", true));
        bindings.put(web + "RequestHeader", new Binding("request header", true));
        bindings.put(web + "CookieValue", new Binding("cookie", true));
        bindings.put(web + "MatrixVariable", new Binding("matrix variable", true));
        bindings.put(web + "RequestPart", new Binding("request part", true));
        bindings.put(web + "RequestBody", new Binding("request body", false));
        bindings.put(web + "ModelAttribute", new Binding("request parameters", false));
        bindings.put("org.springframework.graphql.data.method.annotation.Argument",
                new Binding("GraphQL argument", true));
        bindings.put("org.springframework.graphql.data.method.annotation.Arguments",
                new Binding("GraphQL arguments", false));
        bindings.put(messaging + "Payload", new Binding("message payload", false));
        bindings.put(messaging + "Header", new Binding("message header", true));
        bindings.put(messaging + "DestinationVariable", new Binding("destination variable", true));
        bindings.put("org.springframework.security.core.annotation.AuthenticationPrincipal",
                new Binding("the caller", false));
        bindings.put("org.springframework.security.core.annotation.CurrentSecurityContext",
                new Binding("the caller", false));
        return bindings;
    }
}
