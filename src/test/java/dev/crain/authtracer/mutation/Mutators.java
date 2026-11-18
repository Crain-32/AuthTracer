package dev.crain.authtracer.mutation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

import com.sun.source.tree.AnnotationTree;
import com.sun.source.tree.AssignmentTree;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.ExpressionStatementTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.LambdaExpressionTree;
import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.NewArrayTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.TreeScanner;
import com.sun.source.util.Trees;
import dev.crain.authtracer.mutation.Mutation.Edit;
import dev.crain.authtracer.mutation.Mutation.Operator;

/**
 * Finds where a fixture's sources can be mutated ({@link Operator}), reading them with javac's tree API: annotations,
 * the request rules of a security DSL chain ({@code .requestMatchers(..).hasRole(..)}), and expression strings.
 */
final class Mutators {

    private static final Set<String> METHOD_CHECKS = Set.of("PreAuthorize", "PostAuthorize", "Secured",
            "RolesAllowed", "DenyAll", "PreFilter", "PostFilter", "AuthorizeReturnObject");
    private static final Set<String> METHOD_SECURITY = Set.of("EnableMethodSecurity", "EnableGlobalMethodSecurity",
            "EnableReactiveMethodSecurity");
    private static final Set<String> ENABLING = Set.of("EnableWebSecurity", "EnableWebFluxSecurity",
            "EnableMethodSecurity", "EnableGlobalMethodSecurity", "EnableReactiveMethodSecurity");
    /**
     * What a request rule starts with.
     */
    private static final Set<String> MATCHERS = Set.of("requestMatchers", "antMatchers", "mvcMatchers",
            "regexMatchers", "pathMatchers", "anyRequest", "anyExchange", "matchers", "dispatcherTypeMatchers");
    /**
     * What says which requests a chain is for.
     */
    private static final Set<String> CHAIN_MATCHERS = Set.of("securityMatcher", "securityMatchers");
    /**
     * What a request rule ends with: its authorization.
     */
    private static final Set<String> TERMINALS = Set.of("permitAll", "denyAll", "authenticated",
            "fullyAuthenticated", "rememberMe", "anonymous", "hasRole", "hasAnyRole", "hasAuthority",
            "hasAnyAuthority", "hasAllRoles", "hasAllAuthorities", "access", "hasIpAddress");
    /**
     * Matchers that take an HTTP method first.
     */
    private static final Set<String> METHOD_MATCHERS = Set.of("requestMatchers", "antMatchers", "mvcMatchers",
            "pathMatchers");
    private static final Set<String> ROLE_CALLS = Set.of("hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority");
    private static final Pattern SPEL = Pattern.compile(
            "\\b(hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|isAuthenticated|isFullyAuthenticated|hasPermission"
                    + "|hasScope)\\(");
    private static final Pattern SPEL_ROLE = Pattern.compile("\\b(hasRole|hasAuthority)\\(\\s*'([^']*)'\\s*\\)");
    private static final Pattern SPEL_AND = Pattern.compile("\\s+and\\s+|\\s*&&\\s*");
    private static final Pattern HIERARCHY = Pattern.compile("[\\w.:-]+\\s*>\\s*[\\w.:-]+");
    private static final Pattern BEAN_CALL = Pattern.compile("@\\w+\\.(\\w+)\\(");
    /**
     * What a custom manager's or permission evaluator's decision is made in.
     */
    private static final Set<String> DECISIONS = Set.of("authorize", "check", "hasPermission");
    /**
     * An {@code @Order} value: a number, or {@code Ordered.HIGHEST_PRECEDENCE}/{@code LOWEST_PRECEDENCE} plus or minus
     * one.
     */
    private static final Pattern ORDER = Pattern.compile(
            "(-?\\d+)|((?:Ordered\\.)?(?:HIGHEST|LOWEST)_PRECEDENCE)(?:([+-])(\\d+))?");
    private static final Set<String> LOOSE = Set.of("isAuthenticated()", "permitAll()", "permitAll", "true");

    private Mutators() {
    }

    /**
     * The mutations of the Java sources under a fixture's package directory, file by file in source order.
     */
    static List<Mutation> of(Path packageDir) throws IOException {
        return of(packageDir, List.of());
    }

    /**
     * With the subjects of the fixture's authtracer.yaml rules (decision 0120): an annotation a rule describes is a
     * method check, and so is a call to a method a rule describes, made outside the class the rule names (whose own
     * calls are the library, which the rule stands for).
     */
    static List<Mutation> of(Path packageDir, Collection<String> rules) throws IOException {
        List<Path> files;
        try (Stream<Path> walk = Files.walk(packageDir)) {
            files = walk.filter(path -> path.toString().endsWith(".java")).sorted().toList();
        }
        if (files.isEmpty()) {
            return List.of();
        }
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        try (StandardJavaFileManager manager = compiler.getStandardFileManager(null, Locale.ROOT,
                StandardCharsets.UTF_8)) {
            JavacTask task = (JavacTask) compiler.getTask(null, manager, diagnostic -> {
            }, List.of("-proc:none"), null, manager.getJavaFileObjectsFromPaths(files));
            List<CompilationUnitTree> units = new ArrayList<>();
            task.parse().forEach(units::add);
            SourcePositions positions = Trees.instance(task).getSourcePositions();
            Set<String> custom = customChecks(units);
            Set<String> described = new HashSet<>();
            for (String rule : rules) {
                String subject = rule.substring(rule.indexOf(' ') + 1);
                described.add((rule.startsWith("annotation ") ? "@" : "")
                        + subject.substring(subject.lastIndexOf('.') + 1));
            }
            Set<String> beanMethods = beanMethods(units);
            List<Mutation> mutations = new ArrayList<>();
            for (CompilationUnitTree unit : units) {
                String file = packageDir.toAbsolutePath().relativize(Path.of(unit.getSourceFile().toUri())).toString();
                String source = unit.getSourceFile().getCharContent(true).toString();
                new Finder(unit, file, source, positions, custom, described, beanMethods, mutations).scan(unit, null);
            }
            return mutations;
        }
    }

    /**
     * Annotations the fixture declares that carry a method check ({@code @IsAdmin} meta-annotated with
     * {@code @PreAuthorize}).
     */
    private static Set<String> customChecks(List<CompilationUnitTree> units) {
        Set<String> names = new HashSet<>();
        for (CompilationUnitTree unit : units) {
            new TreeScanner<Void, Void>() {
                @Override
                public Void visitClass(ClassTree tree, Void unused) {
                    if (tree.getKind() == Tree.Kind.ANNOTATION_TYPE && tree.getModifiers().getAnnotations().stream()
                            .anyMatch(annotation -> METHOD_CHECKS.contains(
                                    simpleName(annotation.getAnnotationType())))) {
                        names.add(tree.getSimpleName().toString());
                    }
                    return super.visitClass(tree, unused);
                }
            }.scan(unit, null);
        }
        return names;
    }

    /**
     * The methods expressions call on beans: {@code canRead} for {@code "@authz.canRead(#id)"}.
     */
    private static Set<String> beanMethods(List<CompilationUnitTree> units) {
        Set<String> names = new HashSet<>();
        for (CompilationUnitTree unit : units) {
            new TreeScanner<Void, Void>() {
                @Override
                public Void visitLiteral(LiteralTree tree, Void unused) {
                    if (tree.getValue() instanceof String value) {
                        Matcher call = BEAN_CALL.matcher(value);
                        while (call.find()) {
                            names.add(call.group(1));
                        }
                    }
                    return null;
                }
            }.scan(unit, null);
        }
        return names;
    }

    static String simpleName(Tree type) {
        return switch (type) {
            case IdentifierTree identifier -> identifier.getName().toString();
            case MemberSelectTree select -> select.getIdentifier().toString();
            default -> type.toString();
        };
    }

    /**
     * A pattern's parent: {@code /a/b/**} and {@code /a/b} become {@code /a/**}, {@code /a/**} becomes
     * {@code /**}.
     */
    static String parent(String pattern) {
        String path = pattern.replaceAll("/\\*\\*?$", "");
        int slash = path.lastIndexOf('/');
        return slash <= 0 ? "/**" : path.substring(0, slash) + "/**";
    }

    static String literal(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> out.append(c);
            }
        }
        return out.append('"').toString();
    }

    private static String shorten(String text) {
        String flat = text.replaceAll("\\s+", " ").strip();
        return flat.length() > 90 ? flat.substring(0, 87) + "..." : flat;
    }

    /**
     * One call of a chain: {@code .name(args)} on {@code receiver}.
     */
    private record Segment(String name, MethodInvocationTree call, ExpressionTree receiver) {
    }

    /**
     * A request rule: the matcher at {@code matcher}, the authorization at {@code terminal}, with {@code not()}
     * between them when {@code not}.
     */
    private record Rule(int matcher, int terminal, boolean not) {
    }

    private static final class Finder extends TreePathScanner<Void, Void> {

        private final CompilationUnitTree unit;
        private final String file;
        private final String source;
        private final SourcePositions positions;
        private final Set<String> custom;
        /**
         * What rules describe: annotations as {@code @RequiresPermission}, calls as {@code Guard#require}.
         */
        private final Set<String> described;
        private final Set<String> beanMethods;
        private final List<Mutation> out;

        Finder(CompilationUnitTree unit, String file, String source, SourcePositions positions, Set<String> custom,
                Set<String> described, Set<String> beanMethods, List<Mutation> out) {
            this.unit = unit;
            this.file = file;
            this.source = source;
            this.positions = positions;
            this.custom = custom;
            this.described = described;
            this.beanMethods = beanMethods;
            this.out = out;
        }

        /**
         * Two security filter chains of the class next to each other in order swap their {@code @Order}: the one that
         * took a request first now comes after another that may take it too.
         */
        @Override
        public Void visitClass(ClassTree tree, Void unused) {
            List<Map.Entry<Long, MethodTree>> chains = new ArrayList<>();
            for (Tree member : tree.getMembers()) {
                if (member instanceof MethodTree method && method.getReturnType() != null
                        && method.getReturnType().toString().endsWith("FilterChain")
                        && annotation(method, "Bean") != null && annotation(method, "Order") != null) {
                    order(annotation(method, "Order")).ifPresent(order -> chains.add(Map.entry(order,
                            method)));
                }
            }
            chains.sort(Map.Entry.comparingByKey());
            for (int i = 0; i + 1 < chains.size(); i++) {
                if (chains.get(i).getKey().equals(chains.get(i + 1).getKey())) {
                    continue;
                }
                MethodTree first = chains.get(i).getValue();
                MethodTree second = chains.get(i + 1).getValue();
                AnnotationTree firstOrder = annotation(first, "Order");
                AnnotationTree secondOrder = annotation(second, "Order");
                add(Operator.REORDER_CHAINS, start(firstOrder), "swap " + text(firstOrder) + " of " + first.getName()
                        + "() with " + text(secondOrder) + " of " + second.getName() + "()",
                        new Edit(start(firstOrder), end(firstOrder), text(secondOrder)),
                        new Edit(start(secondOrder), end(secondOrder), text(firstOrder)));
            }
            return super.visitClass(tree, unused);
        }

        private static AnnotationTree annotation(MethodTree method, String name) {
            return method.getModifiers().getAnnotations().stream()
                    .filter(annotation -> simpleName(annotation.getAnnotationType()).equals(name)).findFirst()
                    .orElse(null);
        }

        /**
         * An {@code @Order}'s value when it is a number or {@code Ordered}'s bounds, give or take a number.
         */
        private Optional<Long> order(AnnotationTree order) {
            ExpressionTree value = value(order);
            if (value == null) {
                return Optional.of((long) Integer.MAX_VALUE);
            }
            Matcher matcher = ORDER.matcher(text(value).replaceAll("\\s+", ""));
            if (!matcher.matches()) {
                return Optional.empty();
            }
            long base = matcher.group(1) != null ? Long.parseLong(matcher.group(1))
                    : matcher.group(2).endsWith("HIGHEST_PRECEDENCE") ? Integer.MIN_VALUE : Integer.MAX_VALUE;
            long offset = matcher.group(4) == null ? 0 : Long.parseLong(matcher.group(4));
            return Optional.of(matcher.group(3) != null && matcher.group(3).equals("-") ? base - offset
                    : base + offset);
        }

        /**
         * A decision in code made to grant everyone: a custom manager's {@code authorize}/{@code check}, a permission
         * evaluator's {@code hasPermission}, or a method an expression calls on a bean, when it returns a decision
         * or a boolean.
         */
        @Override
        public Void visitMethod(MethodTree tree, Void unused) {
            TreePath parent = getCurrentPath().getParentPath();
            String name = tree.getName().toString();
            String returned = tree.getReturnType() == null ? "" : tree.getReturnType().toString();
            boolean decision = parent != null && parent.getLeaf() instanceof ClassTree owner
                    && owner.getImplementsClause().stream().map(Tree::toString)
                            .anyMatch(type -> type.contains("AuthorizationManager")
                                    || type.contains("PermissionEvaluator"))
                    && DECISIONS.contains(name);
            String grant = switch (returned) {
                case "AuthorizationResult", "AuthorizationDecision" ->
                        "return new org.springframework.security.authorization.AuthorizationDecision(true);";
                case "Mono<AuthorizationDecision>", "Mono<AuthorizationResult>" ->
                        "return reactor.core.publisher.Mono.just("
                                + "new org.springframework.security.authorization.AuthorizationDecision(true));";
                case "boolean", "Boolean" -> "return true;";
                default -> null;
            };
            if (tree.getBody() != null && grant != null && (decision || beanMethods.contains(name))) {
                add(Operator.GRANT_IN_CODE, start(tree), name + "(..) grants everyone",
                        new Edit(start(tree.getBody()), end(tree.getBody()), "{ " + grant + " }"));
            }
            return super.visitMethod(tree, unused);
        }

        /**
         * A call a rule describes, dropped: the guard a handler calls.
         */
        @Override
        public Void visitExpressionStatement(ExpressionStatementTree tree, Void unused) {
            if (tree.getExpression() instanceof MethodInvocationTree call) {
                String method = simpleName(call.getMethodSelect());
                String type = type();
                if (described.stream().anyMatch(rule -> rule.endsWith("#" + method)
                        && !rule.equals(type + "#" + method))) {
                    add(Operator.DROP_METHOD_CHECK, start(tree), "drop " + shorten(text(tree)),
                            new Edit(start(tree), end(tree), ""));
                }
            }
            return super.visitExpressionStatement(tree, unused);
        }

        private int start(Tree tree) {
            return (int) positions.getStartPosition(unit, tree);
        }

        private int end(Tree tree) {
            return (int) positions.getEndPosition(unit, tree);
        }

        private String text(Tree tree) {
            return source.substring(start(tree), end(tree));
        }

        private void add(Operator operator, int at, String change, Edit... edits) {
            out.add(new Mutation(operator, file, (int) unit.getLineMap().getLineNumber(at), where() + ": " + change,
                    List.of(edits)));
        }

        /**
         * The class and method the current tree is in, e.g. {@code RolesController.admin()}.
         */
        private String where() {
            String method = null;
            for (TreePath path = getCurrentPath(); path != null; path = path.getParentPath()) {
                if (path.getLeaf() instanceof ClassTree tree && !tree.getSimpleName().isEmpty()) {
                    break;
                }
                if (method == null && path.getLeaf() instanceof MethodTree tree) {
                    method = tree.getName() + "()";
                }
            }
            String type = type();
            return (type == null ? file : type) + (method == null ? "" : "." + method);
        }

        /**
         * The named class the current tree is in.
         */
        private String type() {
            for (TreePath path = getCurrentPath(); path != null; path = path.getParentPath()) {
                if (path.getLeaf() instanceof ClassTree tree && !tree.getSimpleName().isEmpty()) {
                    return tree.getSimpleName().toString();
                }
            }
            return null;
        }

        @Override
        public Void visitAnnotation(AnnotationTree tree, Void unused) {
            String name = simpleName(tree.getAnnotationType());
            String shown = shorten(text(tree));
            if (METHOD_CHECKS.contains(name) || custom.contains(name) || described.contains("@" + name)) {
                add(Operator.DROP_METHOD_CHECK, start(tree), "drop " + shown, new Edit(start(tree), end(tree), ""));
            }
            if (described.contains("@" + name)) {
                widen(tree, shown, "USER", "GUEST");
            }
            switch (name) {
                case "PreAuthorize", "PostAuthorize" -> {
                    if (value(tree) instanceof LiteralTree value && value.getValue() instanceof String expression
                            && !LOOSE.contains(expression.strip())) {
                        add(Operator.LOOSEN_METHOD_CHECK, start(tree), shown + " to isAuthenticated()",
                                new Edit(start(value), end(value), "\"isAuthenticated()\""));
                    }
                }
                case "DenyAll" -> add(Operator.LOOSEN_METHOD_CHECK, start(tree), shown + " to @PermitAll",
                        new Edit(start(tree), end(tree), "@jakarta.annotation.security.PermitAll"));
                case "Secured" -> widen(tree, shown, "ROLE_USER", "ROLE_GUEST");
                case "RolesAllowed" -> widen(tree, shown, "USER", "GUEST");
                case "Configuration" -> {
                    if (securityConfiguration()) {
                        add(Operator.DROP_CONFIGURATION, start(tree), "drop " + shown,
                                new Edit(start(tree), end(tree), ""));
                    }
                }
                default -> {
                    if (METHOD_SECURITY.contains(name)) {
                        disable(tree, name, shown);
                    }
                }
            }
            return super.visitAnnotation(tree, unused);
        }

        /**
         * Whether the class the current annotation is on enables Spring Security or method security, or makes a
         * security filter chain.
         */
        private boolean securityConfiguration() {
            TreePath modifiers = getCurrentPath().getParentPath();
            if (modifiers == null || !(modifiers.getParentPath().getLeaf() instanceof ClassTree cls)) {
                return false;
            }
            boolean enabling = cls.getModifiers().getAnnotations().stream()
                    .anyMatch(annotation -> ENABLING.contains(simpleName(annotation.getAnnotationType())));
            boolean chains = cls.getMembers().stream().filter(MethodTree.class::isInstance).map(MethodTree.class::cast)
                    .anyMatch(method -> method.getReturnType() != null
                            && method.getReturnType().toString().endsWith("FilterChain")
                            && method.getModifiers().getAnnotations().stream()
                                    .anyMatch(annotation -> simpleName(annotation.getAnnotationType()).equals("Bean")));
            return enabling || chains;
        }

        /**
         * The annotation's {@code value}: its one unnamed argument, or the one named {@code value}.
         */
        private static ExpressionTree value(AnnotationTree tree) {
            for (ExpressionTree argument : tree.getArguments()) {
                if (!(argument instanceof AssignmentTree assignment)) {
                    return argument;
                }
                if (assignment.getVariable() instanceof IdentifierTree variable
                        && variable.getName().contentEquals("value")) {
                    return assignment.getExpression();
                }
            }
            return null;
        }

        private void widen(AnnotationTree tree, String shown, String role, String otherwise) {
            ExpressionTree value = value(tree);
            if (value == null) {
                return;
            }
            String extra = text(value).contains("\"" + role + "\"") ? otherwise : role;
            String change = shown + " also lets in " + extra;
            if (value instanceof NewArrayTree array && array.getInitializers() != null
                    && !array.getInitializers().isEmpty()) {
                int at = end(array.getInitializers().getLast());
                add(Operator.WIDEN_ROLES, start(tree), change, new Edit(at, at, ", \"" + extra + "\""));
            } else {
                add(Operator.WIDEN_ROLES, start(tree), change,
                        new Edit(start(value), end(value), "{" + text(value) + ", \"" + extra + "\"}"));
            }
        }

        private void disable(AnnotationTree tree, String name, String shown) {
            add(Operator.DISABLE_METHOD_SECURITY, start(tree), "drop " + shown, new Edit(start(tree), end(tree), ""));
            boolean prePost = false;
            for (ExpressionTree argument : tree.getArguments()) {
                if (argument instanceof AssignmentTree assignment
                        && assignment.getVariable() instanceof IdentifierTree variable) {
                    String attribute = variable.getName().toString();
                    prePost |= attribute.equals("prePostEnabled");
                    if (Set.of("prePostEnabled", "securedEnabled", "jsr250Enabled").contains(attribute)
                            && text(assignment.getExpression()).equals("true")) {
                        add(Operator.DISABLE_METHOD_SECURITY, start(tree), shown + " with " + attribute + " = false",
                                new Edit(start(assignment.getExpression()), end(assignment.getExpression()), "false"));
                    }
                }
            }
            if (name.equals("EnableMethodSecurity") && !prePost) {
                String change = shown + " with prePostEnabled = false";
                if (!tree.getArguments().isEmpty()) {
                    int at = start(tree.getArguments().getFirst());
                    add(Operator.DISABLE_METHOD_SECURITY, start(tree), change,
                            new Edit(at, at, "prePostEnabled = false, "));
                } else if (text(tree).endsWith(")")) {
                    add(Operator.DISABLE_METHOD_SECURITY, start(tree), change,
                            new Edit(end(tree) - 1, end(tree) - 1, "prePostEnabled = false"));
                } else {
                    add(Operator.DISABLE_METHOD_SECURITY, start(tree), change,
                            new Edit(end(tree), end(tree), "(prePostEnabled = false)"));
                }
            }
        }

        @Override
        public Void visitLiteral(LiteralTree tree, Void unused) {
            if (tree.getValue() instanceof String value) {
                if (SPEL.matcher(value).find()) {
                    spel(tree, value);
                }
                if (HIERARCHY.matcher(value).find() && (value.contains("ROLE_") || hierarchyCall())) {
                    String inverted = value.lines().map(line -> {
                        if (!line.contains(">")) {
                            return line;
                        }
                        List<String> roles = new ArrayList<>(List.of(line.split(">")).stream().map(String::strip)
                                .toList());
                        java.util.Collections.reverse(roles);
                        return String.join(" > ", roles);
                    }).reduce((a, b) -> a + "\n" + b).orElse(value) + (value.endsWith("\n") ? "\n" : "");
                    if (!inverted.equals(value)) {
                        add(Operator.INVERT_ROLE_HIERARCHY, start(tree), "invert the role hierarchy "
                                + shorten(value), new Edit(start(tree), end(tree), literal(inverted)));
                    }
                }
            }
            return super.visitLiteral(tree, unused);
        }

        private boolean hierarchyCall() {
            TreePath parent = getCurrentPath().getParentPath();
            return parent != null && parent.getLeaf() instanceof MethodInvocationTree call
                    && Set.of("fromHierarchy", "setHierarchy").contains(name(call));
        }

        /**
         * An expression string: each role or authority it asks for also lets in another one, and its first
         * {@code and} becomes {@code or}.
         */
        private void spel(LiteralTree tree, String value) {
            Matcher role = SPEL_ROLE.matcher(value);
            while (role.find()) {
                boolean roles = role.group(1).equals("hasRole");
                String extra = roles ? (role.group(2).equals("USER") ? "GUEST" : "USER")
                        : (role.group(2).equals("ROLE_USER") ? "ROLE_GUEST" : "ROLE_USER");
                String widened = value.substring(0, role.start()) + (roles ? "hasAnyRole" : "hasAnyAuthority") + "('"
                        + role.group(2) + "', '" + extra + "')" + value.substring(role.end());
                add(Operator.WIDEN_ROLES, start(tree), shorten(literal(value)) + " also lets in " + extra,
                        new Edit(start(tree), end(tree), literal(widened)));
            }
            Matcher and = SPEL_AND.matcher(value);
            if (and.find()) {
                String or = value.substring(0, and.start()) + (and.group().contains("&&") ? " || " : " or ")
                        + value.substring(and.end());
                add(Operator.AND_TO_OR, start(tree), shorten(literal(value)) + " with its first and as or",
                        new Edit(start(tree), end(tree), literal(or)));
            }
        }

        private static String name(MethodInvocationTree call) {
            return switch (call.getMethodSelect()) {
                case MemberSelectTree select -> select.getIdentifier().toString();
                case IdentifierTree identifier -> identifier.getName().toString();
                default -> "";
            };
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree tree, Void unused) {
            String name = name(tree);
            if (ROLE_CALLS.contains(name)) {
                widenCall(tree, name);
            }
            if (name.equals("implies") && tree.getArguments().size() == 1
                    && tree.getMethodSelect() instanceof MemberSelectTree select
                    && select.getExpression() instanceof MethodInvocationTree role && name(role).equals("role")
                    && role.getArguments().size() == 1) {
                ExpressionTree senior = role.getArguments().getFirst();
                ExpressionTree junior = tree.getArguments().getFirst();
                add(Operator.INVERT_ROLE_HIERARCHY, start(role), "invert " + shorten(text(role) + ".implies("
                        + text(junior) + ")"), new Edit(start(senior), end(senior), text(junior)),
                        new Edit(start(junior), end(junior), text(senior)));
            }
            if (outermost()) {
                chain(tree);
            }
            return super.visitMethodInvocation(tree, unused);
        }

        /**
         * {@code hasRole("A")} becomes {@code hasAnyRole("A", "USER")}, {@code hasAuthority("a")}
         * {@code hasAnyAuthority("a", "ROLE_USER")}, and a {@code hasAny...} gets one more.
         */
        private void widenCall(MethodInvocationTree tree, String name) {
            List<? extends ExpressionTree> arguments = tree.getArguments();
            if (arguments.isEmpty() || !arguments.stream().allMatch(argument -> argument instanceof LiteralTree literal
                    && literal.getValue() instanceof String)) {
                return;
            }
            boolean roles = name.contains("Role");
            String extra = roles ? "USER" : "ROLE_USER";
            if (arguments.stream().anyMatch(argument -> text(argument).equals("\"" + (roles ? "USER" : "ROLE_USER")
                    + "\""))) {
                extra = roles ? "GUEST" : "ROLE_GUEST";
            }
            String widened = name.startsWith("hasAny") ? name : roles ? "hasAnyRole" : "hasAnyAuthority";
            int nameEnd = end(tree.getMethodSelect());
            int last = end(arguments.getLast());
            List<Edit> edits = new ArrayList<>();
            if (!widened.equals(name)) {
                edits.add(new Edit(nameEnd - name.length(), nameEnd, widened));
            }
            edits.add(new Edit(last, last, ", \"" + extra + "\""));
            add(Operator.WIDEN_ROLES, start(tree), shorten(name + "(" + arguments.stream().map(this::text)
                    .reduce((a, b) -> a + ", " + b).orElse("") + ")") + " also lets in " + extra,
                    edits.toArray(Edit[]::new));
        }

        /**
         * Whether this call is the last of its chain (not the receiver of another call).
         */
        private boolean outermost() {
            TreePath parent = getCurrentPath().getParentPath();
            if (parent == null || !(parent.getLeaf() instanceof MemberSelectTree select)) {
                return true;
            }
            TreePath grandparent = parent.getParentPath();
            return grandparent == null || !(grandparent.getLeaf() instanceof MethodInvocationTree call)
                    || call.getMethodSelect() != select;
        }

        /**
         * The position of the {@code .} a segment starts with.
         */
        private int dot(Segment segment) {
            int at = end(segment.receiver());
            while (source.charAt(at) != '.') {
                if (source.startsWith("//", at)) {
                    at = source.indexOf('\n', at);
                } else if (source.startsWith("/*", at)) {
                    at = source.indexOf("*/", at) + 2;
                } else {
                    at++;
                }
            }
            return at;
        }

        private void chain(MethodInvocationTree outer) {
            List<Segment> segments = new ArrayList<>();
            ExpressionTree expression = outer;
            while (expression instanceof MethodInvocationTree call
                    && call.getMethodSelect() instanceof MemberSelectTree select) {
                segments.addFirst(new Segment(select.getIdentifier().toString(), call, select.getExpression()));
                expression = select.getExpression();
            }
            List<Rule> rules = new ArrayList<>();
            boolean ignoring = false;
            for (int i = 0; i < segments.size(); i++) {
                Segment segment = segments.get(i);
                ignoring |= segment.name().equals("ignoring");
                if (MATCHERS.contains(segment.name())) {
                    int j = i + 1;
                    boolean not = j < segments.size() && segments.get(j).name().equals("not");
                    if (not) {
                        j++;
                    }
                    if (j < segments.size() && TERMINALS.contains(segments.get(j).name())) {
                        rules.add(new Rule(i, j, not));
                        i = j;
                        continue;
                    }
                    scope(segment, ignoring);
                } else if (CHAIN_MATCHERS.contains(segment.name())) {
                    scope(segment, false);
                }
            }
            for (int k = 0; k < rules.size(); k++) {
                rule(segments, rules, k);
            }
        }

        /**
         * A matcher with no authorization after it: a chain's scope (narrowed), or what {@code ignoring()} leaves out
         * (widened).
         */
        private void scope(Segment segment, boolean ignoring) {
            for (LiteralTree pattern : patterns(segment)) {
                String value = (String) pattern.getValue();
                if (ignoring) {
                    String parent = parent(value);
                    if (!parent.equals(value)) {
                        add(Operator.WIDEN_MATCHER, start(pattern), "ignoring() " + literal(value) + " widened to "
                                + literal(parent), new Edit(start(pattern), end(pattern), literal(parent)));
                    }
                } else if (value.endsWith("/**") && value.length() > 3) {
                    String narrowed = value.substring(0, value.length() - 3);
                    add(Operator.NARROW_MATCHER, start(pattern), "." + segment.name() + "(" + literal(value)
                            + ") narrowed to " + literal(narrowed), new Edit(start(pattern), end(pattern),
                            literal(narrowed)));
                }
            }
        }

        /**
         * The path patterns a matcher's arguments hold, not looking into lambdas (another chain's).
         */
        private List<LiteralTree> patterns(Segment segment) {
            List<LiteralTree> patterns = new ArrayList<>();
            TreeScanner<Void, Void> scanner = new TreeScanner<>() {
                @Override
                public Void visitLiteral(LiteralTree tree, Void unused) {
                    if (tree.getValue() instanceof String value && value.startsWith("/")) {
                        patterns.add(tree);
                    }
                    return null;
                }

                @Override
                public Void visitLambdaExpression(LambdaExpressionTree tree, Void unused) {
                    return null;
                }
            };
            segment.call().getArguments().forEach(argument -> scanner.scan(argument, null));
            return patterns;
        }

        private void rule(List<Segment> segments, List<Rule> rules, int k) {
            Rule rule = rules.get(k);
            Segment matcher = segments.get(rule.matcher());
            Segment terminal = segments.get(rule.terminal());
            boolean permit = terminal.name().equals("permitAll") && !rule.not();
            boolean any = matcher.name().equals("anyRequest") || matcher.name().equals("anyExchange");
            int ruleStart = dot(matcher);
            int ruleEnd = end(terminal.call());
            int authorizationStart = dot(segments.get(rule.matcher() + 1));
            String shown = shorten(source.substring(ruleStart, ruleEnd));
            if (!permit) {
                add(Operator.LOOSEN_RULE, ruleStart, shown + " to permitAll()",
                        new Edit(authorizationStart, ruleEnd, ".permitAll()"));
                if (!terminal.name().equals("authenticated") || rule.not()) {
                    add(Operator.RULE_TO_AUTHENTICATED, ruleStart, shown + " to authenticated()",
                            new Edit(authorizationStart, ruleEnd, ".authenticated()"));
                }
                // access((authentication, context) -> ...): the lambda decides, and now grants everyone.
                if (terminal.name().equals("access") && terminal.call().getArguments().size() == 1
                        && terminal.call().getArguments().getFirst() instanceof LambdaExpressionTree lambda) {
                    boolean reactive = segments.stream().anyMatch(segment -> segment.name().equals("pathMatchers")
                            || segment.name().equals("anyExchange"));
                    String granted = "new org.springframework.security.authorization.AuthorizationDecision(true)";
                    String value = reactive ? "reactor.core.publisher.Mono.just(" + granted + ")" : granted;
                    add(Operator.GRANT_IN_CODE, ruleStart, shown + ": its lambda grants everyone",
                            new Edit(start(lambda.getBody()), end(lambda.getBody()),
                                    lambda.getBodyKind() == LambdaExpressionTree.BodyKind.STATEMENT
                                            ? "{ return " + value + "; }" : value));
                }
            }
            if (rules.size() > 1) {
                add(Operator.DROP_RULE, ruleStart, "drop " + shown, new Edit(ruleStart, ruleEnd, ""));
            }
            if (k + 1 < rules.size()) {
                Rule next = rules.get(k + 1);
                Segment nextMatcher = segments.get(next.matcher());
                boolean nextAny = nextMatcher.name().equals("anyRequest") || nextMatcher.name().equals("anyExchange");
                int nextStart = dot(nextMatcher);
                int nextEnd = end(segments.get(next.terminal()).call());
                int nextAuthorization = dot(segments.get(next.matcher() + 1));
                boolean sameAuthorization = source.substring(authorizationStart, ruleEnd).strip()
                        .equals(source.substring(nextAuthorization, nextEnd).strip());
                if (!any && !nextAny && next.matcher() == rule.terminal() + 1 && !sameAuthorization) {
                    add(Operator.REORDER_RULES, ruleStart, "swap " + shown + " with "
                            + shorten(source.substring(nextStart, nextEnd)),
                            new Edit(ruleStart, ruleEnd, source.substring(nextStart, nextEnd)),
                            new Edit(nextStart, nextEnd, source.substring(ruleStart, ruleEnd)));
                }
            }
            int first = dot(segments.get(rules.getFirst().matcher()));
            if (!permit && !any && !matcher.call().getArguments().isEmpty()) {
                String arguments = source.substring(start(matcher.call().getArguments().getFirst()),
                        end(matcher.call().getArguments().getLast()));
                String inserted = "." + matcher.name() + "(" + arguments + ").permitAll()";
                add(Operator.EARLY_PERMIT_ALL, first, inserted + " before every rule, for " + shown,
                        new Edit(first, first, inserted));
            }
            if (k == 0) {
                boolean reactive = segments.stream().anyMatch(segment -> segment.name().equals("pathMatchers")
                        || segment.name().equals("anyExchange"));
                String inserted = (reactive ? ".pathMatchers" : ".requestMatchers") + "(\"/**\").permitAll()";
                add(Operator.EARLY_PERMIT_ALL, first, inserted + " before every rule", new Edit(first, first,
                        inserted));
            }
            if (any) {
                return;
            }
            for (LiteralTree pattern : patterns(matcher)) {
                String value = (String) pattern.getValue();
                if (permit) {
                    String parent = parent(value);
                    if (!parent.equals(value)) {
                        add(Operator.WIDEN_MATCHER, start(pattern), shown + " widened to " + literal(parent),
                                new Edit(start(pattern), end(pattern), literal(parent)));
                    }
                } else if (value.endsWith("/**") && value.length() > 3) {
                    String narrowed = value.substring(0, value.length() - 3);
                    add(Operator.NARROW_MATCHER, start(pattern), shown + " narrowed to " + literal(narrowed),
                            new Edit(start(pattern), end(pattern), literal(narrowed)));
                }
            }
            List<? extends ExpressionTree> arguments = matcher.call().getArguments();
            if (!permit && METHOD_MATCHERS.contains(matcher.name()) && !arguments.isEmpty()
                    && arguments.getFirst() instanceof LiteralTree literal && literal.getValue() instanceof String) {
                int at = start(arguments.getFirst());
                add(Operator.NARROW_MATCHER, ruleStart, shown + " for GET only",
                        new Edit(at, at, "org.springframework.http.HttpMethod.GET, "));
            }
        }
    }
}
