package dev.crain.authtracer.scan.spring;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.ConfigurationProperties;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.constant.ClassConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.ClassType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0111: whether Spring makes a bean of an application class or {@code @Bean} method, as far as the code and
 * its configuration tell. A {@code @Profile}, a {@code @Conditional} (Boot's {@code @ConditionalOn...} carry it) or a
 * component outside every {@code @ComponentScan} root makes it depend on what AuthTracer reads (the profiles and
 * properties the configuration sets, the classpath, the web stack) or on what it can't (the profiles a deployment
 * activates, other beans, an expression). What the code and configuration satisfy is a bean; what they don't, or what
 * only the deployment decides, may be one: the graph keeps it in its weaker reading (a chain that may take a request,
 * an endpoint that may exist, method security that may not be on), with an OPAQUE_CONFIG finding naming the
 * condition.
 */
@Supports({Feature.APPLICATION_GRAPH, Feature.FINDING_OPAQUE_CONFIG})
final class BeanConditions {

    private static final Logger log = LoggerFactory.getLogger(BeanConditions.class);

    private static final String CONDITIONAL = "org.springframework.context.annotation.Conditional";
    private static final String PROFILE = "org.springframework.context.annotation.Profile";
    private static final String CONDITION = "org.springframework.boot.autoconfigure.condition.";
    private static final String ON_PROPERTY = CONDITION + "ConditionalOnProperty";
    private static final String ON_PROPERTIES = CONDITION + "ConditionalOnProperties";
    private static final String ON_BOOLEAN_PROPERTY = CONDITION + "ConditionalOnBooleanProperty";
    private static final String ON_BOOLEAN_PROPERTIES = CONDITION + "ConditionalOnBooleanProperties";
    private static final String ON_CLASS = CONDITION + "ConditionalOnClass";
    private static final String ON_MISSING_CLASS = CONDITION + "ConditionalOnMissingClass";
    private static final String ON_WEB_APPLICATION = CONDITION + "ConditionalOnWebApplication";
    private static final String ON_NOT_WEB_APPLICATION = CONDITION + "ConditionalOnNotWebApplication";
    private static final String SPRING_BOOT_APPLICATION = "org.springframework.boot.autoconfigure.SpringBootApplication";
    private static final String COMPONENT_SCAN = "org.springframework.context.annotation.ComponentScan";
    private static final String COMPONENT_SCANS = "org.springframework.context.annotation.ComponentScans";
    private static final String IMPORT = "org.springframework.context.annotation.Import";
    /**
     * The beans whose condition changes what the graph says about requests and checks.
     */
    private static final Set<String> SECURITY_TYPES = Set.of(WebStack.SECURITY_FILTER_CHAIN,
            WebStack.SECURITY_WEB_FILTER_CHAIN,
            "org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer",
            "org.springframework.security.config.Customizer",
            "org.springframework.security.access.hierarchicalroles.RoleHierarchy",
            "org.springframework.security.access.PermissionEvaluator",
            "org.springframework.security.authorization.AuthorizationManagerFactory",
            "org.springframework.security.authorization.AuthorizationManager",
            "org.springframework.security.access.expression.method.MethodSecurityExpressionHandler",
            "org.springframework.security.config.core.GrantedAuthorityDefaults",
            "jakarta.servlet.Filter", "org.springframework.web.server.WebFilter",
            "org.springframework.web.servlet.HandlerInterceptor", "org.springframework.aop.Advisor",
            "org.springframework.web.servlet.function.RouterFunction",
            "org.springframework.web.reactive.function.server.RouterFunction");
    private static final Set<String> CHAINS = Set.of(WebStack.SECURITY_FILTER_CHAIN,
            WebStack.SECURITY_WEB_FILTER_CHAIN);
    private static final String CUSTOMIZER = "org.springframework.security.config.Customizer";
    private static final String MANAGER_FACTORY = "org.springframework.security.authorization.AuthorizationManagerFactory";
    private static final Set<String> HANDED_TO = Set.of("org.springframework.boot.SpringApplication",
            "org.springframework.boot.builder.SpringApplicationBuilder",
            "org.springframework.context.annotation.AnnotationConfigApplicationContext",
            "org.springframework.web.context.support.AnnotationConfigWebApplicationContext");
    private static final List<String> ENABLING = List.of(WebStack.ENABLE_WEB_SECURITY,
            WebStack.ENABLE_WEBFLUX_SECURITY, SpringNames.ENABLE_METHOD_SECURITY,
            SpringNames.ENABLE_GLOBAL_METHOD_SECURITY, SpringNames.ENABLE_REACTIVE_METHOD_SECURITY);

    private final ScanContext context;
    private final ConfigurationProperties properties;
    private final List<String> profiles;
    private final boolean profilesSet;
    private final boolean reactive;
    /**
     * The packages the application's component scans start from; empty when they can't be told.
     */
    private final Optional<List<String>> roots;
    /**
     * Classes a configuration imports, an auto-configuration file names or the XML defines: beans wherever they are.
     */
    private final Set<String> registered = new LinkedHashSet<>();

    private BeanConditions(ScanContext context, Set<String> xmlBeans) {
        this.context = context;
        this.properties = context.properties();
        List<String> active = new ArrayList<>(properties.list("spring.profiles.active"));
        active.addAll(properties.list("spring.profiles.include"));
        this.profilesSet = !active.isEmpty();
        this.profiles = profilesSet ? expand(active) : Optional.of(properties.list("spring.profiles.default"))
                .filter(list -> !list.isEmpty()).orElse(List.of("default"));
        this.reactive = WebStack.reactive(context);
        registered.addAll(xmlBeans);
        this.roots = roots();
    }

    /**
     * The scan's conditions, read once; {@code xmlBeans} are the classes the application's XML defines beans of.
     */
    static BeanConditions of(ScanContext context, Set<String> xmlBeans) {
        return context.shared(BeanConditions.class, () -> new BeanConditions(context, xmlBeans));
    }

    static BeanConditions of(ScanContext context) {
        return of(context, Set.of());
    }

    /**
     * Why the class may not be a bean, or empty when the code and configuration make it one.
     */
    Optional<String> maybe(JavaSootClass cls) {
        List<String> why = new ArrayList<>(conditions(cls));
        outsideScan(cls).ifPresent(why::add);
        unregistered(cls).ifPresent(why::add);
        return why.isEmpty() ? Optional.empty() : Optional.of(String.join("; ", why));
    }

    /**
     * Why a {@code @Bean} method may not make its bean: its own conditions, then its class's.
     */
    Optional<String> maybe(JavaSootMethod beanMethod) {
        List<String> why = new ArrayList<>(conditions(beanMethod));
        context.findClass(beanMethod.getDeclaringClassType()).flatMap(this::maybe).ifPresent(why::add);
        return why.isEmpty() ? Optional.empty() : Optional.of(String.join("; ", why));
    }

    /**
     * The profiles the configuration runs with when the deployment adds none.
     */
    String profilesNote() {
        return profilesSet ? "the configuration activates " + profiles : "the configuration activates no profile, so"
                + " only " + profiles + " is active unless the deployment sets one";
    }

    /**
     * One OPAQUE_CONFIG finding per class or bean method that carries a condition AuthTracer leaves open and that
     * changes what the graph says: a chain, a customizer or other security bean, what enables Spring Security or
     * method security, a controller.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    void report(GraphBuilder graph) {
        for (JavaSootClass cls : context.applicationClasses()) {
            if (cls.isAnnotation()) {
                continue;
            }
            Optional<String> classWhy = maybe(cls);
            List<String> relevantBeans = new ArrayList<>();
            for (JavaSootMethod method : cls.getMethods()) {
                if (!context.hasAnnotation(method, SpringNames.BEAN) || !relevant(method)) {
                    continue;
                }
                List<String> own = conditions(method);
                if (!own.isEmpty()) {
                    graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The bean " + MethodNames.key(method
                            .getSignature()) + " is only made when " + String.join("; ", own) + ", which AuthTracer"
                            + " can't decide" + note(own.toString()) + ": " + consequence(method),
                            MethodNames.codeRef(method.getSignature())));
                }
                else if (classWhy.isPresent()) {
                    relevantBeans.add(method.getName() + " (" + consequence(method) + ")");
                }
            }
            if (classWhy.isEmpty()) {
                continue;
            }
            List<String> what = new ArrayList<>();
            ENABLING.stream().filter(name -> context.hasAnnotation(cls, name))
                    .forEach(name -> what.add("its @" + name.substring(name.lastIndexOf('.') + 1)
                            + (name.contains("Method") ? " may not be on: where nothing else enables method security,"
                                    + " its annotations show as not enforced" : " may not be on")));
            if (context.hasAnnotation(cls, SpringNames.CONTROLLER)) {
                what.add("its endpoints are shown, though they may not exist");
            }
            relevantBeans.forEach(bean -> what.add("its bean " + bean));
            if (!what.isEmpty()) {
                graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, cls.getName() + " is only a bean when "
                        + classWhy.get() + ", which AuthTracer can't decide" + note(classWhy.get()) + ": "
                        + String.join("; ", what), CodeRef.ofClass(cls.getName())));
            }
        }
    }

    private String note(String why) {
        return why.contains("profile ") ? " (" + profilesNote() + ")" : "";
    }

    private boolean relevant(JavaSootMethod method) {
        return method.getReturnType() instanceof ClassType type && SpringBeans.assignable(context, type,
                SECURITY_TYPES);
    }

    private String consequence(JavaSootMethod method) {
        if (method.getReturnType() instanceof ClassType type && SpringBeans.assignable(context, type, CHAINS)) {
            return "the requests it would take get its rules or the chains after it, whichever asks less";
        }
        if (method.getReturnType() instanceof ClassType type && SpringBeans.assignable(context, type,
                Set.of(MANAGER_FACTORY))) {
            return "the rules it builds are shown without the factors it adds";
        }
        if (method.getReturnType() instanceof ClassType type && SpringBeans.assignable(context, type,
                Set.of(CUSTOMIZER))) {
            return "the requests its rules match get them or the rules after them, whichever asks less";
        }
        return "the graph shows it as made";
    }

    /**
     * The conditions on an element AuthTracer leaves open, each described.
     */
    private List<String> conditions(sootup.java.core.HasAnnotation element) {
        List<String> open = new ArrayList<>();
        for (AnnotationUsage annotation : element.getAnnotations()) {
            String name = Annotations.name(annotation);
            boolean conditional = name.equals(CONDITIONAL) || name.equals(ON_PROPERTIES)
                    || name.equals(ON_BOOLEAN_PROPERTIES) || context.metaAnnotations(name).stream()
                            .anyMatch(meta -> Annotations.name(meta).equals(CONDITIONAL));
            if (conditional) {
                open(annotation).ifPresent(open::add);
            }
        }
        return open;
    }

    /**
     * Why the condition may not hold, or empty when the code and configuration satisfy it.
     */
    private Optional<String> open(AnnotationUsage annotation) {
        String name = Annotations.name(annotation);
        String shortName = "@" + name.substring(name.lastIndexOf('.') + 1);
        return switch (name) {
            case PROFILE -> {
                List<String> expressions = Annotations.strings(annotation, "value");
                boolean holds = expressions.stream().anyMatch(expression -> new ProfileExpression(expression)
                        .matches(profiles));
                yield holds ? Optional.empty() : Optional.of("profile " + String.join(" or ", expressions)
                        + " is active");
            }
            case ON_PROPERTY -> property(annotation, false);
            case ON_BOOLEAN_PROPERTY -> property(annotation, true);
            case ON_PROPERTIES, ON_BOOLEAN_PROPERTIES -> {
                List<String> open = Annotations.nested(annotation, "value").stream().map(this::open)
                        .flatMap(Optional::stream).toList();
                yield open.isEmpty() ? Optional.empty() : Optional.of(String.join(" and ", open));
            }
            case ON_CLASS -> {
                List<String> missing = classes(annotation).stream().filter(type -> context.findClass(type).isEmpty())
                        .toList();
                yield missing.isEmpty() ? Optional.empty() : Optional.of(String.join(", ", missing)
                        + " is on the classpath (it isn't on the one AuthTracer read)");
            }
            case ON_MISSING_CLASS -> {
                List<String> present = classes(annotation).stream()
                        .filter(type -> context.findClass(type).isPresent()).toList();
                yield present.isEmpty() ? Optional.empty() : Optional.of(String.join(", ", present)
                        + " is not on the classpath (it is on the one AuthTracer read)");
            }
            case ON_WEB_APPLICATION -> {
                String type = Annotations.string(annotation, "type").orElse("ANY");
                boolean holds = type.equals("ANY") || type.equals(reactive ? "REACTIVE" : "SERVLET");
                yield holds ? Optional.empty() : Optional.of("the application is a " + type.toLowerCase(Locale.ROOT)
                        + " web application (AuthTracer reads it as a " + (reactive ? "reactive" : "servlet")
                        + " one)");
            }
            case ON_NOT_WEB_APPLICATION -> Optional.of("the application is not a web application");
            default -> Optional.of(shortName + describeValues(annotation) + " holds");
        };
    }

    /**
     * Boot 4.1.1 {@code OnPropertyCondition}: each name under the prefix is set and isn't {@code false} (or equals
     * {@code havingValue}, ignoring case); a name the configuration doesn't set matches when {@code matchIfMissing}.
     * {@code @ConditionalOnBooleanProperty} compares with its boolean {@code havingValue} (default {@code true}).
     */
    private Optional<String> property(AnnotationUsage annotation, boolean bool) {
        String prefix = Annotations.string(annotation, "prefix").map(String::trim).orElse("");
        if (!prefix.isEmpty() && !prefix.endsWith(".")) {
            prefix += ".";
        }
        List<String> names = new ArrayList<>(Annotations.strings(annotation, "name"));
        names.addAll(Annotations.strings(annotation, "value"));
        String having = bool ? String.valueOf(Annotations.bool(annotation, "havingValue").orElse(true))
                : Annotations.string(annotation, "havingValue").orElse("");
        boolean ifMissing = Annotations.bool(annotation, "matchIfMissing").orElse(false);
        List<String> open = new ArrayList<>();
        for (String name : names) {
            String key = prefix + name;
            Optional<String> value = properties.get(key);
            boolean holds = value.map(set -> having.isEmpty() ? !set.equalsIgnoreCase("false")
                    : set.equalsIgnoreCase(having)).orElse(ifMissing);
            if (!holds) {
                open.add(key + (having.isEmpty() ? " is set and not false" : " is " + having) + " (the configuration"
                        + value.map(set -> " sets " + set).orElse(" doesn't set it") + ")");
            }
        }
        return open.isEmpty() ? Optional.empty() : Optional.of(String.join(" and ", open));
    }

    private static List<String> classes(AnnotationUsage annotation) {
        List<String> types = new ArrayList<>(Annotations.strings(annotation, "value"));
        types.addAll(Annotations.strings(annotation, "name"));
        return types;
    }

    private static String describeValues(AnnotationUsage annotation) {
        List<String> values = annotation.getValues().keySet().stream().sorted()
                .map(key -> key + "=" + String.join(",", Annotations.strings(annotation, key))).toList();
        return values.isEmpty() ? "" : "(" + String.join(", ", values) + ")";
    }

    /**
     * Profile groups ({@code spring.profiles.group.<name>}) add their members after the profile.
     */
    private List<String> expand(List<String> active) {
        List<String> expanded = new ArrayList<>();
        List<String> pending = new ArrayList<>(active);
        while (!pending.isEmpty()) {
            String profile = pending.removeFirst().trim();
            if (!profile.isEmpty() && !expanded.contains(profile)) {
                expanded.add(profile);
                pending.addAll(properties.list("spring.profiles.group." + profile));
            }
        }
        return List.copyOf(expanded);
    }

    /**
     * A component outside every package the application's component scans start from, which nothing imports.
     */
    private Optional<String> outsideScan(JavaSootClass cls) {
        if (roots.isEmpty() || !context.hasAnnotation(cls, SpringNames.COMPONENT) || registered.contains(cls.getName())
                || roots.get().stream().anyMatch(root -> root.isEmpty() || cls.getName().startsWith(root + "."))) {
            return Optional.empty();
        }
        return Optional.of("something registers it: it is outside the component scan (packages " + roots.get()
                + ") and nothing AuthTracer reads imports it");
    }

    /**
     * A class that is no component (no {@code @Configuration} or other stereotype) and that nothing AuthTracer reads
     * registers: Spring makes no bean of it, so its {@code @Bean} methods and {@code @Enable} annotations do nothing.
     * Spring Security 5's {@code @Enable} annotations carried {@code @Configuration}; 6's don't, so a class upgraded
     * as it was is one of these.
     */
    private Optional<String> unregistered(JavaSootClass cls) {
        if (cls.isInterface() || cls.isAnnotation() || registers(cls)
                || context.subtypesOf(cls.getType()).stream().map(context::findClass).flatMap(Optional::stream)
                        .anyMatch(this::registers)) {
            // A subclass that is a bean has the class's bean methods and annotations too.
            return Optional.empty();
        }
        return Optional.of("something registers it: it has no @Configuration (Spring Security 6's @Enable"
                + " annotations don't carry one) and nothing AuthTracer reads registers it");
    }

    private boolean registers(JavaSootClass cls) {
        return context.hasAnnotation(cls, SpringNames.COMPONENT) || registered.contains(cls.getName());
    }

    /**
     * The classes the application hands to Spring itself: {@code SpringApplication.run(..)}, {@code new
     * SpringApplication(..)}, a {@code SpringApplicationBuilder}'s {@code sources(..)}, a context's {@code register(..)}
     * or {@code registerBean(..)}.
     */
    private Set<String> handed() {
        Set<String> handed = new LinkedHashSet<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                    if (invoke.isEmpty() || !handsTo(invoke.get())) {
                        continue;
                    }
                    invoke.get().getArgs().stream().flatMap(arg -> arg instanceof Local array
                            ? Locals.elements(method.getBody(), array).stream() : Stream.of(arg))
                            .filter(ClassConstant.class::isInstance)
                            .map(constant -> className((ClassConstant) constant)).forEach(handed::add);
                }
            }
        }
        return handed;
    }

    private static boolean handsTo(AbstractInvokeExpr invoke) {
        String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = invoke.getMethodSignature().getName();
        return HANDED_TO.contains(owner) || (name.equals("register") || name.equals("registerBean"))
                && (owner.startsWith("org.springframework.context.") || owner.startsWith("org.springframework.web.")
                        || owner.startsWith("org.springframework.boot."));
    }

    private static String className(ClassConstant constant) {
        String descriptor = constant.getValue();
        if (descriptor.startsWith("L") && descriptor.endsWith(";")) {
            descriptor = descriptor.substring(1, descriptor.length() - 1);
        }
        return descriptor.replace('/', '.');
    }

    /**
     * The roots of the {@code @SpringBootApplication} and {@code @ComponentScan} classes; empty when there are none,
     * when one is declared through an annotation of the application's own, or when XML scans components too.
     */
    private Optional<List<String>> roots() {
        List<String> found = new ArrayList<>();
        boolean unknown = false;
        for (JavaSootClass cls : context.applicationClasses()) {
            if (cls.isAnnotation()) {
                continue;
            }
            for (AnnotationUsage annotation : cls.getAnnotations()) {
                String name = Annotations.name(annotation);
                switch (name) {
                    case SPRING_BOOT_APPLICATION -> found.addAll(packages(cls, annotation, "scanBasePackages",
                            "scanBasePackageClasses"));
                    case COMPONENT_SCAN -> found.addAll(componentScan(cls, annotation));
                    case COMPONENT_SCANS -> Annotations.nested(annotation, "value")
                            .forEach(scan -> found.addAll(componentScan(cls, scan)));
                    case IMPORT -> registered.addAll(Annotations.strings(annotation, "value"));
                    default -> unknown |= context.metaAnnotations(name).stream().map(Annotations::name)
                            .anyMatch(meta -> meta.equals(COMPONENT_SCAN) || meta.equals(SPRING_BOOT_APPLICATION));
                }
            }
        }
        registered.addAll(autoConfigurations());
        registered.addAll(handed());
        // ComponentScanAnnotationParser splits each on ",; \t\n" and resolves placeholders.
        List<String> packages = found.stream().flatMap(entry -> Stream.of(entry.split("[,;\\s]+")))
                .map(String::trim).filter(entry -> !entry.isEmpty()).distinct().toList();
        if (packages.isEmpty() || unknown || xmlScans() || packages.stream().anyMatch(entry -> entry.contains("${")
                || entry.contains("*"))) {
            return Optional.empty();
        }
        return Optional.of(packages);
    }

    private static List<String> componentScan(JavaSootClass cls, AnnotationUsage annotation) {
        List<String> packages = new ArrayList<>(Annotations.strings(annotation, "value"));
        packages.addAll(Annotations.strings(annotation, "basePackages"));
        Annotations.strings(annotation, "basePackageClasses").forEach(type -> packages.add(packageOf(type)));
        return packages.isEmpty() ? List.of(packageOf(cls.getName())) : packages;
    }

    /**
     * The packages named, and those of the classes named; the annotated class's own when it names none.
     */
    private static List<String> packages(JavaSootClass cls, AnnotationUsage annotation, String packagesElement,
            String classesElement) {
        List<String> packages = new ArrayList<>(Annotations.strings(annotation, packagesElement));
        Annotations.strings(annotation, classesElement).forEach(type -> packages.add(packageOf(type)));
        return packages.isEmpty() ? List.of(packageOf(cls.getName())) : packages;
    }

    private static String packageOf(String className) {
        int dot = className.lastIndexOf('.');
        return dot < 0 ? "" : className.substring(0, dot);
    }

    /**
     * Classes the resources' {@code META-INF/spring.factories} and {@code META-INF/spring/*.imports} name.
     */
    private List<String> autoConfigurations() {
        List<String> names = new ArrayList<>();
        for (Path dir : context.input().resourceDirs()) {
            Path factories = dir.resolve("META-INF/spring.factories");
            Path imports = dir.resolve("META-INF/spring");
            try {
                if (Files.isRegularFile(factories)) {
                    for (String line : Files.readAllLines(factories)) {
                        String values = line.contains("=") ? line.substring(line.indexOf('=') + 1) : line;
                        Stream.of(values.replace("\\", "").split(",")).map(String::trim)
                                .filter(name -> !name.isEmpty() && !name.startsWith("#")).forEach(names::add);
                    }
                }
                if (Files.isDirectory(imports)) {
                    try (Stream<Path> files = Files.list(imports)) {
                        for (Path file : files.filter(path -> path.toString().endsWith(".imports")).toList()) {
                            Files.readAllLines(file).stream().map(String::trim)
                                    .filter(name -> !name.isEmpty() && !name.startsWith("#")).forEach(names::add);
                        }
                    }
                }
            }
            catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return names;
    }

    /**
     * Whether a Spring XML file under the resources scans components itself.
     */
    private boolean xmlScans() {
        for (Path dir : context.input().resourceDirs()) {
            if (!Files.isDirectory(dir)) {
                continue;
            }
            try (Stream<Path> files = Files.walk(dir, 6)) {
                for (Path file : files.filter(path -> path.toString().endsWith(".xml")).toList()) {
                    if (Files.readString(file).contains("component-scan")) {
                        log.info("Scanning {}: {} scans components, so every component counts as a bean",
                                context.input().service(), file);
                        return true;
                    }
                }
            }
            catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return false;
    }

    /**
     * Spring's {@code ProfilesParser}: names joined with {@code &} or {@code |} (not both without parentheses),
     * negated with {@code !}, grouped with parentheses.
     */
    static final class ProfileExpression {

        private final List<String> tokens = new ArrayList<>();
        private int next;

        ProfileExpression(String expression) {
            StringBuilder name = new StringBuilder();
            for (char c : expression.toCharArray()) {
                if ("()&|!".indexOf(c) >= 0 || Character.isWhitespace(c)) {
                    if (!name.isEmpty()) {
                        tokens.add(name.toString());
                        name.setLength(0);
                    }
                    if (!Character.isWhitespace(c)) {
                        tokens.add(String.valueOf(c));
                    }
                }
                else {
                    name.append(c);
                }
            }
            if (!name.isEmpty()) {
                tokens.add(name.toString());
            }
        }

        boolean matches(List<String> active) {
            next = 0;
            return !tokens.isEmpty() && expression(active);
        }

        private boolean expression(List<String> active) {
            boolean value = term(active);
            while (next < tokens.size() && (tokens.get(next).equals("&") || tokens.get(next).equals("|"))) {
                boolean and = tokens.get(next++).equals("&");
                boolean right = term(active);
                value = and ? value && right : value || right;
            }
            return value;
        }

        private boolean term(List<String> active) {
            if (next >= tokens.size()) {
                return false;
            }
            String token = tokens.get(next++);
            if (token.equals("!")) {
                return !term(active);
            }
            if (token.equals("(")) {
                boolean value = expression(active);
                if (next < tokens.size() && tokens.get(next).equals(")")) {
                    next++;
                }
                return value;
            }
            return active.contains(token);
        }
    }
}
