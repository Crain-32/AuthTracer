package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JNewArrayExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0053: servlets the application registers, which the filter chain checks like any request: a
 * {@code @WebServlet} class (with {@code @ServletComponentScan}) or a {@code ServletRegistrationBean} bean's servlet,
 * at its URL patterns ({@code /legacy/*} is {@code /legacy/**}), one Ingress per {@code doGet}/{@code doPost}/...
 * it overrides ({@code service(..)}: any method). And Spring Boot's H2 console, with
 * {@code spring.h2.console.enabled}: {@code GET}/{@code POST} under {@code spring.h2.console.path}.
 * <p>
 * Decision 0080: a registration an application helper builds is read through it (one level); the URL patterns that
 * are constants are kept when others aren't; a library servlet registered at a path is an Ingress there, checked by
 * the request rules alone; what can't be read is an OPAQUE_CONFIG finding.
 * <p>
 * A {@code @WebServlet} is registered by Boot's embedded server with {@code @ServletComponentScan}, or by the servlet
 * container a war is deployed to ({@link #discovery}).
 */
@Supports(Feature.HTTP_ENDPOINTS)
final class ServletEndpoints {

    private static final String HTTP_SERVLET = "jakarta.servlet.http.HttpServlet";
    private static final String WEB_SERVLET = "jakarta.servlet.annotation.WebServlet";
    /**
     * Spring Boot 4's, and 3's.
     */
    private static final List<String> COMPONENT_SCAN = List.of(
            "org.springframework.boot.web.server.servlet.context.ServletComponentScan",
            "org.springframework.boot.web.servlet.ServletComponentScan");
    static final String REGISTRATION = "org.springframework.boot.web.servlet.ServletRegistrationBean";
    private static final String BOOT_WAR = "org.springframework.boot.web.servlet.support.SpringBootServletInitializer";
    private static final String WEB_APPLICATION_INITIALIZER = "org.springframework.web.WebApplicationInitializer";

    /**
     * Whether the application's {@code @WebServlet} and {@code @WebFilter} classes are registered: surely, maybe (a
     * Boot war, deployed or run as a jar), or not.
     */
    enum Discovery {
        SURE, WAR, NONE
    }
    private static final String H2_CONSOLE = "org.springframework.boot.h2console.autoconfigure.H2ConsoleAutoConfiguration";
    static final String H2_SERVLET = "org.h2.server.web.JakartaWebServlet";
    /**
     * Decision 0110: {@code HttpServlet#doHead} runs {@code doGet} unless the servlet overrides it.
     */
    private static final Map<String, String> HANDLERS = Map.of("doGet", "GET", "doHead", "HEAD", "doPost", "POST",
            "doPut", "PUT", "doDelete", "DELETE", "doPatch", "PATCH", "doOptions", "OPTIONS", "doTrace", "TRACE",
            "service", "*");

    private static final Set<String> COLLECTIONS = Set.of("of", "asList", "singletonList", "singleton", "copyOf");
    private static final String SERVLET = "jakarta.servlet.Servlet";
    private static final String DISPATCHER_SERVLET = "org.springframework.web.servlet.DispatcherServlet";
    /**
     * Library servlets whose requests are read elsewhere: Spring MVC's handlers are the controllers, Spring Web
     * Services' the {@code @Endpoint}s (decision 0056).
     */
    private static final Set<String> READ_ELSEWHERE = Set.of("org.springframework.web.servlet.DispatcherServlet",
            "org.springframework.ws.transport.http.MessageDispatcherServlet");

    private final ScanContext context;
    private final List<Finding> findings = new ArrayList<>();
    private final List<Ingress> libraryServlets = new ArrayList<>();

    ServletEndpoints(ScanContext context) {
        this.context = context;
    }

    /**
     * What {@link #detect()} couldn't read.
     */
    List<Finding> findings() {
        return findings;
    }

    /**
     * Who registers the application's {@code @WebServlet} and {@code @WebFilter} classes. Boot 4.1.1's embedded
     * server with {@code @ServletComponentScan}; else the servlet container a war is deployed to, which reads them
     * itself unless its web.xml is metadata-complete (Tomcat 11's {@code ContextConfig#webConfig}), while Boot's
     * embedded server doesn't ({@code ServletComponentScan}: "Scanning is only performed when using an embedded web
     * server"). A war without Boot (a web.xml or a {@code WebApplicationInitializer}, and no auto-configuration) is
     * deployed to one; a Boot war (a {@code SpringBootServletInitializer}) may be, or may run as an executable jar,
     * which AuthTracer can't tell: {@link Discovery#WAR}, the weaker reading, registered with a finding.
     */
    static Discovery discovery(ScanContext context) {
        if (COMPONENT_SCAN.stream().anyMatch(context::anyClassAnnotated)) {
            return Discovery.SURE;
        }
        List<java.nio.file.Path> resources = context.input().resourceDirs();
        if (WebXml.metadataComplete(resources)) {
            return Discovery.NONE;
        }
        if (context.applicationClasses().stream().anyMatch(cls -> SpringBeans.assignable(context, cls.getType(),
                Set.of(BOOT_WAR)))) {
            return Discovery.WAR;
        }
        boolean war = WebXml.present(resources) || context.applicationClasses().stream().anyMatch(cls ->
                !cls.isInterface() && !cls.isAbstract() && SpringBeans.assignable(context, cls.getType(),
                        Set.of(WEB_APPLICATION_INITIALIZER)));
        return war && !context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION) ? Discovery.SURE
                : Discovery.NONE;
    }

    /**
     * The finding for a Boot war's {@code @WebServlet} or {@code @WebFilter}, which runs as the container deploys it.
     */
    static Finding warFinding(String what, JavaSootClass cls, String consequence) {
        return new Finding(Finding.Kind.OPAQUE_CONFIG, "The " + what + " " + cls.getName() + " is registered by the"
                + " servlet container the war is deployed to (a SpringBootServletInitializer), not when it runs as an"
                + " executable jar (no @ServletComponentScan), which AuthTracer can't tell: " + consequence,
                CodeRef.ofClass(cls.getName()));
    }

    List<RequestMappings.Mapping> detect() {
        List<RequestMappings.Mapping> mappings = new ArrayList<>();
        Discovery discovery = discovery(context);
        for (JavaSootClass cls : context.applicationClasses()) {
            if (discovery != Discovery.NONE) {
                context.findAnnotation(cls, WEB_SERVLET).ifPresent(servlet -> {
                    List<String> patterns = new ArrayList<>(Annotations.strings(servlet, "urlPatterns"));
                    patterns.addAll(Annotations.strings(servlet, "value"));
                    defaultServlet("The @WebServlet " + cls.getName(), patterns, CodeRef.ofClass(cls.getName()));
                    if (discovery == Discovery.WAR) {
                        findings.add(warFinding("@WebServlet", cls, "its requests are shown as ways in"));
                    }
                    mappings.addAll(servlet(cls.getType(), patterns));
                });
            }
            for (JavaSootMethod method : cls.getMethods()) {
                if (method.hasBody() && context.hasAnnotation(method, SpringNames.BEAN)
                        && method.getReturnType() instanceof ClassType type
                        && type.getFullyQualifiedName().equals(REGISTRATION)) {
                    registered(method, mappings);
                }
            }
        }
        return mappings;
    }

    /**
     * A {@code ServletRegistrationBean} bean's servlet at its patterns, with a finding for what can't be read of it.
     */
    @Supports({Feature.LIBRARY_ENDPOINTS, Feature.FINDING_OPAQUE_CONFIG})
    private void registered(JavaSootMethod method, List<RequestMappings.Mapping> mappings) {
        String bean = MethodNames.key(method.getSignature());
        CodeRef at = MethodNames.codeRef(method.getSignature());
        Optional<Registration> registration = registration(context, method);
        if (registration.isEmpty() || registration.get().servlet() == null) {
            findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The servlet registration " + bean + " registers "
                    + (registration.isEmpty() ? "a servlet in a way AuthTracer can't read"
                            : "a servlet AuthTracer can't tell") + ": its requests aren't on the graph", at));
            return;
        }
        Registration found = registration.get();
        if (found.unread()) {
            findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The servlet registration " + bean + " maps its"
                    + " servlet to " + (found.patterns().isEmpty() ? "URL patterns that aren't constants: its requests"
                            : String.join(", ", found.patterns()) + " and to URL patterns that aren't constants: the"
                                    + " requests to those") + " aren't on the graph", at));
        }
        String servlet = found.servlet().getFullyQualifiedName();
        if (!READ_ELSEWHERE.contains(servlet)) {
            defaultServlet("The servlet registration " + bean, found.patterns(), at);
        }
        if (context.isApplication(found.servlet())) {
            mappings.addAll(servlet(found.servlet(), found.patterns()));
        }
        else if (!READ_ELSEWHERE.contains(servlet) && context.superClassesOf(found.servlet()).stream()
                .noneMatch(type -> READ_ELSEWHERE.contains(type.getFullyQualifiedName()))) {
            // What a library's servlet serves isn't read: its requests, at its patterns, pass the request rules.
            found.patterns().stream().flatMap(pattern -> route(pattern).stream()).distinct()
                    .forEach(route -> libraryServlets.add(Ingress.of("*", route, CodeRef.ofClass(servlet))));
        }
    }

    /**
     * Spring Boot's H2 console, which a library servlet serves.
     */
    @Supports(Feature.LIBRARY_ENDPOINTS)
    List<Ingress> library() {
        List<Ingress> library = new ArrayList<>(libraryServlets);
        if (context.findClass(H2_CONSOLE).isEmpty() || context.findClass(H2_SERVLET).isEmpty()
                || !context.properties().flag("spring.h2.console.enabled").orElse(false)) {
            return library;
        }
        String path = context.properties().get("spring.h2.console.path").orElse("/h2-console");
        List.of("GET", "POST").forEach(method -> library.add(Ingress.of(method, RequestMappings.join(path, "/**"),
                CodeRef.ofClass(H2_SERVLET))));
        return library;
    }

    /**
     * A {@code ServletRegistrationBean}'s servlet (null when AuthTracer can't tell which) and its URL patterns.
     *
     * @param unread some of its URL mappings aren't constants, so the patterns are the ones that are
     */
    record Registration(ClassType servlet, List<String> patterns, boolean unread) {
    }

    /**
     * Where a value in the method being read comes from: in a helper, its parameters are the caller's arguments.
     */
    private record Frame(JavaSootMethod method, Frame caller, AbstractInvokeExpr call) {

        /**
         * The method and value a value is read from: a parameter's argument, in the caller.
         */
        Frame of(Value value) {
            if (caller != null && value instanceof Local local) {
                OptionalInt parameter = Locals.parameterIndex(method.getBody(), local);
                if (parameter.isPresent() && parameter.getAsInt() < call.getArgCount()) {
                    return caller;
                }
            }
            return this;
        }

        Value argument(Value value) {
            if (caller != null && value instanceof Local local) {
                OptionalInt parameter = Locals.parameterIndex(method.getBody(), local);
                if (parameter.isPresent() && parameter.getAsInt() < call.getArgCount()) {
                    return call.getArg(parameter.getAsInt());
                }
            }
            return value;
        }
    }

    /**
     * {@code new ServletRegistrationBean<>(new LegacyServlet(), "/legacy/*")}, and its {@code addUrlMappings(..)},
     * {@code setUrlMappings(..)} and {@code setServlet(..)}; in the bean method, else in the application method it
     * returns the registration of ({@code return register(new LegacyServlet(), "/legacy/*")}), with its arguments.
     */
    static Optional<Registration> registration(ScanContext context, JavaSootMethod method) {
        Optional<Registration> own = registration(context, new Frame(method, null, null));
        if (own.isPresent()) {
            return own;
        }
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt).filter(call -> call.getMethodSignature()
                    .getType() instanceof ClassType returned && returned.getFullyQualifiedName().equals(REGISTRATION)
                    && context.isApplication(call.getMethodSignature().getDeclClassType()));
            Optional<JavaSootMethod> helper = invoke.flatMap(call -> context.findMethod(call.getMethodSignature()))
                    .filter(JavaSootMethod::hasBody);
            if (helper.isPresent()) {
                return registration(context, new Frame(helper.get(), new Frame(method, null, null), invoke.get()))
                        .map(found -> found.servlet() != null ? found : new Registration(generic(context, method),
                                found.patterns(), found.unread()));
            }
        }
        return Optional.empty();
    }

    private static Optional<Registration> registration(ScanContext context, Frame frame) {
        boolean registers = false;
        boolean mapped = false;
        boolean unread = false;
        ClassType servlet = null;
        List<String> patterns = new ArrayList<>();
        for (Stmt stmt : frame.method().getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isEmpty() || !invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName()
                    .equals(REGISTRATION)) {
                continue;
            }
            registers = true;
            String name = invoke.get().getMethodSignature().getName();
            Immediate mappings = null;
            // Boot 4.1.1's constructors: (), (servlet, urlMappings...) and (servlet, alwaysMapUrl, urlMappings...).
            if (name.equals("<init>") && invoke.get().getArgCount() >= 2) {
                servlet = created(context, frame, invoke.get().getArg(0)).orElse(servlet);
                mappings = invoke.get().getArg(invoke.get().getArgCount() - 1);
            }
            else if (name.equals("addUrlMappings") || name.equals("setUrlMappings")) {
                mappings = invoke.get().getArg(0);
            }
            else if (name.equals("setServlet")) {
                servlet = created(context, frame, invoke.get().getArg(0)).orElse(servlet);
            }
            if (mappings != null) {
                Mappings read = mappings(frame, mappings);
                // An empty varargs array is no mappings at all.
                mapped |= read.unread() || !read.patterns().isEmpty();
                unread |= read.unread();
                patterns.addAll(read.patterns());
            }
        }
        if (registers && servlet == null) {
            servlet = generic(context, frame.method());
        }
        // A registration with no URL mappings is mapped to /*: every request. One whose mappings can't be read isn't.
        return registers ? Optional.of(new Registration(servlet, mapped ? patterns : List.of("/*"), unread))
                : Optional.empty();
    }

    /**
     * The servlet a {@code ServletRegistrationBean<LegacyServlet>} return type names, when it is a class.
     */
    private static ClassType generic(ScanContext context, JavaSootMethod method) {
        return context.classFiles().genericReturnType(method.getSignature())
                .filter(generic -> generic.arguments().size() == 1).map(generic -> generic.arguments().getFirst()
                        .name())
                .filter(name -> !name.equals(SERVLET) && !name.equals(HTTP_SERVLET))
                .flatMap(context::findClass).map(JavaSootClass::getType).orElse(null);
    }

    /**
     * URL mappings read: the constants, and whether there are others.
     */
    private record Mappings(List<String> patterns, boolean unread) {
    }

    /**
     * URL patterns given in a method (a filter registration's, an interceptor's, decision 0070): empty when one of
     * them isn't a constant.
     */
    @Supports(Feature.CALL_PATHS)
    static Optional<List<String>> mappings(JavaSootMethod method, Immediate argument) {
        Mappings read = mappings(new Frame(method, null, null), argument);
        return read.unread() ? Optional.empty() : Optional.of(read.patterns());
    }

    /**
     * URL mappings: a string constant, a varargs array of them, or a collection {@code List.of(..)} makes of them,
     * each element a constant or not.
     */
    private static Mappings mappings(Frame frame, Immediate value) {
        Frame from = frame.of(value);
        Value argument = frame.argument(value);
        if (argument instanceof StringConstant constant) {
            return new Mappings(List.of(constant.getValue()), false);
        }
        if (!(argument instanceof Local local)) {
            return new Mappings(List.of(), true);
        }
        Optional<Value> definition = Locals.definition(from.method().getBody(), local);
        if (definition.orElse(null) instanceof JNewArrayExpr array && array.getSize() instanceof IntConstant size) {
            List<String> strings = strings(from.method(), local);
            return new Mappings(strings, strings.size() != size.getValue());
        }
        if (definition.orElse(null) instanceof AbstractInvokeExpr invoke
                && COLLECTIONS.contains(invoke.getMethodSignature().getName())) {
            List<String> strings = new ArrayList<>();
            boolean unread = false;
            for (Immediate element : invoke.getArgs()) {
                Mappings read = mappings(from, element);
                strings.addAll(read.patterns());
                unread |= read.unread();
            }
            return new Mappings(strings, unread);
        }
        return new Mappings(List.of(), true);
    }

    /**
     * The servlet given: created there, or a value of a servlet class (a bean parameter, a field).
     */
    private static Optional<ClassType> created(ScanContext context, Frame frame, Value value) {
        Frame from = frame.of(value);
        if (!(frame.argument(value) instanceof Local local)) {
            return Optional.empty();
        }
        return Locals.created(from.method().getBody(), local).or(() -> local.getType() instanceof ClassType type
                && !type.getFullyQualifiedName().equals(SERVLET) && !type.getFullyQualifiedName().equals(HTTP_SERVLET)
                && SpringBeans.assignable(context, type, Set.of(SERVLET)) ? Optional.of(type) : Optional.empty());
    }

    /**
     * The servlet's handler methods at each pattern; servlets that aren't the application's are not read.
     */
    private List<RequestMappings.Mapping> servlet(ClassType type, List<String> patterns) {
        List<RequestMappings.Mapping> mappings = new ArrayList<>();
        Optional<JavaSootClass> cls = context.isApplication(type) ? context.findClass(type) : Optional.empty();
        if (cls.isEmpty() || context.superClassesOf(type).stream()
                .noneMatch(superType -> superType.getFullyQualifiedName().equals(HTTP_SERVLET))) {
            return mappings;
        }
        // The handler methods the servlet or an application superclass overrides, the nearest first.
        List<JavaSootMethod> methods = new ArrayList<>(cls.get().getMethods());
        context.superClassesOf(type).stream().filter(context::isApplication).map(context::findClass)
                .flatMap(Optional::stream).forEach(superClass -> methods.addAll(superClass.getMethods()));
        Set<String> seen = new HashSet<>();
        for (JavaSootMethod method : methods) {
            String httpMethod = HANDLERS.get(method.getName());
            if (httpMethod == null || !method.hasBody() || method.getParameterCount() != 2 || !seen.add(httpMethod)) {
                continue;
            }
            for (String pattern : patterns) {
                route(pattern).ifPresent(route -> mappings.add(new RequestMappings.Mapping(Ingress.of(httpMethod,
                        route, MethodNames.codeRef(method.getSignature())), method, true)));
            }
        }
        return mappings;
    }

    /**
     * A servlet URL pattern as a route (Servlet 6.1, 12.2): {@code /x/*} is {@code /x/**}. Decision 0112: an
     * extension {@code *.do} takes every path that ends in it, {@code /**}{@code /*.do}; the default servlet {@code /}
     * takes what no other mapping does, shown as all of it, {@code /**}; {@code ""} is the context root alone. Empty
     * for a pattern the container refuses.
     */
    static Optional<String> route(String pattern) {
        if (pattern.startsWith("*.")) {
            return Optional.of("/**/" + pattern);
        }
        if (pattern.equals("/")) {
            return Optional.of("/**");
        }
        if (pattern.isEmpty()) {
            return Optional.of("/");
        }
        if (!pattern.startsWith("/")) {
            return Optional.empty();
        }
        return Optional.of(pattern.endsWith("/*") ? pattern.substring(0, pattern.length() - 1) + "**" : pattern);
    }

    /**
     * Decision 0112: a servlet mapped to {@code /} where Spring Boot maps its DispatcherServlet too. The container keeps
     * one registration's mappings (Tomcat's {@code ApplicationServletRegistration#addMapping} refuses all of a later
     * registration's patterns when one is taken), so either the servlet or Spring MVC answers: the graph shows both.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private void defaultServlet(String what, List<String> patterns, CodeRef at) {
        boolean dispatcherAtRoot = context.findClass(DISPATCHER_SERVLET).isPresent()
                && context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION)
                && context.properties().get("spring.mvc.servlet.path").map(path -> path.equals("/") || path.isEmpty())
                        .orElse(true);
        if (patterns.contains("/") && dispatcherAtRoot) {
            findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, what + " maps its servlet to /, where Spring Boot"
                    + " maps the DispatcherServlet: the container keeps one of the two registrations, which"
                    + " AuthTracer can't tell, so the graph shows the servlet's endpoints and the controllers'", at));
        }
    }

    private static List<String> strings(JavaSootMethod method, Immediate argument) {
        return Locals.strings(method.getBody(), argument);
    }
}
