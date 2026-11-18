package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.flow.Payloads;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.expr.JNewArrayExpr;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.ClassType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0056: Spring Web Services (5.0) SOAP operations. An {@code @Endpoint} class's {@code @PayloadRoot}
 * ({@code @PayloadRoots}) methods are each an Ingress {@code SOAP <localPart>} (its namespace a condition,
 * {@code ?namespace:<uri>}), its {@code @SoapAction} and {@code @Action} methods an Ingress {@code SOAP <action>},
 * answered with what they return, behind
 * the {@code MessageDispatcherServlet}'s {@code POST <path>/**}, which the request rules check: the path is Spring
 * Boot's {@code spring.webservices.path} ({@code /services}), or the pattern of a
 * {@code ServletRegistrationBean<MessageDispatcherServlet>} the application registers. Without Spring Boot (decision
 * 0080), the mappings of the application's {@code AbstractMessageDispatcherServletInitializer}; with none of these,
 * the operations are an OPAQUE_CONFIG finding.
 */
@Supports(Feature.HTTP_ENDPOINTS)
final class SoapEndpoints {

    static final String SOAP = "SOAP";
    private static final String ENDPOINT = "org.springframework.ws.server.endpoint.annotation.Endpoint";
    private static final String PAYLOAD_ROOT = "org.springframework.ws.server.endpoint.annotation.PayloadRoot";
    private static final String PAYLOAD_ROOTS = "org.springframework.ws.server.endpoint.annotation.PayloadRoots";
    private static final String SOAP_ACTION = "org.springframework.ws.soap.server.endpoint.annotation.SoapAction";
    private static final String SOAP_ACTIONS = "org.springframework.ws.soap.server.endpoint.annotation.SoapActions";
    private static final String ADDRESSING_ACTION = "org.springframework.ws.soap.addressing.server.annotation.Action";
    /**
     * An operation's namespace, a condition of its Ingress the linker compares with a call's.
     */
    static final String NAMESPACE = "namespace:";
    /**
     * The SOAP action a call names, beside its request's namespace.
     */
    static final String ACTION = "soapAction:";
    private static final String DISPATCHER = "org.springframework.ws.transport.http.MessageDispatcherServlet";
    private static final String BOOT = "org.springframework.boot.webservices.autoconfigure.WebServicesAutoConfiguration";

    private static final String INITIALIZER =
            "org.springframework.ws.transport.http.support.AbstractMessageDispatcherServletInitializer";
    /**
     * Spring WS 5.0.2's {@code AbstractMessageDispatcherServletInitializer.DEFAULT_SERVLET_MAPPINGS}.
     */
    private static final List<String> INITIALIZER_MAPPINGS = List.of("/services", "*.wsdl");
    private static final String ENABLE_WS = "org.springframework.ws.config.annotation.EnableWs";
    private static final String WS_CONFIGURATION = "org.springframework.ws.config.annotation.WsConfigurationSupport";

    private final ScanContext context;
    private final List<Finding> findings = new ArrayList<>();
    private List<Ingress> transports;

    SoapEndpoints(ScanContext context) {
        this.context = context;
    }

    /**
     * What {@link #detect()} couldn't place.
     */
    List<Finding> findings() {
        return findings;
    }

    static boolean isSoap(Ingress ingress) {
        return SOAP.equals(ingress.httpMethod());
    }

    List<RequestMappings.Mapping> detect() {
        List<RequestMappings.Mapping> mappings = new ArrayList<>();
        if (transports().isEmpty()) {
            return mappings;
        }
        Ingress transport = transports().getFirst();
        for (JavaSootClass cls : context.applicationClasses()) {
            if (!context.hasAnnotation(cls, ENDPOINT)) {
                continue;
            }
            for (JavaSootMethod method : cls.getMethods()) {
                List<AnnotationUsage> roots = new ArrayList<>();
                context.findAnnotation(method, PAYLOAD_ROOT).ifPresent(roots::add);
                context.findAnnotation(method, PAYLOAD_ROOTS)
                        .ifPresent(container -> roots.addAll(Annotations.nested(container, "value")));
                List<Ingress> operations = new ArrayList<>();
                CodeRef handler = MethodNames.codeRef(method.getSignature());
                for (AnnotationUsage root : roots) {
                    Annotations.string(root, "localPart").ifPresent(localPart -> operations.add(Ingress.of(SOAP,
                            localPart, handler).withParams(Annotations.string(root, "namespace")
                                    .filter(namespace -> !namespace.isEmpty()).map(namespace -> NAMESPACE + namespace)
                                    .orElse(null))));
                }
                actions(method).forEach(action -> operations.add(Ingress.of(SOAP, action, handler)));
                for (Ingress operation : operations) {
                    mappings.add(new RequestMappings.Mapping(operation.withResponse(Payloads.returnedBy(context,
                            method.getSignature()).orElse(null)), method, true, transport));
                }
            }
        }
        return mappings;
    }

    /**
     * The SOAP actions a method is mapped to: {@code @SoapAction} ({@code @SoapActions}), which Spring WS's
     * {@code SoapActionAnnotationMethodEndpointMapping} matches against the request's {@code SOAPAction} header, and
     * WS-Addressing's {@code @Action}, which {@code AnnotationActionEndpointMapping} matches against its
     * {@code wsa:Action}. {@code WsConfigurationSupport} (5.0.2) orders them after the payload root mapping.
     */
    private List<String> actions(JavaSootMethod method) {
        List<AnnotationUsage> found = new ArrayList<>();
        context.findAnnotation(method, SOAP_ACTION).ifPresent(found::add);
        context.findAnnotation(method, SOAP_ACTIONS)
                .ifPresent(container -> found.addAll(Annotations.nested(container, "value")));
        context.findAnnotation(method, ADDRESSING_ACTION).ifPresent(found::add);
        return found.stream().flatMap(annotation -> Annotations.string(annotation, "value").stream())
                .filter(action -> !action.isEmpty()).toList();
    }

    /**
     * The dispatcher servlet's requests, a {@code POST} at each of its paths: an operation arrives in any of them.
     */
    List<Ingress> transports() {
        if (transports == null) {
            transports = servletPaths().stream().map(path -> Ingress.of("POST", path, null)).toList();
        }
        return transports;
    }

    /**
     * The dispatcher servlet's paths, as patterns under them: those of the registrations the application makes, else
     * Boot's.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private List<String> servletPaths() {
        List<String> paths = new ArrayList<>();
        for (JavaSootMethod method : SpringBeans.beanMethods(context, ServletEndpoints.REGISTRATION)) {
            if (method.hasBody()) {
                ServletEndpoints.registration(context, method).filter(found -> dispatches(method, found.servlet()))
                        .ifPresent(found -> found.patterns().stream().flatMap(pattern -> path(pattern).stream())
                                .filter(path -> !paths.contains(path)).forEach(paths::add));
            }
        }
        if (paths.isEmpty()) {
            initializerPaths().forEach(paths::add);
        }
        if (!paths.isEmpty()) {
            return paths;
        }
        if (context.findClass(BOOT).isEmpty() || !context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION)) {
            Optional<JavaSootClass> endpoint = context.applicationClasses().stream()
                    .filter(cls -> context.hasAnnotation(cls, ENDPOINT)).findFirst();
            endpoint.ifPresent(cls -> findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "Spring Web Services"
                    + " endpoints (" + cls.getName() + ") with no MessageDispatcherServlet AuthTracer can find: no"
                    + " Spring Boot auto-configuration, ServletRegistrationBean or"
                    + " AbstractMessageDispatcherServletInitializer registers one (web.xml isn't read), so the SOAP"
                    + " operations aren't on the graph", CodeRef.ofClass(cls.getName()))));
            return paths;
        }
        // Boot 4.1.1's WebServicesAutoConfiguration backs off for the application's own configuration
        // (@ConditionalOnMissingBean(WsConfigurationSupport.class)), and that registers no dispatcher servlet here.
        Optional<JavaSootClass> configuration = context.applicationClasses().stream()
                .filter(cls -> context.hasAnnotation(cls, ENABLE_WS) || context.superClassesOf(cls.getType()).stream()
                        .anyMatch(type -> type.getFullyQualifiedName().equals(WS_CONFIGURATION)))
                .findFirst();
        if (configuration.isPresent()) {
            if (context.applicationClasses().stream().anyMatch(cls -> context.hasAnnotation(cls, ENDPOINT))) {
                findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "Spring Web Services is configured by "
                        + configuration.get().getName() + " (@EnableWs or a WsConfigurationSupport), so Spring"
                        + " Boot's MessageDispatcherServlet isn't registered, and AuthTracer finds no"
                        + " ServletRegistrationBean for one: the SOAP operations aren't on the graph",
                        CodeRef.ofClass(configuration.get().getName())));
            }
            return paths;
        }
        return List.of(RequestMappings.join(context.properties().get("spring.webservices.path").orElse("/services"),
                "/**"));
    }

    /**
     * The paths an application's {@code AbstractMessageDispatcherServletInitializer} maps the dispatcher at: its
     * {@code getServletMappings()}, else the default; a finding when the override returns what isn't constants.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private List<String> initializerPaths() {
        List<String> paths = new ArrayList<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            if (cls.isAbstract() || context.superClassesOf(cls.getType()).stream()
                    .noneMatch(type -> type.getFullyQualifiedName().equals(INITIALIZER))) {
                continue;
            }
            List<String> mappings = INITIALIZER_MAPPINGS;
            Optional<JavaSootMethod> override = Stream.concat(Stream.of(cls.getType()),
                    context.superClassesOf(cls.getType()).stream().filter(context::isApplication))
                    .flatMap(type -> context.findClass(type).stream()).flatMap(found -> found.getMethods().stream())
                    .filter(method -> method.getName().equals("getServletMappings") && method.getParameterCount() == 0
                            && method.hasBody())
                    .findFirst();
            if (override.isPresent()) {
                mappings = returnedStrings(override.get());
                if (mappings.isEmpty()) {
                    findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The MessageDispatcherServlet initializer "
                            + cls.getName() + " maps the servlet at paths that aren't constants: the SOAP operations"
                            + " there aren't on the graph", MethodNames.codeRef(override.get().getSignature())));
                }
            }
            mappings.stream().flatMap(pattern -> path(pattern).stream()).filter(path -> !paths.contains(path))
                    .forEach(paths::add);
        }
        return paths;
    }

    /**
     * The string constants of the array a method returns: {@code return new String[] {"/ws/*"};}.
     */
    private static List<String> returnedStrings(JavaSootMethod method) {
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof JReturnStmt returned && returned.getOp() instanceof Local array
                    && Locals.definition(method.getBody(), array).orElse(null) instanceof JNewArrayExpr created
                    && created.getSize() instanceof IntConstant size) {
                List<String> strings = Locals.strings(method.getBody(), array);
                return strings.size() == size.getValue() ? strings : List.of();
            }
        }
        return List.of();
    }

    private static Optional<String> path(String pattern) {
        // The default servlet ("/") answers whatever no other servlet maps.
        return pattern.equals("/") ? Optional.of("/**") : ServletEndpoints.route(pattern);
    }

    /**
     * Whether the registration bean registers a {@code MessageDispatcherServlet}: as its type argument, or as the
     * servlet it is given.
     */
    private boolean dispatches(JavaSootMethod method, ClassType servlet) {
        return servlet != null && (servlet.getFullyQualifiedName().equals(DISPATCHER) || context.superClassesOf(servlet)
                .stream().anyMatch(type -> type.getFullyQualifiedName().equals(DISPATCHER)))
                || context.classFiles().genericReturnType(method.getSignature()).filter(generic -> generic.arguments()
                        .size() == 1 && generic.arguments().getFirst().name().equals(DISPATCHER)).isPresent();
    }
}
