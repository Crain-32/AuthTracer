package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.ClassFileMetadata;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.ref.JStaticFieldRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0032: gRPC services (grpc-java's and grpc-kotlin's generated stubs, served by Spring gRPC). A bean
 * extending a generated {@code GreeterGrpc.GreeterImplBase} serves each rpc its methods override: the Ingress
 * {@code GRPC fixtures.grpc.Greeter/SayHello}, named by the generated {@code getSayHelloMethod()}'s full method name.
 * Calls on the generated stubs ({@code GreeterGrpc.newBlockingStub(channel).sayHello(..)}) are Egress to the same
 * name.
 */
@Supports(Feature.GRPC_METHODS)
final class GrpcServices {

    static final String GRPC = "GRPC";
    private static final String METHOD_DESCRIPTOR = "io.grpc.MethodDescriptor";
    private static final Set<String> STREAMING_TYPES = Set.of("SERVER_STREAMING", "BIDI_STREAMING");
    private static final String DISPATCHER_SERVLET = "org.springframework.web.servlet.DispatcherServlet";
    private static final String GRPC_SERVLET = "io.grpc.servlet.jakarta.GrpcServlet";
    private static final String SERVICES_CONFIGURATION =
            "org.springframework.boot.grpc.server.autoconfigure.GrpcServerServicesAutoConfiguration";
    private static final String REFLECTION = "io.grpc.protobuf.services.ProtoReflectionServiceV1";
    private static final String REFLECTION_V1 = "grpc.reflection.v1.ServerReflection/ServerReflectionInfo";
    /**
     * grpc-services 1.83.1's reflection services, by the rpc each serves.
     */
    private static final Map<String, String> HAND_REGISTERED = Map.of(REFLECTION, REFLECTION_V1,
            "io.grpc.protobuf.services.ProtoReflectionService",
            "grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo");

    /**
     * An rpc of a generated {@code *Grpc} class.
     *
     * @param fullName the gRPC full method name, {@code package.Service/Method}
     * @param javaName the stub and service method, e.g. {@code sayHello}
     * @param responseType the message the server answers with, when the descriptor's type arguments are known
     * @param streaming whether the server answers with a stream of responses
     */
    record GrpcMethod(String fullName, String javaName, String responseType, boolean streaming) {
    }

    private final ScanContext context;
    private final Map<String, List<GrpcMethod>> generated = new ConcurrentHashMap<>();

    GrpcServices(ScanContext context) {
        this.context = context;
    }

    static boolean isGrpc(Ingress ingress) {
        return GRPC.equals(ingress.httpMethod());
    }

    /**
     * The services among the operations, e.g. {@code fixtures.grpc.Greeter}.
     */
    @Supports(Feature.REQUEST_RULES)
    static Set<String> serviceNames(List<RequestMappings.Mapping> rpcs) {
        return rpcs.stream().map(rpc -> rpc.ingress().route()).map(route -> route.substring(0, route.indexOf('/')))
                .collect(Collectors.toCollection(TreeSet::new));
    }

    /**
     * Spring Boot serves gRPC through the servlet container when it can (4.1.1 {@code ServletGrpcServerConfiguration}):
     * a servlet web application with grpc-servlet on the classpath, unless {@code spring.grpc.server.servlet.enabled}
     * is false. Calls are then {@code POST /package.Service/Method} requests, which the HTTP rules authorize.
     */
    private boolean servletTransport() {
        return !WebStack.reactive(context) && context.findClass(DISPATCHER_SERVLET).isPresent()
                && context.findClass(GRPC_SERVLET).isPresent()
                && context.properties().flag("spring.grpc.server.servlet.enabled").orElse(true);
    }

    /**
     * Decision 0059: the services Spring Boot's gRPC server adds (4.1.1 {@code GrpcServerServicesAutoConfiguration},
     * {@code GrpcServerHealthAutoConfiguration}), each with its servlet transport when served through the container:
     * server reflection, {@code grpc.reflection.v1.ServerReflection/ServerReflectionInfo}, which lists every service
     * and message type, unless {@code spring.grpc.server.reflection.enabled=false}; and health,
     * {@code grpc.health.v1.Health/Check} and {@code /Watch}, unless {@code spring.grpc.server.health.enabled=false}.
     * Only when the application serves gRPC services itself. Reflection the application registers by hand is served
     * whatever Boot's properties say, at its bean method.
     */
    @Supports(Feature.LIBRARY_ENDPOINTS)
    List<Map.Entry<Ingress, Ingress>> library(boolean serves) {
        List<Map.Entry<Ingress, Ingress>> services = new ArrayList<>();
        if (disabled("spring.grpc.server.enabled")) {
            return services;
        }
        // The application's own: served as every BindableService bean is, whatever Boot's properties say.
        Map<String, CodeRef> methods = new LinkedHashMap<>(registeredByHand());
        if ((serves || !methods.isEmpty()) && context.findClass(SERVICES_CONFIGURATION).isPresent()
                && context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION)) {
            CodeRef boot = CodeRef.ofClass(SERVICES_CONFIGURATION);
            // Boot's reflection service is @ConditionalOnBean(BindableService.class), not on a missing one: it is
            // added beside one the application registers.
            if (context.findClass(REFLECTION).isPresent() && !disabled("spring.grpc.server.reflection.enabled")) {
                methods.putIfAbsent(REFLECTION_V1, boot);
            }
            if (!disabled("spring.grpc.server.health.enabled")) {
                methods.putIfAbsent("grpc.health.v1.Health/Check", boot);
                methods.putIfAbsent("grpc.health.v1.Health/Watch", boot);
            }
        }
        boolean servlet = servletTransport();
        methods.forEach((method, handler) -> services.add(Map.entry(Ingress.of(GRPC, method, handler),
                servlet ? Ingress.of("POST", "/" + method, handler) : Ingress.of(GRPC, method, handler))));
        return services;
    }

    /**
     * Server reflection the application registers as a bean ({@code @Bean BindableService reflection()} returning
     * grpc-services' {@code ProtoReflectionServiceV1.newInstance()}, or the deprecated v1alpha
     * {@code ProtoReflectionService.newInstance()}), by the rpc it serves, at its bean method.
     */
    @Supports(Feature.LIBRARY_ENDPOINTS)
    private Map<String, CodeRef> registeredByHand() {
        Map<String, CodeRef> methods = new LinkedHashMap<>();
        for (JavaSootMethod bean : SpringBeans.beanMethods(context)) {
            if (!bean.hasBody()) {
                continue;
            }
            for (Stmt stmt : bean.getBody().getStmts()) {
                Optional<String> served = Locals.invoke(stmt)
                        .filter(invoke -> invoke.getMethodSignature().getName().equals("newInstance"))
                        .map(invoke -> HAND_REGISTERED.get(invoke.getMethodSignature().getDeclClassType()
                                .getFullyQualifiedName()));
                served.ifPresent(method -> methods.putIfAbsent(method, MethodNames.codeRef(bean.getSignature())));
            }
        }
        return methods;
    }

    private boolean disabled(String property) {
        return !context.properties().flag(property).orElse(true);
    }

    List<RequestMappings.Mapping> detect(SpringBeans beans) {
        List<RequestMappings.Mapping> mappings = new ArrayList<>();
        boolean servlet = servletTransport();
        for (JavaSootClass cls : context.applicationClasses()) {
            if (!beans.isBean(cls.getType())) {
                continue;
            }
            Optional<String> grpcClass = implBaseOuter(cls);
            if (grpcClass.isEmpty()) {
                continue;
            }
            for (GrpcMethod rpc : methods(grpcClass.get())) {
                handler(cls, rpc.javaName()).ifPresent(handler -> {
                    Ingress ingress = Ingress.of(GRPC, rpc.fullName(), MethodNames.codeRef(handler.getSignature()))
                            .withResponse(rpc.responseType() == null ? null
                                    : new Payload(rpc.responseType(), rpc.streaming()));
                    // The response goes to a StreamObserver, so it is the rpc's, not the handler's return type.
                    mappings.add(new RequestMappings.Mapping(ingress, handler, true, servlet
                            ? Ingress.of("POST", "/" + rpc.fullName(), ingress.handler()) : null));
                });
            }
        }
        return mappings;
    }

    /**
     * The rpc a call on a generated stub ({@code GreeterGrpc$GreeterBlockingStub#sayHello}) makes.
     */
    @Supports(Feature.SERVICE_CALLS)
    Optional<GrpcMethod> stubCall(MethodSignature called) {
        String owner = called.getDeclClassType().getFullyQualifiedName();
        int nested = owner.lastIndexOf('$');
        if (nested < 0 || !owner.endsWith("Stub")) {
            return Optional.empty();
        }
        // Kotlin calls a stub method with default arguments as sayHello$default.
        String name = called.getName().replaceFirst("\\$default$", "");
        return methods(owner.substring(0, nested)).stream()
                .filter(rpc -> rpc.javaName().equals(name)).findFirst();
    }

    /**
     * The generated {@code *Grpc} class whose {@code *ImplBase} the class extends, looking up the superclasses.
     */
    private Optional<String> implBaseOuter(JavaSootClass cls) {
        for (ClassType type : context.superClassesOf(cls.getType())) {
            String name = type.getFullyQualifiedName();
            int nested = name.lastIndexOf('$');
            if (nested > 0 && name.endsWith("ImplBase") && !methods(name.substring(0, nested)).isEmpty()) {
                return Optional.of(name.substring(0, nested));
            }
        }
        return Optional.empty();
    }

    private Optional<JavaSootMethod> handler(JavaSootClass cls, String name) {
        return cls.getMethods().stream().filter(method -> method.getName().equals(name) && method.hasBody()
                && !method.isStatic()).findFirst();
    }

    /**
     * The rpcs a generated class declares: each static {@code get<Rpc>Method()} builds its {@code MethodDescriptor}
     * with {@code generateFullMethodName(SERVICE_NAME, "Rpc")}, both constants.
     */
    List<GrpcMethod> methods(String grpcClass) {
        // grpc-kotlin's GreeterGrpcKt (coroutine stubs and ImplBase) takes its descriptors from grpc-java's
        // GreeterGrpc.
        String generator = grpcClass.endsWith("GrpcKt") ? grpcClass.substring(0, grpcClass.length() - 2) : grpcClass;
        return generated.computeIfAbsent(generator, name -> context.findClass(name).map(this::read)
                .orElse(List.of()));
    }

    private List<GrpcMethod> read(JavaSootClass cls) {
        List<GrpcMethod> rpcs = new ArrayList<>();
        for (JavaSootMethod method : cls.getMethods()) {
            String name = method.getName();
            if (!method.isStatic() || !method.hasBody() || method.getParameterCount() != 0 || !name.startsWith("get")
                    || !name.endsWith("Method") || name.length() <= "getMethod".length()
                    || !(method.getReturnType() instanceof ClassType returned)
                    || !returned.getFullyQualifiedName().equals(METHOD_DESCRIPTOR)) {
                continue;
            }
            Optional<String> fullName = Optional.empty();
            boolean streaming = false;
            for (Stmt stmt : method.getBody().getStmts()) {
                Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                if (invoke.isPresent() && invoke.get().getMethodSignature().getName().equals("generateFullMethodName")
                        && invoke.get().getArgCount() == 2 && invoke.get().getArg(0) instanceof StringConstant service
                        && invoke.get().getArg(1) instanceof StringConstant rpc) {
                    fullName = Optional.of(service.getValue() + "/" + rpc.getValue());
                }
                if (stmt instanceof AbstractDefinitionStmt definition
                        && definition.getRightOp() instanceof JStaticFieldRef field
                        && field.getFieldSignature().getDeclClassType().getFullyQualifiedName()
                                .equals(METHOD_DESCRIPTOR + "$MethodType")) {
                    streaming |= STREAMING_TYPES.contains(field.getFieldSignature().getName());
                }
            }
            if (fullName.isEmpty()) {
                continue;
            }
            String rpc = name.substring("get".length(), name.length() - "Method".length());
            List<ClassFileMetadata.GenericType> types = context.classFiles().genericReturnType(method.getSignature())
                    .map(ClassFileMetadata.GenericType::arguments).orElse(List.of());
            rpcs.add(new GrpcMethod(fullName.get(), Character.toLowerCase(rpc.charAt(0)) + rpc.substring(1),
                    types.size() == 2 ? types.getLast().name() : null, streaming));
        }
        return rpcs;
    }
}
