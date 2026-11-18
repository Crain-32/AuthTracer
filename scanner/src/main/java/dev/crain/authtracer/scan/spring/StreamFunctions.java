package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.ClassFileMetadata.GenericType;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0047: Spring Cloud Stream's functional bindings (5.0). The functions bound are those
 * {@code spring.cloud.stream.function.definition} or {@code spring.cloud.function.definition} names ({@code ;}
 * between functions, {@code |} composing them), or, without a definition, the only function bean there is
 * ({@code FunctionBindingRegistrar}). A {@code Consumer}'s or {@code Function}'s input binding {@code <name>-in-0}
 * receives from its destination ({@code spring.cloud.stream.bindings.<binding>.destination}, by default the binding's
 * name): an Ingress like a listener's ({@code KAFKA orders}, by the binder), handled by the function's lambda or
 * method reference. A {@code Function}'s result and a {@code Supplier}'s values (polled: a scheduled entry point) go
 * to {@code <name>-out-0}'s destination: an Egress. {@code StreamBridge.send(binding, ..)} sends to the binding's
 * destination, or to the destination of that name.
 */
@Supports({Feature.MESSAGE_LISTENERS, Feature.MESSAGE_SENDS})
final class StreamFunctions {

    private static final String STREAM_BRIDGE = "org.springframework.cloud.stream.function.StreamBridge";
    private static final String STREAM_OPERATIONS = "org.springframework.cloud.stream.function.StreamOperations";
    private static final String KAFKA_BINDER = "org.springframework.cloud.stream.binder.kafka.KafkaMessageChannelBinder";
    private static final String RABBIT_BINDER =
            "org.springframework.cloud.stream.binder.rabbit.RabbitMessageChannelBinder";
    private static final String KOTLIN_FUNCTION = "kotlin.jvm.functions.Function";
    private static final Map<String, String> FUNCTIONS = Map.of("java.util.function.Consumer", "Consumer",
            "java.util.function.Function", "Function", "java.util.function.Supplier", "Supplier");

    /**
     * A bound function: what receives (null for a supplier), and where its values go.
     */
    record Binding(RequestMappings.Mapping mapping, List<Egress> outputs, List<JavaSootMethod> composed) {

        /**
         * Which binding a mapping is, however its Ingress is renamed later.
         */
        static String key(RequestMappings.Mapping mapping) {
            return mapping.handler().getSignature() + " " + mapping.ingress().httpMethod() + " "
                    + mapping.ingress().route();
        }
    }

    private final ScanContext context;

    StreamFunctions(ScanContext context) {
        this.context = context;
    }

    /**
     * {@code StreamBridge}, or {@code StreamOperations}, the interface it implements, which a field may be typed as.
     */
    static boolean isStreamBridge(String owner) {
        return owner.equals(STREAM_BRIDGE) || owner.equals(STREAM_OPERATIONS);
    }

    List<Binding> detect() {
        List<Binding> bindings = new ArrayList<>();
        if (context.findClass(STREAM_BRIDGE).isEmpty() || binder(null).isEmpty()) {
            return bindings;
        }
        Map<String, Fn> functions = functions();
        List<String> definitions = context.properties().get("spring.cloud.stream.function.definition")
                .or(() -> context.properties().get("spring.cloud.function.definition"))
                .map(definition -> Arrays.stream(definition.split(";")).map(String::trim).toList())
                .orElse(functions.size() == 1 ? List.copyOf(functions.keySet()) : List.of());
        for (String definition : definitions) {
            List<Fn> composed = Arrays.stream(definition.split("[|,]")).map(String::trim)
                    .map(functions::get).toList();
            // A name the application has no function bean for (an empty one, between two ;s, too) binds nothing.
            if (composed.isEmpty() || composed.contains(null)) {
                continue;
            }
            String name = definition.replaceAll("[|,\\s]", "");
            Fn first = composed.getFirst();
            Fn last = composed.getLast();
            List<Egress> outputs = new ArrayList<>();
            if (!last.kind().equals("Consumer")) {
                String out = name + "-out-0";
                binder(out).ifPresent(kind -> destinations(out).forEach(destination -> outputs.add(Egress.of(
                        "Spring Cloud Stream", kind, destination, null, null,
                        MethodNames.codeRef(last.handler().getSignature()), null).withRequest(carried(last, false)))));
            }
            if (first.kind().equals("Supplier")) {
                // Polled by the binder: nobody calls it.
                bindings.add(new Binding(new RequestMappings.Mapping(ScheduledTasks.ingress(first.declaration()),
                        first.handler(), true), outputs, rest(composed)));
                continue;
            }
            String in = name + "-in-0";
            Optional<String> kind = binder(in);
            if (kind.isEmpty()) {
                continue;
            }
            for (String destination : destinations(in)) {
                bindings.add(new Binding(new RequestMappings.Mapping(Ingress.of(kind.get(), destination,
                        MethodNames.codeRef(first.handler().getSignature())).withRequest(carried(first, true)),
                        first.handler(), true), outputs, rest(composed)));
            }
        }
        return bindings;
    }

    /**
     * A function bean: {@code Consumer}, {@code Function} or {@code Supplier}; where it is declared (a {@code @Bean}
     * method, or the component class's method), and the code it runs.
     */
    private record Fn(String kind, JavaSootMethod declaration, JavaSootMethod handler) {
    }

    /**
     * The function beans by name: {@code @Bean} methods returning a {@code java.util.function} type or a Kotlin
     * function type ({@code () -> T} a supplier, {@code (T) -> Unit} a consumer, {@code (T) -> R} a function), and
     * components implementing one, named as Spring names the bean.
     */
    private Map<String, Fn> functions() {
        Map<String, Fn> functions = new LinkedHashMap<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!context.hasAnnotation(method, SpringNames.BEAN) || !(method.getReturnType() instanceof ClassType
                        type)) {
                    continue;
                }
                String kind = FUNCTIONS.get(type.getFullyQualifiedName());
                if (kind == null && type.getFullyQualifiedName().equals(KOTLIN_FUNCTION + "0")) {
                    kind = "Supplier";
                }
                else if (kind == null && type.getFullyQualifiedName().equals(KOTLIN_FUNCTION + "1")) {
                    kind = context.classFiles().genericReturnType(method.getSignature())
                            .filter(generic -> generic.arguments().size() == 2
                                    && generic.arguments().getLast().name().equals("kotlin.Unit"))
                            .isPresent() ? "Consumer" : "Function";
                }
                if (kind != null) {
                    String name = context.findAnnotation(method, SpringNames.BEAN).flatMap(bean -> Annotations
                            .string(bean, "name").or(() -> Annotations.string(bean, "value"))).filter(found -> !found
                                    .isEmpty()).orElse(method.getName());
                    functions.put(name, new Fn(kind, method, handler(method).orElse(method)));
                }
            }
            if (!context.hasAnnotation(cls, SpringNames.COMPONENT)) {
                continue;
            }
            for (ClassType implemented : context.interfacesOf(cls.getType())) {
                String kind = FUNCTIONS.get(implemented.getFullyQualifiedName());
                Optional<JavaSootMethod> body = Optional.ofNullable(kind).flatMap(found -> implementation(cls, found));
                body.ifPresent(found -> functions.put(SpringBeans.beanName(context, cls), new Fn(kind, found, found)));
            }
        }
        return functions;
    }

    /**
     * Decision 0098: what the function takes or gives, when it is an application type: the bean method's
     * {@code Consumer<T>}, {@code Function<T, R>} or {@code Supplier<R>} type argument (a Kotlin function type's
     * too), or the component's {@code accept}/{@code apply} parameter or {@code get}/{@code apply} result; out of a
     * {@code Message}, and many of them from a {@code Flux} or a collection.
     *
     * @param input what it takes, else what it gives
     */
    @Supports(Feature.FIELD_LINEAGE)
    private Payload carried(Fn fn, boolean input) {
        Optional<GenericType> type;
        if (context.hasAnnotation(fn.declaration(), SpringNames.BEAN)) {
            type = context.classFiles().genericReturnType(fn.declaration().getSignature())
                    .flatMap(generic -> input ? generic.arguments().stream().findFirst()
                            : generic.arguments().stream().reduce((first, second) -> second));
        }
        else {
            // A component's typed accept or apply takes one value.
            JavaSootMethod method = fn.handler();
            type = input ? context.classFiles().genericParameterTypes(method.getSignature()).stream().findFirst()
                    .or(() -> Optional.of(new GenericType(method.getParameterType(0).toString(), List.of())))
                    : context.classFiles().genericReturnType(method.getSignature())
                            .or(() -> Optional.of(new GenericType(method.getReturnType().toString(), List.of())));
        }
        return type.map(found -> MessageListeners.payload(context, found, false)).orElse(null);
    }

    /**
     * The component's {@code accept}, {@code apply} or {@code get}: the typed one, not the bridge.
     */
    private static Optional<JavaSootMethod> implementation(JavaSootClass cls, String kind) {
        String name = switch (kind) {
            case "Consumer" -> "accept";
            case "Function" -> "apply";
            default -> "get";
        };
        return cls.getMethods().stream().filter(method -> method.getName().equals(name) && method.hasBody())
                .min(Comparator.comparing((JavaSootMethod method) -> method.getParameterTypes().stream()
                        .allMatch(parameter -> parameter.toString().equals("java.lang.Object"))
                        && method.getParameterCount() > 0));
    }

    /**
     * {@code streamBridge.send("orders-out-0", order)}: the binding's destination, or the destination of that name.
     */
    Optional<Egress> send(String binding, CodeRef callSite) {
        return binder(binding).map(kind -> Egress.of("StreamBridge", kind, destinations(binding).getFirst(), null,
                null, callSite, null));
    }

    /**
     * The binding's destinations, comma-separated for a consumer; by default the binding's name.
     */
    private List<String> destinations(String binding) {
        List<String> configured = context.properties()
                .getResolvingKnown("spring.cloud.stream.bindings." + binding + ".destination").stream()
                .flatMap(value -> Arrays.stream(value.split(","))).map(String::trim)
                .filter(found -> !found.isEmpty()).toList();
        return configured.isEmpty() ? List.of(binding) : configured;
    }

    /**
     * The functions a composition runs after its first, walked on the same path.
     */
    private static List<JavaSootMethod> rest(List<Fn> composed) {
        return composed.subList(1, composed.size()).stream().map(Fn::handler).toList();
    }

    /**
     * {@code KAFKA} or {@code RABBIT}: the binding's binder, the default binder, else the binder on the classpath.
     */
    Optional<String> binder(String binding) {
        Optional<String> named = Optional.ofNullable(binding)
                .flatMap(found -> context.properties().get("spring.cloud.stream.bindings." + found + ".binder"))
                .or(() -> context.properties().get("spring.cloud.stream.default-binder"));
        if (named.isPresent()) {
            String binder = named.get().toLowerCase(Locale.ROOT);
            return binder.contains("kafka") ? Optional.of(MessageListeners.KAFKA)
                    : binder.contains("rabbit") ? Optional.of(MessageListeners.RABBIT) : Optional.empty();
        }
        return context.findClass(KAFKA_BINDER).isPresent() ? Optional.of(MessageListeners.KAFKA)
                : context.findClass(RABBIT_BINDER).isPresent() ? Optional.of(MessageListeners.RABBIT)
                        : Optional.empty();
    }

    /**
     * The code the function runs: the lambda or method reference the bean method returns.
     */
    private Optional<JavaSootMethod> handler(JavaSootMethod bean) {
        if (!bean.hasBody()) {
            return Optional.empty();
        }
        return bean.getBody().getStmts().stream().filter(AbstractDefinitionStmt.class::isInstance)
                .map(stmt -> ((AbstractDefinitionStmt) stmt).getRightOp())
                .filter(JDynamicInvokeExpr.class::isInstance).map(JDynamicInvokeExpr.class::cast)
                .flatMap(dynamic -> dynamic.getBootstrapArgs().stream())
                .filter(MethodHandle.class::isInstance).map(handle -> ((MethodHandle) handle).getReferenceSignature())
                .filter(MethodSignature.class::isInstance).map(MethodSignature.class::cast)
                .filter(target -> context.isApplication(target.getDeclClassType()))
                .map(context::findMethod).flatMap(Optional::stream).findFirst();
    }
}
