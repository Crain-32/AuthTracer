package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.ClassFileMetadata.GenericType;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0044: message-driven entry points. A {@code @KafkaListener}, {@code @RabbitListener} or
 * {@code @JmsListener} method handles what arrives on its topics, queues or destination: an Ingress
 * ({@code KAFKA orders}) whose route is the topic. Nobody authenticates a message, so no request rule applies; the
 * checks on its path are the method checks it reaches, which run without a caller ({@link NoCaller}). A class-level listener's
 * {@code @KafkaHandler}/{@code @RabbitHandler} methods share its topics.
 */
@Supports(Feature.MESSAGE_LISTENERS)
final class MessageListeners {

    static final String KAFKA = "KAFKA";
    static final String RABBIT = "RABBIT";
    static final String JMS = "JMS";
    private static final Set<String> KINDS = Set.of(KAFKA, RABBIT, JMS);
    private static final String KAFKA_LISTENER = "org.springframework.kafka.annotation.KafkaListener";
    private static final String KAFKA_HANDLER = "org.springframework.kafka.annotation.KafkaHandler";
    private static final String RABBIT_LISTENER = "org.springframework.amqp.rabbit.annotation.RabbitListener";
    private static final String RABBIT_HANDLER = "org.springframework.amqp.rabbit.annotation.RabbitHandler";
    private static final String JMS_LISTENER = "org.springframework.jms.annotation.JmsListener";
    private static final String MESSAGING = "org.springframework.messaging.handler.annotation.";
    private static final String PAYLOAD = MESSAGING + "Payload";
    private static final Set<String> HEADERS = Set.of(MESSAGING + "Header", MESSAGING + "Headers");
    /**
     * Packages of the parameters listener adapters fill with something other than the payload.
     */
    private static final List<String> FRAMEWORK = List.of("org.springframework.messaging.",
            "org.springframework.kafka.", "org.apache.kafka.", "org.springframework.amqp.", "com.rabbitmq.",
            "jakarta.jms.", "javax.jms.", "kotlin.coroutines.");
    private static final String CONSUMER_RECORD = "org.apache.kafka.clients.consumer.ConsumerRecord";
    private static final String CONSUMER_RECORDS = "org.apache.kafka.clients.consumer.ConsumerRecords";
    /**
     * The framework's parameters that carry the payload whole: a record, a message, a batch of records.
     */
    private static final Set<String> CARRIERS = Set.of(CONSUMER_RECORD, CONSUMER_RECORDS,
            "org.springframework.messaging.Message");
    /**
     * Carriers of one value, its type their last type argument.
     */
    private static final Set<String> ONE = Set.of("org.springframework.messaging.Message",
            "reactor.core.publisher.Mono", "java.util.Optional", CONSUMER_RECORD);
    /**
     * Carriers of many values.
     */
    private static final Set<String> MANY = Set.of("java.util.List", "java.util.Collection", "java.util.Set",
            "java.lang.Iterable", "reactor.core.publisher.Flux", CONSUMER_RECORDS);

    private final ScanContext context;
    private final List<Finding> findings = new ArrayList<>();

    MessageListeners(ScanContext context) {
        this.context = context;
    }

    /**
     * Listeners {@link #detect()} found no destination for.
     */
    List<Finding> findings() {
        return findings;
    }

    static boolean isListener(Ingress ingress) {
        return KINDS.contains(ingress.httpMethod());
    }

    /**
     * Several consumers of one topic in a service (in different groups, each gets every message) are told apart by
     * handler: {@code KAFKA orders?handler=Billing.onOrder}.
     */
    static List<RequestMappings.Mapping> distinct(List<RequestMappings.Mapping> mappings) {
        Map<String, Long> handlers = mappings.stream().filter(mapping -> isListener(mapping.ingress()))
                .collect(Collectors.groupingBy(mapping -> mapping.ingress().id(),
                        Collectors.mapping(RequestMappings.Mapping::handler, Collectors.toSet())))
                .entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, entry -> (long) entry.getValue()
                        .size()));
        return mappings.stream().map(mapping -> !isListener(mapping.ingress())
                || handlers.getOrDefault(mapping.ingress().id(), 1L) < 2 ? mapping
                        : mapping.withIngress(mapping.ingress().andParams("handler="
                                + simpleName(mapping.handler().getDeclaringClassType().getFullyQualifiedName()) + "."
                                + methodName(mapping.handler().getName())))).toList();
    }

    /**
     * A lambda's body ({@code lambda$shipOrders$0}) by the method it is written in.
     */
    private static String methodName(String name) {
        return name.startsWith("lambda$") ? name.split("\\$")[1] : name;
    }

    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    List<RequestMappings.Mapping> detect() {
        List<RequestMappings.Mapping> mappings = new ArrayList<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            List<String> classTopics = context.findAnnotation(cls, KAFKA_LISTENER).map(this::kafkaTopics)
                    .orElse(List.of());
            List<String> classQueues = context.findAnnotation(cls, RABBIT_LISTENER).map(this::rabbitQueues)
                    .orElse(List.of());
            // A class-level listener's handlers are picked by the payload's type, which tells them apart.
            long handlers = cls.getMethods().stream().filter(method -> context.hasAnnotation(method, KAFKA_HANDLER)
                    || context.hasAnnotation(method, RABBIT_HANDLER)).count();
            for (JavaSootMethod method : cls.getMethods()) {
                if (RequestMappings.suspendImpl(method)) {
                    continue;
                }
                List<AnnotationUsage> kafka = repeated(method, KAFKA_LISTENER);
                List<AnnotationUsage> rabbit = repeated(method, RABBIT_LISTENER);
                boolean handler = context.hasAnnotation(method, KAFKA_HANDLER)
                        || context.hasAnnotation(method, RABBIT_HANDLER);
                String payload = handler && handlers > 1 && method.getParameterCount() > 0
                        ? "payload=" + simpleName(method.getParameterType(0).toString()) : null;
                List<String> topics = !kafka.isEmpty() ? kafka.stream().flatMap(found -> kafkaTopics(found).stream())
                        .distinct().toList() : context.hasAnnotation(method, KAFKA_HANDLER) ? classTopics : List.of();
                List<String> queues = !rabbit.isEmpty() ? rabbit.stream()
                        .flatMap(found -> rabbitQueues(found).stream()).distinct().toList()
                        : context.hasAnnotation(method, RABBIT_HANDLER) ? classQueues : List.of();
                topics.forEach(topic -> mappings.add(mapping(KAFKA, topic, payload, method)));
                queues.forEach(queue -> mappings.add(mapping(RABBIT, queue, payload, method)));
                if (!kafka.isEmpty() && topics.isEmpty() || !rabbit.isEmpty() && queues.isEmpty()) {
                    findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The listener "
                            + MethodNames.key(method.getSignature()) + " names no topic or queue AuthTracer can"
                            + " read (a server-named queue, or one set at runtime): what it handles isn't on the"
                            + " graph", MethodNames.codeRef(method.getSignature())));
                }
                repeated(method, JMS_LISTENER).stream()
                        .flatMap(annotation -> Annotations.string(annotation, "destination").stream())
                        .map(this::resolve).distinct()
                        .forEach(destination -> mappings.add(mapping(JMS, destination, null, method)));
            }
        }
        return mappings;
    }

    /**
     * A repeatable listener annotation on the method, also when repeated (in its container, e.g.
     * {@code @KafkaListeners}).
     */
    private List<AnnotationUsage> repeated(JavaSootMethod method, String annotation) {
        List<AnnotationUsage> found = new ArrayList<>();
        context.findAnnotation(method, annotation).ifPresent(found::add);
        context.findAnnotation(method, annotation + "s")
                .ifPresent(container -> found.addAll(Annotations.nested(container, "value")));
        return found;
    }

    private RequestMappings.Mapping mapping(String kind, String destination, String payload,
            JavaSootMethod method) {
        // The response is preset, to none: a listener answers nobody (a @SendTo reply is a message of its own).
        return new RequestMappings.Mapping(Ingress.of(kind, destination, MethodNames.codeRef(method.getSignature()))
                .withParams(payload).withRequest(request(method)), method, true);
    }

    /**
     * Decision 0090: what the listener receives, when it is an application type: its {@code @Payload} parameter,
     * else the first one Spring's {@code PayloadMethodArgumentResolver} takes, neither a {@code @Header(s)} nor one of
     * the framework's own (an acknowledgment, a channel or session). Decision 0098: else the record or message it
     * takes whole, whose value is the payload ({@code ConsumerRecord<K, V>}'s {@code V}, {@code Message<T>}'s
     * {@code T}); a batch ({@code List<T>}, {@code ConsumerRecords<K, V>}) receives many.
     */
    @Supports(Feature.FIELD_LINEAGE)
    private Payload request(JavaSootMethod method) {
        Integer payload = null;
        Integer carrier = null;
        for (int i = method.getParameterCount() - 1; i >= 0; i--) {
            Set<String> annotations = context.classFiles().parameterAnnotations(method.getSignature(), i);
            String type = method.getParameterType(i).toString();
            if (annotations.contains(PAYLOAD)) {
                payload = i;
                break;
            }
            if (annotations.stream().anyMatch(HEADERS::contains)) {
                continue;
            }
            if (FRAMEWORK.stream().noneMatch(type::startsWith)) {
                payload = i;
            }
            else if (CARRIERS.contains(type)) {
                carrier = i;
            }
        }
        List<GenericType> generic = context.classFiles().genericParameterTypes(method.getSignature());
        return Optional.ofNullable(payload != null ? payload : carrier)
                .map(chosen -> generic.size() == method.getParameterCount() ? generic.get(chosen)
                        : new GenericType(method.getParameterType(chosen).toString(), List.of()))
                .map(type -> payload(context, type, false)).orElse(null);
    }

    /**
     * Decision 0098: the application type a message holds, out of what carries it: a Kafka record's value, a
     * {@code Message}'s payload, a {@code Mono}'s value; and a batch's or a stream's ({@code List}, a {@code Flux},
     * {@code ConsumerRecords}) many of them. {@code null} when it is none of the application's types.
     */
    @Supports(Feature.FIELD_LINEAGE)
    static Payload payload(ScanContext context, GenericType type, boolean many) {
        // The held type is the last type argument: a record's value, a message's payload, a batch's element. A raw
        // type holds none AuthTracer can name.
        Optional<GenericType> held = type.arguments().stream().reduce((first, second) -> second);
        if (MANY.contains(type.name()) || ONE.contains(type.name())) {
            return held.map(found -> payload(context, found, many || MANY.contains(type.name()))).orElse(null);
        }
        if (type.name().endsWith("[]")) {
            return payload(context, new GenericType(type.name().substring(0, type.name().length() - 2), List.of()),
                    true);
        }
        // A type variable's name is no class.
        return context.isApplication(context.type(type.name())) ? new Payload(type.name(), many) : null;
    }

    private static String simpleName(String type) {
        return type.substring(Math.max(type.lastIndexOf('.'), type.lastIndexOf('$')) + 1);
    }

    /**
     * {@code topics}, {@code topicPattern}, and each {@code @TopicPartition}'s {@code topic}.
     */
    private List<String> kafkaTopics(AnnotationUsage listener) {
        List<String> topics = new ArrayList<>(Annotations.strings(listener, "topics"));
        Annotations.string(listener, "topicPattern").filter(pattern -> !pattern.isEmpty()).ifPresent(topics::add);
        Annotations.nested(listener, "topicPartitions").forEach(partition -> Annotations.string(partition, "topic")
                .filter(topic -> !topic.isEmpty()).ifPresent(topics::add));
        return topics.stream().map(this::resolve).distinct().toList();
    }

    /**
     * {@code queues}, and the {@code @Queue} of each {@code bindings} {@code @QueueBinding} and of
     * {@code queuesToDeclare}: its {@code value} or {@code name} (none for a queue the broker names).
     */
    private List<String> rabbitQueues(AnnotationUsage listener) {
        List<String> queues = new ArrayList<>(Annotations.strings(listener, "queues"));
        List<AnnotationUsage> declared = new ArrayList<>(Annotations.nested(listener, "queuesToDeclare"));
        Annotations.nested(listener, "bindings").forEach(binding -> declared.addAll(Annotations.nested(binding,
                "value")));
        for (AnnotationUsage queue : declared) {
            Annotations.string(queue, "value").filter(name -> !name.isEmpty())
                    .or(() -> Annotations.string(queue, "name").filter(name -> !name.isEmpty()))
                    .ifPresent(queues::add);
        }
        return queues.stream().map(this::resolve).distinct().toList();
    }

    /**
     * {@code ${app.topic}} from the application's properties, or as written when it can't be resolved.
     */
    private String resolve(String name) {
        return context.properties().resolveKnown(name);
    }
}
