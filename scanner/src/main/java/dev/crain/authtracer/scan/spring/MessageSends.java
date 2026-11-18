package dev.crain.authtracer.scan.spring;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.ClassType;
import sootup.core.types.Type;
import sootup.java.core.JavaSootMethod;

/**
 * Messages the code sends to a broker, as Egress the linker links to the listeners of the same name (decisions 0044,
 * 0047).
 */
@Supports(Feature.MESSAGE_SENDS)
final class MessageSends {

    private static final Set<String> KAFKA_TEMPLATES = Set.of("org.springframework.kafka.core.KafkaTemplate",
            "org.springframework.kafka.core.KafkaOperations");
    private static final Set<String> JMS_TEMPLATES = Set.of("org.springframework.jms.core.JmsTemplate",
            "org.springframework.jms.core.JmsOperations", "org.springframework.jms.core.JmsMessagingTemplate",
            "org.springframework.jms.core.JmsMessageOperations");
    private static final Set<String> RABBIT_TEMPLATES = Set.of("org.springframework.amqp.rabbit.core.RabbitTemplate",
            "org.springframework.amqp.rabbit.core.RabbitOperations", "org.springframework.amqp.core.AmqpTemplate");
    /**
     * The JMS and RabbitMQ template methods that send a message: a request that waits for its reply too.
     */
    private static final Set<String> SENDS = Set.of("send", "convertAndSend", "sendAndReceive",
            "convertSendAndReceive");
    private static final String STRING = "java.lang.String";
    private static final String OBJECT = "java.lang.Object";
    private static final String PRODUCER_RECORD = "org.apache.kafka.clients.producer.ProducerRecord";
    private static final String MESSAGING = "org.springframework.messaging.";
    private static final String MESSAGE = MESSAGING + "Message";
    private static final String MESSAGE_BUILDER = MESSAGING + "support.MessageBuilder";
    /**
     * {@code KafkaHeaders.TOPIC}, a constant the compiler copies into the code.
     */
    private static final String KAFKA_TOPIC = "kafka_topic";
    /**
     * How many calls a builder chain is followed back.
     */
    private static final int MAX_CHAIN = 16;

    private final ScanContext context;
    private final StreamFunctions stream;
    private final UnreadCalls unread;
    private final ConfiguredValues configured;

    MessageSends(ScanContext context, UnreadCalls unread, ConfiguredValues configured) {
        this.context = context;
        this.stream = new StreamFunctions(context);
        this.unread = unread;
        this.configured = configured;
    }

    /**
     * Decision 0044: a message sent to a topic, queue or destination: {@code KafkaTemplate.send} (its topic, or a
     * {@code ProducerRecord}'s) and {@code sendDefault} (Boot's {@code spring.kafka.template.default-topic}),
     * {@code JmsTemplate.convertAndSend}/{@code send}, and {@code RabbitTemplate.convertAndSend}/{@code send} on the
     * default exchange, whose routing key is the queue, and their request-reply {@code sendAndReceive} and
     * {@code convertSendAndReceive}. The linker links it to the listeners of that name. Decision 0082: a send whose
     * destination AuthTracer can't read (a parameter, a {@code Destination} object, the template's default, a named
     * exchange's bindings) is an Egress to {@link Egress#UNKNOWN_TARGET}.
     */
    Optional<Egress> detect(JavaSootMethod caller, Stmt stmt, AbstractInvokeExpr invoke) {
        String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = invoke.getMethodSignature().getName();
        List<String> parameters = invoke.getMethodSignature().getParameterTypes().stream().map(Object::toString)
                .toList();
        boolean named = !parameters.isEmpty() && parameters.getFirst().equals(STRING);
        if (StreamFunctions.isStreamBridge(owner) && named) {
            // Decision 0047: streamBridge.send("binding", payload), its only methods that take a String, each the
            // binding.
            Optional<String> binding = destination(caller, invoke.getArg(0));
            if (binding.isPresent()) {
                return stream.send(binding.get(), MethodNames.codeRef(caller.getSignature(), stmt))
                        .map(found -> found.withRequest(request(caller, invoke)));
            }
            return stream.binder(null).map(kind -> unread.egress("StreamBridge", kind, "binding", null, null, caller,
                    stmt, UnreadCalls.origin(caller, invoke.getArg(0)), null));
        }
        return templateSend(caller, stmt, invoke, owner, name, parameters, named).map(found -> found.uriTemplate()
                .equals(Egress.UNKNOWN_TARGET) ? found : found.withRequest(request(caller, invoke)));
    }

    /**
     * Decision 0090: the message a template send passes, its last {@code Object} parameter: Kafka's value
     * ({@code send(topic, [partition, [timestamp,]] [key,] value)}, {@code sendDefault(..)}), RabbitMQ's and JMS's
     * message (before a post-processor or correlation data), {@code StreamBridge}'s data. Decision 0098: a
     * {@code ProducerRecord}'s value, and a {@code Message}'s payload, when the method builds them; not RabbitMQ's
     * own {@code Message}, which holds bytes.
     */
    @Supports(Feature.FIELD_LINEAGE)
    static Optional<Value> payload(JavaSootMethod caller, AbstractInvokeExpr invoke) {
        List<Type> parameters = invoke.getMethodSignature().getParameterTypes();
        for (int i = parameters.size() - 1; i >= 0; i--) {
            String type = parameters.get(i).toString();
            if (type.equals(PRODUCER_RECORD)) {
                return constructor(caller, invoke.getArg(i)).map(MessageSends::recordValue);
            }
            if (type.equals(OBJECT) || type.equals(MESSAGE)) {
                Value value = invoke.getArg(i);
                return value.getType() instanceof ClassType held
                        && held.getFullyQualifiedName().startsWith(MESSAGING)
                                ? message(caller, value).map(Built::payload) : Optional.of(value);
            }
        }
        return Optional.empty();
    }

    /**
     * The type of the message a send passes, when it is an application type.
     */
    @Supports(Feature.FIELD_LINEAGE)
    private Payload request(JavaSootMethod caller, AbstractInvokeExpr invoke) {
        return payload(caller, invoke).filter(Local.class::isInstance).map(Value::getType)
                .filter(ClassType.class::isInstance).map(ClassType.class::cast).filter(context::isApplication)
                .map(type -> new Payload(type.getFullyQualifiedName(), false)).orElse(null);
    }

    /**
     * A {@code Message} the method builds, with its payload and the headers set on it:
     * {@code MessageBuilder.withPayload(p)[.setHeader(name, value)..].build()},
     * {@code MessageBuilder.createMessage(p, headers)}, {@code new GenericMessage<>(p[, headers])}, and
     * {@code MessageBuilder.fromMessage(m)}'s copy of one.
     *
     * @param headers each header a {@code setHeader} sets with a constant name, the last one set
     */
    private record Built(Value payload, Map<String, Value> headers) {
    }

    private static Optional<Built> message(JavaSootMethod caller, Value value) {
        Map<String, Value> headers = new HashMap<>();
        Value current = value;
        for (int i = 0; i < MAX_CHAIN && current instanceof Local local; i++) {
            Value definition = Locals.definition(caller.getBody(), local).orElse(null);
            if (definition instanceof JNewExpr) {
                // GenericMessage's (and ErrorMessage's) constructors take the payload first.
                return constructor(caller, local).map(init -> new Built(init.getArg(0), headers));
            }
            if (!(definition instanceof AbstractInvokeExpr call) || !call.getMethodSignature().getDeclClassType()
                    .getFullyQualifiedName().equals(MESSAGE_BUILDER)) {
                return Optional.empty();
            }
            String name = call.getMethodSignature().getName();
            if (name.equals("withPayload") || name.equals("createMessage")) {
                return Optional.of(new Built(call.getArg(0), headers));
            }
            if (name.equals("setHeader")) {
                // Read from build() back: the first one met is the last one set.
                Locals.text(call.getArg(0), Map.of()).ifPresent(header -> headers.putIfAbsent(header,
                        call.getArg(1)));
            }
            // fromMessage(message), the one other static method, copies the message it is given.
            current = call instanceof AbstractInstanceInvokeExpr instance ? instance.getBase() : call.getArg(0);
        }
        return Optional.empty();
    }

    private Optional<Egress> templateSend(JavaSootMethod caller, Stmt stmt, AbstractInvokeExpr invoke, String owner,
            String name, List<String> parameters, boolean named) {
        if (KAFKA_TEMPLATES.contains(owner) && (name.equals("send") || name.equals("sendDefault"))) {
            if (name.equals("sendDefault")) {
                return Optional.of(defaultTopic(owner, caller, stmt, "the template's default topic"));
            }
            if (parameters.getFirst().equals(MESSAGE)) {
                // Decision 0098: its kafka_topic header (KafkaHeaders.TOPIC), else the template's default topic
                // (MessagingMessageConverter#fromMessage).
                Optional<Value> header = message(caller, invoke.getArg(0))
                        .flatMap(built -> Optional.ofNullable(built.headers().get(KAFKA_TOPIC)));
                if (header.isPresent()) {
                    return Optional.of(sent(owner, MessageListeners.KAFKA, "topic", header.get(), caller, stmt,
                            null));
                }
                return Optional.of(defaultTopic(owner, caller, stmt, "a Message whose headers name it, else the"
                        + " template's default topic"));
            }
            // Else its other send: of a ProducerRecord.
            Value topic = named ? invoke.getArg(0) : recordTopic(caller, invoke.getArg(0));
            return Optional.of(sent(owner, MessageListeners.KAFKA, "topic", topic, caller, stmt,
                    "a ProducerRecord from " + UnreadCalls.origin(caller, invoke.getArg(0))));
        }
        if (JMS_TEMPLATES.contains(owner) && SENDS.contains(name)) {
            return Optional.of(sent(owner, MessageListeners.JMS, "destination", named ? invoke.getArg(0) : null,
                    caller, stmt, !parameters.isEmpty() && parameters.getFirst().equals("jakarta.jms.Destination")
                            ? "a Destination from " + UnreadCalls.origin(caller, invoke.getArg(0))
                            : "the template's default destination"));
        }
        if (RABBIT_TEMPLATES.contains(owner) && SENDS.contains(name)) {
            // (String routingKey, Object message, ..) or (String exchange, String routingKey, Object message, ..).
            boolean exchanged = named && invoke.getArgCount() >= 3 && parameters.get(1).equals(STRING);
            if (!exchanged) {
                return Optional.of(sent(owner, MessageListeners.RABBIT, "queue", named ? invoke.getArg(0) : null,
                        caller, stmt, "the template's default exchange and routing key"));
            }
            Optional<String> exchange = destination(caller, invoke.getArg(0));
            if (exchange.filter(String::isEmpty).isPresent()) {
                // The default exchange routes by queue name.
                return Optional.of(sent(owner, MessageListeners.RABBIT, "queue", invoke.getArg(1), caller, stmt,
                        null));
            }
            String routingKey = destination(caller, invoke.getArg(1)).orElse(Egress.UNKNOWN_TARGET);
            return Optional.of(unread.egress(MethodNames.simpleName(owner), MessageListeners.RABBIT, "queue", null,
                    null, caller, stmt, exchange.map(found -> "the bindings of the exchange " + found
                            + " for the routing key " + routingKey).orElseGet(() -> "an exchange from "
                                    + UnreadCalls.origin(caller, invoke.getArg(0))), null));
        }
        return Optional.empty();
    }

    /**
     * A send to Boot's {@code spring.kafka.template.default-topic}, else to {@link Egress#UNKNOWN_TARGET}.
     */
    private Egress defaultTopic(String owner, JavaSootMethod caller, Stmt stmt, String none) {
        return context.properties().getResolvingKnown("spring.kafka.template.default-topic")
                .map(topic -> egress(owner, MessageListeners.KAFKA, topic, caller, stmt))
                .orElseGet(() -> unread.egress(MethodNames.simpleName(owner), MessageListeners.KAFKA, "topic", null,
                        null, caller, stmt, none, null));
    }

    /**
     * A send to the destination the value names, else to {@link Egress#UNKNOWN_TARGET}.
     *
     * @param value the destination's value, {@code null} when the call names none
     * @param none why there is no destination when {@code value} is {@code null}
     */
    private Egress sent(String owner, String kind, String what, Value value, JavaSootMethod caller, Stmt stmt,
            String none) {
        Optional<String> destination = value == null ? Optional.empty() : destination(caller, value);
        return destination.map(found -> egress(owner, kind, found, caller, stmt))
                .orElseGet(() -> unread.egress(MethodNames.simpleName(owner), kind, what, null, null, caller, stmt,
                        value == null ? none : UnreadCalls.origin(caller, value), null));
    }

    private Egress egress(String owner, String kind, String destination, JavaSootMethod caller, Stmt stmt) {
        return Egress.of(MethodNames.simpleName(owner), kind, context.properties().resolveKnown(destination), null,
                null, MethodNames.codeRef(caller.getSignature(), stmt), null);
    }

    /**
     * A destination the code or the configuration names ({@link ConfiguredValues}): a constant, a {@code @Value}
     * parameter or field, a {@code @ConfigurationProperties} getter. One no file sets keeps its placeholder, which a
     * listener of the same {@code ${..}} name matches.
     */
    private Optional<String> destination(JavaSootMethod caller, Value value) {
        ConfiguredValues.Configured found = configured.of(caller, value);
        return Optional.ofNullable(found.value() != null ? found.value() : found.expression());
    }

    /**
     * {@code new ProducerRecord<>(topic, ..)}: each of its constructors takes the topic first.
     */
    private static Value recordTopic(JavaSootMethod caller, Value record) {
        return constructor(caller, record).map(init -> init.getArg(0)).orElse(null);
    }

    /**
     * A {@code ProducerRecord}'s value: its constructors' last {@code Object} parameter
     * ({@code (topic, [partition, [timestamp,]] [key,] value[, headers])}).
     */
    private static Value recordValue(AbstractInvokeExpr init) {
        return init.getArg(init.getMethodSignature().getParameterTypes().stream().map(Object::toString).toList()
                .lastIndexOf(OBJECT));
    }

    private static Optional<AbstractInvokeExpr> constructor(JavaSootMethod caller, Value created) {
        if (!(created instanceof Local local)
                || !(Locals.definition(caller.getBody(), local).orElse(null) instanceof JNewExpr)) {
            return Optional.empty();
        }
        return caller.getBody().getStmts().stream().flatMap(stmt -> Locals.invoke(stmt).stream())
                .filter(invoke -> invoke instanceof AbstractInstanceInvokeExpr instance
                        && instance.getBase().equals(local) && invoke.getMethodSignature().getName().equals("<init>"))
                .findFirst();
    }
}
