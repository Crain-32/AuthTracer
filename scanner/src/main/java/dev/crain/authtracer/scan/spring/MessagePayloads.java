package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.flow.ResponseFields;
import dev.crain.authtracer.scan.flow.Shape;
import dev.crain.authtracer.scan.flow.TypeProperties;
import dev.crain.authtracer.scan.flow.ValueFlow;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0090: what a message carries, at both ends. A send's payload is the fields of its type, filled by Flows
 * whose path is the send's Egress, from the fields it is built from on the way there: what the method sending it was
 * passed is what its callers on the walk pass. A listener's payload is the fields of its parameter's type. The linker
 * joins the two by JSON name. Decision 0098: what a listener writes of it into objects of other types, by Flows whose
 * path is the listener's Ingress.
 */
@Supports({Feature.MESSAGE_SENDS, Feature.MESSAGE_LISTENERS, Feature.FIELD_LINEAGE})
final class MessagePayloads {

    private static final Pattern SETTER = Pattern.compile("set\\p{Upper}.*");

    private final ValueFlow valueFlow;
    private final ResponseFields fields;
    private final TypeProperties properties;
    /**
     * Per payload type, the types it holds: its own and its fields', nested.
     */
    private final Map<String, Set<String>> held = new ConcurrentHashMap<>();

    MessagePayloads(ValueFlow valueFlow, ResponseFields fields, TypeProperties properties) {
        this.valueFlow = valueFlow;
        this.fields = fields;
        this.properties = properties;
    }

    /**
     * @param callers where each method on the walk was called from, innermost first
     */
    void sent(Egress egress, JavaSootMethod caller, AbstractInvokeExpr invoke, Iterator<AsyncCalls.Site> callers) {
        // A send has a request payload only when its message is one the method passes.
        if (egress.request() != null) {
            MessageSends.payload(caller, invoke).ifPresent(payload -> fields.expose(egress.id(),
                    egress.request().type(), resolved(valueFlow.argumentShape(caller, payload), caller, callers)));
        }
    }

    /**
     * Decision 0098: a Spring Cloud Stream function's result, which goes to its output binding.
     */
    void returned(Egress output, JavaSootMethod function) {
        if (output.request() != null) {
            fields.expose(output.id(), output.request().type(), valueFlow.returnShape(function));
        }
    }

    void received(Ingress listener) {
        if (listener.request() != null) {
            fields.expose(listener.id(), listener.request().type(), Shape.EMPTY);
        }
    }

    /**
     * Decision 0098: on a listener's path, an object of another application type the code creates
     * ({@code new Invoice(order.id(), ..)}, with the setters called on it there) or sets a property of
     * ({@code shipment.setCarrier(..)}) from what the listener received: its fields are filled by Flows whose path is
     * the listener's Ingress, from the payload's fields, as a send's are. What the service keeps of a message and
     * later serves comes from them. Objects built of none of the payload's fields aren't followed.
     */
    void written(Ingress listener, JavaSootMethod caller, AbstractInvokeExpr invoke,
            Iterator<AsyncCalls.Site> callers) {
        if (listener.request() == null || !(invoke instanceof AbstractInstanceInvokeExpr instance)) {
            return;
        }
        String type = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = invoke.getMethodSignature().getName();
        // A protobuf builder makes a message for a call the listener makes (decision 0032), not one it keeps.
        if (type.equals(listener.request().type()) || !properties.isApplicationType(type)
                || properties.isProtobufBuilder(type)) {
            return;
        }
        boolean created = Locals.created(caller.getBody(), instance.getBase()).isPresent();
        List<AsyncCalls.Site> sites = new ArrayList<>();
        callers.forEachRemaining(sites::add);
        Shape shape;
        if (name.equals("<init>") && created) {
            shape = onWalk(caller, instance.getBase(), sites);
        }
        else if (!created && invoke.getArgCount() == 1 && SETTER.matcher(name).matches()) {
            // A setter on an object the method didn't create here (one it loaded): only that property.
            Optional<TypeProperties.Property> property = properties.byName(type,
                    Character.toLowerCase(name.charAt(3)) + name.substring(4));
            if (property.isEmpty()) {
                return;
            }
            shape = new Shape.Composite(type, Map.of(property.get().name(), onWalk(caller, invoke.getArg(0),
                    sites)));
        }
        else {
            return;
        }
        Set<String> origins = new LinkedHashSet<>();
        Shape.collect(shape, origins, new LinkedHashSet<>());
        Set<String> received = held(listener.request().type());
        if (origins.stream().anyMatch(origin -> received.contains(Field.ownerOf(origin)))) {
            fields.expose(listener.id(), type, shape);
        }
    }

    /**
     * A value's shape on the walk: a method its caller on the walk calls (a factory, {@code Entry.of(change, dto)}) is
     * read with what the caller passes it, so the fields of a value whose fields are known (a DTO built from a call's
     * reply) are the fields it was built of; then in terms of what the callers further up pass.
     */
    private Shape onWalk(JavaSootMethod method, Value value, List<AsyncCalls.Site> sites) {
        AsyncCalls.Site first = sites.isEmpty() ? null : sites.getFirst();
        AbstractInvokeExpr call = first == null || first.method() == null ? null
                : Locals.invoke(first.stmt()).orElse(null);
        if (call != null && !(call instanceof JDynamicInvokeExpr) && method.getParameterCount() > 0
                && call.getArgCount() == method.getParameterCount()) {
            Shape read = valueFlow.argumentShape(method, value, valueFlow.argumentsAt(first.method(), call));
            return resolved(read, first.method(), sites.subList(1, sites.size()).iterator());
        }
        return resolved(valueFlow.argumentShape(method, value), method, sites.iterator());
    }

    /**
     * A shape in terms of the method's parameters, in terms of what its callers on the walk pass instead; a lambda's
     * in terms of what it captures and is handed where it is created (decision 0098).
     */
    private Shape resolved(Shape shape, JavaSootMethod method, Iterator<AsyncCalls.Site> callers) {
        JavaSootMethod current = method;
        // The walk's entry is the last site: its own parameters stay unread.
        while (!parameters(shape).isEmpty() && callers.hasNext()) {
            AsyncCalls.Site site = callers.next();
            if (site.method() == null) {
                break;
            }
            // A site is a call the walk followed.
            AbstractInvokeExpr call = Locals.invoke(site.stmt()).orElseThrow();
            shape = call instanceof JDynamicInvokeExpr lambda
                    ? valueFlow.atLambda(shape, current, site.method(), site.stmt(), lambda)
                    : valueFlow.atCallSite(shape, site.method(), call);
            current = site.method();
        }
        return shape;
    }

    private Set<String> held(String type) {
        return held.computeIfAbsent(type, key -> {
            Set<String> types = new HashSet<>();
            List<String> pending = new ArrayList<>(List.of(key));
            while (!pending.isEmpty()) {
                String next = pending.removeLast();
                if (types.add(next)) {
                    properties.of(next).forEach(property -> pending.add(Field.held(properties.heldType(next,
                            property))));
                }
            }
            return types;
        });
    }

    private static Set<Integer> parameters(Shape shape) {
        Set<Integer> parameters = new LinkedHashSet<>();
        Shape.collect(shape, new LinkedHashSet<>(), parameters);
        return parameters;
    }
}
