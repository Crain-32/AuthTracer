package dev.crain.authtracer.scan.flow;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.ClassFileMetadata.GenericType;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ArrayType;
import sootup.core.types.ClassType;

/**
 * Body types, unwrapped from the containers frameworks put around them.
 */
@Supports({Feature.RESPONSE_FIELDS, Feature.FIELD_LINEAGE})
public final class Payloads {

    private static final Set<String> WRAPPERS = Set.of("java.util.Optional",
            "java.util.concurrent.CompletableFuture", "java.util.concurrent.CompletionStage",
            "java.util.concurrent.Callable", "org.springframework.http.ResponseEntity",
            "org.springframework.http.HttpEntity", "org.springframework.core.ParameterizedTypeReference",
            "reactor.core.publisher.Mono",
            // Spring MVC's asynchronous results.
            "org.springframework.web.context.request.async.DeferredResult",
            "org.springframework.web.context.request.async.WebAsyncTask",
            // JAX-RS's Response names no body type (decision 0052).
            "jakarta.ws.rs.core.Response",
            // Spring HATEOAS writes its content unwrapped (@JsonUnwrapped getContent), next to _links.
            "org.springframework.hateoas.EntityModel");
    /** Containers of many, by name, for when their classes aren't on the classpath to follow. */
    private static final Set<String> COLLECTIONS = Set.of("java.util.List", "java.util.Set",
            "java.util.Collection", "java.lang.Iterable", "java.util.stream.Stream", "reactor.core.publisher.Flux",
            "kotlinx.coroutines.flow.Flow");

    private static final String CONTINUATION = "kotlin.coroutines.Continuation";
    private static final String PUBLISHER = "org.reactivestreams.Publisher";
    private static final int MAX_DEPTH = 8;

    private Payloads() {
    }

    /**
     * The response body a handler method returns: an object, or an array of them ({@code Employee[]}).
     */
    public static Optional<Payload> returnedBy(ScanContext context, MethodSignature method) {
        return declared(context, method).flatMap(type -> unwrap(context, type, false));
    }

    /**
     * A response body that stays a library type with one of the application's types among its arguments, e.g. a
     * library's {@code Envelope<Employee>}: what Jackson writes of it isn't known, so its fields aren't in the graph.
     */
    public static Optional<String> unread(ScanContext context, MethodSignature method) {
        return declared(context, method).flatMap(type -> body(context, type, false, 0)).map(Body::type)
                .filter(type -> !context.isApplication(context.type(type.name())) && mentionsApplication(context,
                        type)).map(Payloads::text);
    }

    public static Optional<Payload> unwrap(ScanContext context, GenericType type, boolean many) {
        return body(context, type, many, 0).map(body -> new Payload(body.type().name(), body.many()));
    }

    private static Optional<GenericType> declared(ScanContext context, MethodSignature method) {
        String declared = switch (method.getType()) {
            case ClassType type -> type.getFullyQualifiedName();
            case ArrayType array -> array.toString();
            default -> null;
        };
        if (declared == null) {
            return Optional.empty();
        }
        // A Kotlin suspend function returns Object; its real result type is its Continuation's type argument.
        List<GenericType> parameters = context.classFiles().genericParameterTypes(method);
        if (!parameters.isEmpty() && parameters.getLast().name().equals(CONTINUATION)
                && !parameters.getLast().arguments().isEmpty()) {
            return Optional.of(parameters.getLast().arguments().getFirst());
        }
        return Optional.of(context.classFiles().genericReturnType(method)
                .orElse(new GenericType(declared, List.of())));
    }

    /**
     * Through wrappers to what they hold, and through collections, maps' values, streams and publishers (a
     * {@code Page}, an {@code ArrayList}, a {@code Flux}) to their elements, many of them. A {@code Page}'s elements
     * are written under its {@code content}, a map's under their keys: the fields are the elements', wherever they
     * sit.
     */
    private static Optional<Body> body(ScanContext context, GenericType type, boolean many, int depth) {
        if (type.name().endsWith("[]")) {
            return Optional.of(new Body(new GenericType(type.name().substring(0, type.name().length() - 2),
                    List.of()), true));
        }
        if (WRAPPERS.contains(type.name()) || COLLECTIONS.contains(type.name())) {
            return type.arguments().isEmpty() || depth > MAX_DEPTH ? Optional.empty()
                    : body(context, type.arguments().getFirst(), many || COLLECTIONS.contains(type.name()),
                            depth + 1);
        }
        if (!type.arguments().isEmpty() && depth <= MAX_DEPTH && !context.isApplication(context.type(type.name()))) {
            GenericTypes generics = new GenericTypes(context);
            GenericType element = generics.element(type);
            if (element == type) {
                element = generics.as(type, PUBLISHER).filter(publisher -> !publisher.arguments().isEmpty())
                        .map(publisher -> publisher.arguments().getFirst()).orElse(type);
            }
            if (element != type) {
                return body(context, element, true, depth + 1);
            }
        }
        return Optional.of(new Body(type, many));
    }

    private static boolean mentionsApplication(ScanContext context, GenericType type) {
        return type.arguments().stream().anyMatch(argument -> context.isApplication(context.type(argument.name()))
                || mentionsApplication(context, argument));
    }

    private static String text(GenericType type) {
        return type.arguments().isEmpty() ? type.name() : type.name() + "<" + String.join(", ",
                type.arguments().stream().map(Payloads::text).toList()) + ">";
    }

    private record Body(GenericType type, boolean many) {
    }
}
