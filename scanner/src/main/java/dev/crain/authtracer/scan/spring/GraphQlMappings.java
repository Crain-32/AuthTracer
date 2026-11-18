package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.ClassFileMetadata;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.types.ClassType;
import sootup.core.types.Type;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0029: Spring for GraphQL operations as Ingress. A {@code @QueryMapping}, {@code @MutationMapping} or
 * {@code @SubscriptionMapping} controller method, or a {@code @SchemaMapping} on the {@code Query}, {@code Mutation}
 * or {@code Subscription} type, is the Ingress {@code QUERY employee}. Every operation arrives as
 * {@code POST <spring.graphql.http.path>} (default {@code /graphql}), which request-level rules match.
 */
@Supports(Feature.GRAPHQL_OPERATIONS)
final class GraphQlMappings {

    private static final String PACKAGE = "org.springframework.graphql.data.method.annotation.";
    private static final Map<String, String> OPERATIONS = Map.of(PACKAGE + "QueryMapping", "Query",
            PACKAGE + "MutationMapping", "Mutation", PACKAGE + "SubscriptionMapping", "Subscription");
    private static final String SCHEMA_MAPPING = PACKAGE + "SchemaMapping";
    private static final String BATCH_MAPPING = PACKAGE + "BatchMapping";
    private static final Set<String> ROOT_TYPES = Set.of("Query", "Mutation", "Subscription");
    /**
     * Parameters that aren't the source object: GraphQL arguments, context values, the principal.
     */
    private static final Set<String> NOT_SOURCE = Set.of(PACKAGE + "Argument", PACKAGE + "Arguments",
            PACKAGE + "ContextValue", PACKAGE + "LocalContextValue",
            "org.springframework.security.core.annotation.AuthenticationPrincipal");
    private static final Set<String> MANY = Set.of("java.util.List", "java.util.Set", "java.util.Collection",
            "java.lang.Iterable", "reactor.core.publisher.Flux");
    private static final Set<String> SINGLE = Set.of("java.util.Optional", "java.util.concurrent.CompletableFuture",
            "reactor.core.publisher.Mono", "java.util.concurrent.Callable");

    private final ScanContext context;

    GraphQlMappings(ScanContext context) {
        this.context = context;
    }

    List<RequestMappings.Mapping> detect(SpringBeans beans) {
        List<RequestMappings.Mapping> mappings = new ArrayList<>();
        String path = context.properties().get("spring.graphql.http.path").orElse("/graphql");
        // Spring Boot serves GraphQL over WebSocket too once the path is set (decision 0034).
        Optional<String> webSocketPath = context.properties().get("spring.graphql.websocket.path");
        for (JavaSootClass cls : context.applicationClasses()) {
            if (!beans.isController(cls)) {
                continue;
            }
            Optional<String> classType = context.findAnnotation(cls, SCHEMA_MAPPING)
                    .flatMap(mapping -> Annotations.string(mapping, "typeName")).filter(name -> !name.isEmpty());
            for (JavaSootMethod method : cls.getMethods()) {
                operation(method, classType).ifPresent(operation -> {
                    Ingress ingress = Ingress.of(operation.type().toUpperCase(Locale.ROOT), operation.field(),
                            MethodNames.codeRef(method.getSignature()));
                    mappings.add(new RequestMappings.Mapping(ingress, method, false,
                            Ingress.of("POST", RequestMappings.join("", path), ingress.handler()),
                            webSocketPath.map(socket -> Ingress.of("GET", RequestMappings.join("", socket),
                                    ingress.handler())).orElse(null)));
                });
            }
        }
        return mappings;
    }

    private record Operation(String type, String field) {
    }

    private static final Set<String> WEBSOCKET_AUTHENTICATION = Set.of(
            "org.springframework.graphql.server.webmvc.AuthenticationWebSocketInterceptor",
            "org.springframework.graphql.server.webflux.AuthenticationWebSocketInterceptor");

    /**
     * Decision 0034: an {@code AuthenticationWebSocketInterceptor} bean authenticates a GraphQL WebSocket connection
     * from its {@code connection_init} payload, and closes it when that fails: the operations on it need an
     * authenticated caller.
     */
    Optional<AuthorizationLocation> webSocketAuthentication(GraphBuilder graph) {
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody() || !context.hasAnnotation(method, SpringNames.BEAN)) {
                    continue;
                }
                boolean creates = method.getBody().getStmts().stream()
                        .filter(AbstractDefinitionStmt.class::isInstance).map(AbstractDefinitionStmt.class::cast)
                        .anyMatch(definition -> definition.getRightOp() instanceof JNewExpr created
                                && WEBSOCKET_AUTHENTICATION.contains(created.getType().getFullyQualifiedName()));
                if (creates) {
                    return Optional.of(graph.node(new AuthorizationLocation(
                            "location:HTTP_REQUEST:graphql-websocket:" + MethodNames.key(method.getSignature()),
                            "AuthenticationWebSocketInterceptor (GraphQL over WebSocket)",
                            AuthorizationLocation.Scope.HTTP_REQUEST, AuthorizationLocation.Phase.PRE,
                            Requirement.authenticated(), MethodNames.codeRef(method.getSignature()), null, null,
                            AuthorizationLocation.Denial.THROW, false)));
                }
            }
        }
        return Optional.empty();
    }

    /**
     * A resolver of a non-root type's field: {@code @SchemaMapping(typeName = "Person", field = "salary")}, or a
     * {@code @BatchMapping} that resolves the field for many sources at once.
     *
     * @param graphQlType the schema type, e.g. {@code Person}
     * @param owner the Java type of the source objects
     * @param javaType the Java type of the field's value, or {@code ?}
     */
    record Resolver(String graphQlType, String owner, String field, String javaType, JavaSootMethod method) {
    }

    List<Resolver> resolvers(SpringBeans beans) {
        List<Resolver> resolvers = new ArrayList<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            if (!beans.isController(cls)) {
                continue;
            }
            Optional<String> classType = context.findAnnotation(cls, SCHEMA_MAPPING)
                    .flatMap(mapping -> Annotations.string(mapping, "typeName")).filter(name -> !name.isEmpty());
            for (JavaSootMethod method : cls.getMethods()) {
                if (!RequestMappings.suspendImpl(method)) {
                    resolver(method, classType).ifPresent(resolvers::add);
                }
            }
        }
        return resolvers;
    }

    private Optional<Resolver> resolver(JavaSootMethod method, Optional<String> classType) {
        for (AnnotationUsage annotation : method.getAnnotations()) {
            String name = Annotations.name(annotation);
            boolean batch = name.equals(BATCH_MAPPING);
            if (!batch && !name.equals(SCHEMA_MAPPING)) {
                continue;
            }
            Optional<String> source = source(method, batch);
            // Spring names the type after the source object's class unless the mapping names it.
            Optional<String> type = Annotations.string(annotation, "typeName").filter(typeName -> !typeName.isEmpty())
                    .or(() -> classType)
                    .or(() -> source.map(GraphQlMappings::simpleName));
            if (type.isEmpty() || ROOT_TYPES.contains(type.get())) {
                return Optional.empty();
            }
            Optional<String> owner = source.or(() -> applicationType(type.get()));
            if (owner.isEmpty()) {
                return Optional.empty();
            }
            String field = Annotations.string(annotation, "field")
                    .or(() -> Annotations.string(annotation, "value"))
                    .filter(value -> !value.isEmpty()).orElse(method.getName());
            String javaType = valueType(context.classFiles().genericReturnType(method.getSignature())
                    .orElse(erased(method.getReturnType())), batch);
            return Optional.of(new Resolver(type.get(), owner.get(), field, javaType, method));
        }
        return Optional.empty();
    }

    /**
     * The parameter that receives the parent object: the first application type that isn't an argument or a context
     * value; for a batch, the element type of its collection.
     */
    private Optional<String> source(JavaSootMethod method, boolean batch) {
        List<ClassFileMetadata.GenericType> parameters = context.classFiles()
                .genericParameterTypes(method.getSignature());
        if (parameters.isEmpty()) {
            // No generic signature: the erased types are the types.
            parameters = method.getParameterTypes().stream().map(GraphQlMappings::erased).toList();
        }
        for (int index = 0; index < parameters.size(); index++) {
            if (context.classFiles().parameterAnnotations(method.getSignature(), index).stream()
                    .anyMatch(NOT_SOURCE::contains)) {
                continue;
            }
            ClassFileMetadata.GenericType parameter = parameters.get(index);
            if (batch && MANY.contains(parameter.name()) && !parameter.arguments().isEmpty()) {
                parameter = parameter.arguments().getFirst();
            }
            String name = parameter.name();
            if (context.findClass(name).filter(found -> context.isApplication(found.getType())).isPresent()) {
                return Optional.of(name);
            }
        }
        return Optional.empty();
    }

    private Optional<String> applicationType(String simpleName) {
        return context.applicationClasses().stream().map(cls -> cls.getType().getFullyQualifiedName())
                .filter(name -> simpleName(name).equals(simpleName)).findFirst();
    }

    private static ClassFileMetadata.GenericType erased(Type type) {
        return new ClassFileMetadata.GenericType(type instanceof ClassType cls ? cls.getFullyQualifiedName()
                : type.toString(), List.of());
    }

    private static String simpleName(String className) {
        return className.substring(Math.max(className.lastIndexOf('.'), className.lastIndexOf('$')) + 1);
    }

    /**
     * The field's value type: unwraps {@code Mono}, {@code Optional} and collections; a batch's {@code Map} gives its
     * values.
     */
    private static String valueType(ClassFileMetadata.GenericType type, boolean batch) {
        if (batch && type.name().equals("java.util.Map") && type.arguments().size() == 2) {
            return valueType(type.arguments().getLast(), false);
        }
        if ((MANY.contains(type.name()) || SINGLE.contains(type.name())) && !type.arguments().isEmpty()) {
            return valueType(type.arguments().getFirst(), batch);
        }
        return type.name();
    }

    /**
     * The root type and field a method handles: the annotation's name (or {@code field} for {@code @SchemaMapping}),
     * else the method's name.
     */
    private Optional<Operation> operation(JavaSootMethod method, Optional<String> classType) {
        for (AnnotationUsage annotation : method.getAnnotations()) {
            String name = Annotations.name(annotation);
            String type = OPERATIONS.get(name);
            if (type == null && name.equals(SCHEMA_MAPPING)) {
                type = Annotations.string(annotation, "typeName").filter(typeName -> !typeName.isEmpty())
                        .or(() -> classType).orElse(null);
                if (type == null || !ROOT_TYPES.contains(type)) {
                    return Optional.empty();
                }
            }
            if (type != null) {
                String field = Annotations.string(annotation, "field")
                        .or(() -> Annotations.string(annotation, "name"))
                        .or(() -> Annotations.string(annotation, "value"))
                        .filter(value -> !value.isEmpty()).orElse(method.getName());
                return Optional.of(new Operation(type, field));
            }
        }
        return Optional.empty();
    }
}
