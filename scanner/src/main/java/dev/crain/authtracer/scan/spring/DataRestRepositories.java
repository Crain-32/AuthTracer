package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.atteo.evo.inflector.English;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.ClassFileMetadata;
import dev.crain.authtracer.scan.ClassFileMetadata.GenericDeclaration;
import dev.crain.authtracer.scan.ClassFileMetadata.GenericType;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.flow.Payloads;
import sootup.core.model.MethodModifier;
import sootup.core.types.ClassType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0040: Spring Data REST exports repositories as HTTP resources, with no controller in the code. Each
 * exported repository is a collection at its path ({@code /persons}: the domain type's simple name, uncapitalized and
 * pluralized by Evo Inflector as Spring Data REST does, or {@code @RepositoryRestResource(path)}), under
 * {@code spring.data.rest.base-path}: {@code GET} and {@code POST} on the collection, {@code GET}, {@code PUT},
 * {@code PATCH} and {@code DELETE} on {@code /{id}} for the CRUD methods the repository has, and
 * {@code GET /search/<method>} for each query method. {@code @RestResource(exported = false)} hides a method;
 * {@code spring.data.rest.detection-strategy} (by default: public interfaces, or annotated ones that are exported)
 * picks the repositories.
 * <p>
 * Decision 0114: each association of an exported domain type to another exported one is a resource too,
 * {@code /persons/{id}/address} (5.1.1 {@code RepositoryPropertyReferenceController}): reading it runs the owner's
 * {@code findById} and reads the property, not the linked repository; linking runs the linked repository's
 * {@code findById} for each URI sent, then the owner's {@code save}: one URI for a single entity, any number (none
 * too) for a collection, which is unlinked an item at a time (5.1.1 answers {@code DELETE} on the collection and
 * {@code PATCH} on a single entity with 405). A {@code RepositoryRestConfigurer}'s constant
 * {@code setBasePath(..)} is the base path; what else it sets about what is exported is an OPAQUE_CONFIG finding.
 */
@Supports(Feature.HTTP_ENDPOINTS)
final class DataRestRepositories {

    private static final String REPOSITORY = "org.springframework.data.repository.Repository";
    private static final String CONFIGURATION =
            "org.springframework.data.rest.webmvc.config.RepositoryRestMvcConfiguration";
    private static final String BOOT_AUTO_CONFIGURATION =
            "org.springframework.boot.data.rest.autoconfigure.DataRestAutoConfiguration";
    private static final String IMPORT = "org.springframework.context.annotation.Import";
    private static final String REPOSITORY_REST_RESOURCE =
            "org.springframework.data.rest.core.annotation.RepositoryRestResource";
    private static final String REST_RESOURCE = "org.springframework.data.rest.core.annotation.RestResource";
    private static final String PAGEABLE = "org.springframework.data.domain.Pageable";
    private static final String SORT = "org.springframework.data.domain.Sort";
    private static final String OBJECT = "java.lang.Object";
    /**
     * Methods of Spring Data's base interfaces that are not query methods.
     */
    private static final Set<String> BASE_METHODS = Set.of("findAll", "findById", "findOne", "findAllById", "save",
            "saveAll", "saveAndFlush", "saveAllAndFlush", "delete", "deleteById", "deleteAll", "deleteAllById",
            "deleteAllInBatch", "deleteAllByIdInBatch", "deleteInBatch", "count", "existsById", "flush", "getById",
            "getOne", "getReferenceById", "findBy", "exists");

    private static final String EVENT_HANDLER = "org.springframework.data.rest.core.annotation.RepositoryEventHandler";
    private static final String HANDLE = "org.springframework.data.rest.core.annotation.Handle";
    /**
     * The events each request publishes ({@code RepositoryEntityController}): a {@code PUT} to an existing item and a
     * {@code PATCH} save it.
     */
    private static final Map<String, String> EVENTS = Map.of("POST", "Create", "PUT", "Save", "PATCH", "Save",
            "DELETE", "Delete");

    /**
     * The {@code @RepositoryEventHandler} methods a request runs, before and after the repository call.
     */
    record EventHandlers(List<JavaSootMethod> before, List<JavaSootMethod> after) {
    }

    /**
     * What makes a property an association to Spring Data: JPA's relationship annotations, MongoDB's references,
     * Spring Data's own {@code @Reference}.
     */
    private static final Set<String> ASSOCIATIONS = Set.of("jakarta.persistence.OneToOne", "jakarta.persistence.OneToMany",
            "jakarta.persistence.ManyToOne", "jakarta.persistence.ManyToMany",
            "org.springframework.data.annotation.Reference", "org.springframework.data.mongodb.core.mapping.DBRef",
            "org.springframework.data.mongodb.core.mapping.DocumentReference");
    private static final Set<String> MANY = Set.of("java.util.List", "java.util.Set", "java.util.Collection",
            "java.util.SortedSet", "java.lang.Iterable", "java.util.Map");
    private static final String CONFIGURER = "org.springframework.data.rest.webmvc.config.RepositoryRestConfigurer";
    private static final String REST_CONFIGURATION = "org.springframework.data.rest.core.config.";
    /**
     * What a configurer may set that doesn't change which resources there are or where.
     */
    private static final Set<String> HARMLESS = Set.of("exposeIdsFor", "setDefaultPageSize", "setMaxPageSize",
            "setReturnBodyOnCreate", "setReturnBodyOnUpdate", "setReturnBodyForPutAndPost", "setDefaultMediaType",
            "useHalAsDefaultJsonMediaType", "setPageParamName", "setLimitParamName", "setSortParamName",
            "setEnableEnumTranslation", "getProjectionConfiguration", "getMetadataConfiguration", "addMapping",
            "withEntityLookup", "getCorsRegistry");

    /**
     * An exported repository: its domain type, its collection's path and the CRUD methods it serves.
     */
    private record Exported(JavaSootClass repository, String type, String collection,
            Optional<JavaSootMethod> findOne, Optional<JavaSootMethod> save) {
    }

    private final ScanContext context;
    private final Map<String, EventHandlers> eventHandlers = new HashMap<>();
    private final List<Finding> findings = new ArrayList<>();

    DataRestRepositories(ScanContext context) {
        this.context = context;
    }

    /**
     * By Ingress id, after {@link #detect()}.
     */
    Map<String, EventHandlers> eventHandlers() {
        return eventHandlers;
    }

    /**
     * Decision 0114: what can't be read of the configuration.
     */
    List<Finding> findings() {
        return findings;
    }

    List<RequestMappings.Mapping> detect() {
        List<RequestMappings.Mapping> mappings = new ArrayList<>();
        if (!active()) {
            return mappings;
        }
        List<Exported> exported = new ArrayList<>();
        String basePath = configuredBasePath().orElse(context.properties().get("spring.data.rest.base-path")
                .orElse(""));
        String strategy = context.properties().get("spring.data.rest.detection-strategy").orElse("default")
                .toUpperCase(java.util.Locale.ROOT);
        for (JavaSootClass repository : context.applicationClasses()) {
            if (!repository.isInterface() || context.interfacesOf(repository.getType()).stream()
                    .noneMatch(type -> type.getFullyQualifiedName().equals(REPOSITORY))) {
                continue;
            }
            List<GenericType> arguments = typeArguments(repository.getType().getFullyQualifiedName(), Map.of());
            // A generic base repository's domain type is a variable: it is no repository of its own.
            if (arguments.isEmpty() || arguments.getFirst().variable()
                    || !exported(repository, arguments.getFirst().name(), strategy)) {
                continue;
            }
            String type = arguments.getFirst().name();
            String id = arguments.size() > 1 && !arguments.get(1).variable() ? arguments.get(1).name() : OBJECT;
            String collection = RequestMappings.join(basePath, path(repository).orElse(English.plural(
                    uncapitalize(simpleName(type)))));
            // The methods Spring Data's DefaultCrudMethods picks, in its order: the repository's own declaration
            // of each signature before an inherited one.
            Optional<JavaSootMethod> findAll = crudMethod(repository, List.of(
                    new Crud("findAll", PAGEABLE), new Crud("findAll", SORT), new Crud("findAll", null)));
            Optional<JavaSootMethod> findOne = crudMethod(repository, List.of(
                    new Crud("findById", id), new Crud("findById", OBJECT)));
            Optional<JavaSootMethod> save = crudMethod(repository, List.of(
                    new Crud("save", type), new Crud("save", OBJECT)));
            Optional<JavaSootMethod> delete = crudMethod(repository, List.of(new Crud("delete", type),
                    new Crud("deleteById", id), new Crud("delete", OBJECT), new Crud("deleteById", OBJECT),
                    new Crud("delete", "java.lang.Iterable")));
            // An item's PUT, PATCH and DELETE look it up first, through findById.
            List<JavaSootMethod> lookup = findOne.filter(method -> !hidden(method)).stream().toList();
            Payload one = new Payload(type, false);
            add(mappings, repository, type, findAll, "GET", collection, new Payload(type, true), List.of());
            add(mappings, repository, type, save, "POST", collection, one, List.of());
            String item = collection + "/{id}";
            add(mappings, repository, type, findOne, "GET", item, one, List.of());
            add(mappings, repository, type, save, "PUT", item, one, lookup);
            add(mappings, repository, type, save, "PATCH", item, one, lookup);
            add(mappings, repository, type, delete, "DELETE", item, null, lookup);
            exported.add(new Exported(repository, type, collection, findOne.filter(method -> !hidden(method)),
                    save.filter(method -> !hidden(method))));
            // Query methods it declares, and those of the application's interfaces it extends.
            List<JavaSootMethod> queries = new ArrayList<>(repository.getMethods());
            context.interfacesOf(repository.getType()).stream().filter(context::isApplication)
                    .map(context::findClass).flatMap(Optional::stream)
                    .forEach(parent -> queries.addAll(parent.getMethods()));
            Set<String> seen = new HashSet<>();
            for (JavaSootMethod query : queries) {
                if (!seen.add(query.getSubSignature().toString())) {
                    continue;
                }
                if (BASE_METHODS.contains(query.getName()) || query.hasBody() || hidden(query)) {
                    continue;
                }
                String searchPath = restResource(query).flatMap(annotation -> Annotations.string(annotation, "path"))
                        .filter(found -> !found.isEmpty()).orElse(query.getName());
                mappings.add(new RequestMappings.Mapping(Ingress.of("GET", collection + "/search/" + searchPath,
                        MethodNames.codeRef(query.getSignature())).withResponse(Payloads.returnedBy(context,
                                query.getSignature()).orElse(null)), query, true));
            }
        }
        exported.forEach(owner -> associations(owner, exported, mappings));
        return mappings;
    }

    /**
     * Decision 0114: the owner's associations to other exported types, each a resource under its item.
     */
    private void associations(Exported owner, List<Exported> exported, List<RequestMappings.Mapping> mappings) {
        if (owner.findOne().isEmpty()) {
            return;
        }
        List<String> types = new ArrayList<>(List.of(owner.type()));
        context.superClassesOf(context.type(owner.type())).stream().filter(context::isApplication)
                .forEach(type -> types.add(type.getFullyQualifiedName()));
        for (String declaring : types) {
            for (ClassFileMetadata.DeclaredField field : context.classFiles().fields(declaring)) {
                if (field.annotations().keySet().stream().noneMatch(ASSOCIATIONS::contains)
                        || "false".equals(field.annotations().get(REST_RESOURCE + ".exported"))) {
                    continue;
                }
                Optional<GenericType> declared = context.classFiles().genericFieldType(declaring, field.name());
                boolean many = declared.map(found -> MANY.contains(found.name())).orElse(false);
                String target = many ? declared.get().arguments().isEmpty() ? null
                        : declared.get().arguments().getLast().name() : field.type();
                Optional<Exported> linked = exported.stream().filter(other -> other.type().equals(target)).findFirst();
                if (linked.isEmpty()) {
                    continue;
                }
                String property = owner.collection() + "/{id}/" + Optional.ofNullable(field.annotations()
                        .get(REST_RESOURCE + ".path")).filter(path -> !path.isEmpty()).orElse(field.name());
                Payload response = new Payload(target, many);
                CodeRef read = CodeRef.ofMethod(owner.repository().getType().getFullyQualifiedName(),
                        owner.findOne().get().getName());
                // Reading: the owner's findById, then the property.
                mappings.add(new RequestMappings.Mapping(Ingress.of("GET", property, read).withResponse(response),
                        owner.findOne().get(), true));
                if (many) {
                    mappings.add(new RequestMappings.Mapping(Ingress.of("GET", property + "/{propertyId}", read)
                            .withResponse(new Payload(target, false)), owner.findOne().get(), true));
                }
                if (owner.save().isEmpty()) {
                    continue;
                }
                CodeRef write = CodeRef.ofMethod(owner.repository().getType().getFullyQualifiedName(),
                        owner.save().get().getName());
                List<JavaSootMethod> lookup = new ArrayList<>(List.of(owner.findOne().get()));
                if (many) {
                    // Linking: each URI sent is looked up in the linked type's repository, and a caller may send
                    // none (a PUT of none unlinks them all). Unlinking is by item: the collection answers DELETE 405.
                    for (String method : List.of("PUT", "POST", "PATCH")) {
                        link(mappings, Ingress.of(method, property, write), owner, lookup, "LinkSave");
                    }
                    link(mappings, Ingress.of("DELETE", property + "/{propertyId}", write), owner, lookup,
                            "LinkDelete");
                    continue;
                }
                // One link, which must be sent and is looked up in the linked type's repository; PATCH answers 405.
                List<JavaSootMethod> linking = new ArrayList<>(lookup);
                linked.get().findOne().ifPresent(linking::add);
                link(mappings, Ingress.of("PUT", property, write), owner, linking, "LinkSave");
                link(mappings, Ingress.of("DELETE", property, write), owner, lookup, "LinkDelete");
            }
        }
    }

    private void link(List<RequestMappings.Mapping> mappings, Ingress ingress, Exported owner,
            List<JavaSootMethod> lookup, String event) {
        mappings.add(new RequestMappings.Mapping(ingress, owner.save().get(), true));
        List<JavaSootMethod> before = new ArrayList<>(lookup);
        before.addAll(handlers("Before" + event, owner.type()));
        eventHandlers.put(ingress.id(), new EventHandlers(before, handlers("After" + event, owner.type())));
    }

    /**
     * Decision 0114: a {@code RepositoryRestConfigurer}'s constant {@code setBasePath(..)}; what else it sets about
     * the resources (their exposure, the detection strategy, a base path that isn't a constant), or a configurer built
     * in a bean method, is an OPAQUE_CONFIG finding.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private Optional<String> configuredBasePath() {
        Optional<String> basePath = Optional.empty();
        for (JavaSootClass cls : context.applicationClasses()) {
            boolean configurer = context.interfacesOf(cls.getType()).stream()
                    .anyMatch(type -> type.getFullyQualifiedName().equals(CONFIGURER));
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                if (method.getReturnType() instanceof ClassType returned
                        && returned.getFullyQualifiedName().equals(CONFIGURER)
                        && context.hasAnnotation(method, SpringNames.BEAN)) {
                    findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The RepositoryRestConfigurer bean "
                            + MethodNames.key(method.getSignature()) + " configures Spring Data REST in a way AuthTracer"
                            + " doesn't read: the resources it exports and their paths may differ from the graph's",
                            MethodNames.codeRef(method.getSignature())));
                    continue;
                }
                if (!configurer || !method.getName().equals("configureRepositoryRestConfiguration")) {
                    continue;
                }
                List<String> unread = new ArrayList<>();
                for (sootup.core.jimple.common.stmt.Stmt stmt : method.getBody().getStmts()) {
                    Optional<sootup.core.jimple.common.expr.AbstractInvokeExpr> invoke =
                            dev.crain.authtracer.scan.Locals.invoke(stmt);
                    if (invoke.isEmpty() || !invoke.get().getMethodSignature().getDeclClassType()
                            .getFullyQualifiedName().startsWith(REST_CONFIGURATION)) {
                        continue;
                    }
                    String name = invoke.get().getMethodSignature().getName();
                    if (name.equals("setBasePath") && invoke.get().getArgCount() == 1
                            && invoke.get().getArg(0) instanceof sootup.core.jimple.common.constant.StringConstant path) {
                        basePath = Optional.of(path.getValue());
                    }
                    else if (!HARMLESS.contains(name)) {
                        unread.add(name);
                    }
                }
                if (!unread.isEmpty()) {
                    findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The RepositoryRestConfigurer "
                            + cls.getName() + " sets what AuthTracer doesn't read (" + String.join(", ",
                                    unread.stream().distinct().toList()) + "): the resources Spring Data REST exports"
                            + " and their paths may differ from the graph's", MethodNames.codeRef(method
                                    .getSignature())));
                }
            }
        }
        return basePath;
    }

    /**
     * Spring Data REST is on the classpath, and Spring Boot configures it or the application imports it.
     */
    private boolean active() {
        if (context.findClass(CONFIGURATION).isEmpty()) {
            return false;
        }
        boolean boot = context.findClass(BOOT_AUTO_CONFIGURATION).isPresent()
                && context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION);
        return boot || context.applicationClasses().stream().anyMatch(cls -> context.superClassesOf(cls.getType())
                .stream().anyMatch(type -> type.getFullyQualifiedName().equals(CONFIGURATION))
                || context.findAnnotation(cls, IMPORT).map(annotation -> Annotations.strings(annotation, "value")
                        .contains(CONFIGURATION)).orElse(false));
    }

    /**
     * Spring Data REST's detection strategies (5.1.1's {@code RepositoryDetectionStrategies}): {@code DEFAULT}
     * exports what the repository's annotation says, else what its domain type's says, else public interfaces;
     * {@code ANNOTATED} annotated ones that say so; {@code VISIBILITY} public ones, whatever they say; {@code ALL}
     * every one.
     */
    private boolean exported(JavaSootClass repository, String domainType, String strategy) {
        Optional<AnnotationUsage> annotation = exportAnnotation(repository);
        boolean explicitly = annotation.flatMap(found -> Annotations.bool(found, "exported")).orElse(true);
        return switch (strategy) {
            case "ALL" -> true;
            case "ANNOTATED" -> annotation.isPresent() && explicitly;
            case "VISIBILITY" -> repository.isPublic();
            default -> annotation.isPresent() ? explicitly : context.findClass(domainType)
                    .flatMap(this::exportAnnotation).map(found -> Annotations.bool(found, "exported").orElse(true))
                    .orElse(repository.isPublic());
        };
    }

    private Optional<AnnotationUsage> exportAnnotation(JavaSootClass cls) {
        return context.findAnnotation(cls, REPOSITORY_REST_RESOURCE)
                .or(() -> context.findAnnotation(cls, REST_RESOURCE));
    }

    private Optional<String> path(JavaSootClass repository) {
        return exportAnnotation(repository).flatMap(annotation -> Annotations.string(annotation, "path"))
                .filter(path -> !path.isEmpty());
    }

    /**
     * One resource method, unless the repository has no such CRUD method or hides it.
     *
     * @param domain the repository's domain type
     * @param lookup repository methods the request runs before the event handlers and the method itself
     */
    private void add(List<RequestMappings.Mapping> mappings, JavaSootClass repository, String domain,
            Optional<JavaSootMethod> method, String httpMethod, String route, Payload response,
            List<JavaSootMethod> lookup) {
        if (method.isEmpty() || hidden(method.get())) {
            return;
        }
        boolean own = method.get().getDeclaringClassType().equals(repository.getType());
        CodeRef handler = own ? MethodNames.codeRef(method.get().getSignature())
                : CodeRef.ofMethod(repository.getType().getFullyQualifiedName(), method.get().getName());
        Ingress ingress = Ingress.of(httpMethod, route, handler).withResponse(response);
        mappings.add(new RequestMappings.Mapping(ingress, method.get(), true));
        if (EVENTS.containsKey(httpMethod)) {
            String event = EVENTS.get(httpMethod);
            List<JavaSootMethod> before = new ArrayList<>(lookup);
            before.addAll(handlers("Before" + event, domain));
            eventHandlers.put(ingress.id(), new EventHandlers(before, handlers("After" + event, domain)));
        }
    }

    /**
     * A CRUD method's signature: its name and its one parameter's type, {@code null} for none.
     */
    private record Crud(String name, String parameter) {

        boolean matches(JavaSootMethod method) {
            if (!method.getName().equals(name) || MethodModifier.isBridge(method.getModifiers())) {
                return false;
            }
            return parameter == null ? method.getParameterCount() == 0
                    : method.getParameterCount() == 1 && method.getParameterType(0).toString().equals(parameter);
        }
    }

    /**
     * The first signature the repository has, its own declaration before an inherited one, as
     * {@code ReflectionUtils.doWithMethods} and {@code getMostSpecificMethod} find it.
     */
    private Optional<JavaSootMethod> crudMethod(JavaSootClass repository, List<Crud> signatures) {
        List<JavaSootClass> declaring = new ArrayList<>(List.of(repository));
        context.interfacesOf(repository.getType()).forEach(type -> context.findClass(type).ifPresent(declaring::add));
        for (Crud signature : signatures) {
            for (JavaSootClass cls : declaring) {
                Optional<JavaSootMethod> found = cls.getMethods().stream().filter(signature::matches).findFirst();
                if (found.isPresent()) {
                    return found;
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Decision 0040: the {@code @HandleBeforeSave} (...) methods of {@code @RepositoryEventHandler} beans that take
     * the domain type, or a supertype of it.
     */
    private List<JavaSootMethod> handlers(String event, String domainType) {
        Set<String> accepted = new HashSet<>(Set.of(domainType, "java.lang.Object"));
        ClassType domain = context.type(domainType);
        context.superClassesOf(domain).forEach(type -> accepted.add(type.getFullyQualifiedName()));
        context.interfacesOf(domain).forEach(type -> accepted.add(type.getFullyQualifiedName()));
        List<JavaSootMethod> found = new ArrayList<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            if (!context.hasAnnotation(cls, EVENT_HANDLER)) {
                continue;
            }
            for (JavaSootMethod method : cls.getMethods()) {
                if (method.hasBody() && method.getParameterCount() >= 1 && context.hasAnnotation(method, HANDLE + event)
                        && accepted.contains(method.getParameterType(0).toString())) {
                    found.add(method);
                }
            }
        }
        return found;
    }

    private boolean hidden(JavaSootMethod method) {
        return restResource(method).flatMap(annotation -> Annotations.bool(annotation, "exported")).map(exported ->
                !exported).orElse(false);
    }

    private Optional<AnnotationUsage> restResource(JavaSootMethod method) {
        return context.findAnnotation(method, REST_RESOURCE);
    }

    /**
     * The domain and id types: the type arguments of the Spring Data interface the repository extends, through the
     * application's own generic interfaces.
     */
    private List<GenericType> typeArguments(String className, Map<String, GenericType> bindings) {
        GenericDeclaration declaration = context.classFiles().declaration(className);
        for (GenericType supertype : declaration.supertypes()) {
            List<GenericType> arguments = supertype.arguments().stream()
                    .map(argument -> argument.variable() ? bindings.getOrDefault(argument.name(), argument) : argument)
                    .toList();
            if (supertype.name().startsWith("org.springframework.data.") && !arguments.isEmpty()) {
                return arguments;
            }
            if (context.isApplication(context.type(supertype.name()))) {
                List<String> parameters = context.classFiles().declaration(supertype.name()).typeParameters();
                Map<String, GenericType> next = new HashMap<>();
                for (int i = 0; i < parameters.size() && i < arguments.size(); i++) {
                    next.put(parameters.get(i), arguments.get(i));
                }
                List<GenericType> found = typeArguments(supertype.name(), next);
                if (!found.isEmpty()) {
                    return found;
                }
            }
        }
        return List.of();
    }

    private static String simpleName(String className) {
        return className.substring(Math.max(className.lastIndexOf('.'), className.lastIndexOf('$')) + 1);
    }

    private static String uncapitalize(String name) {
        return name.isEmpty() ? name : Character.toLowerCase(name.charAt(0)) + name.substring(1);
    }
}
