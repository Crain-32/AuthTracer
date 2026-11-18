package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.model.MethodModifier;
import sootup.core.signatures.MethodSubSignature;
import sootup.core.types.ClassType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Spring MVC controller mappings as Ingress nodes.
 */
@Supports(Feature.HTTP_ENDPOINTS)
final class RequestMappings {

    /**
     * An Ingress and the handler method requests to it run.
     *
     * @param functional the Ingress already carries its response, so the handler's return type is not read and it
     *        renders no view: a {@code RouterFunction} route (its handler returns a {@code ServerResponse}), and the
     *        STOMP, RSocket, gRPC and Data REST mappings, which set the response themselves
     * @param transport the HTTP request the operation arrives in, when the ingress is not one itself (a GraphQL
     *        operation arrives as {@code POST /graphql}): request-level rules match it
     * @param webSocket a second way in: the WebSocket handshake a GraphQL operation can also arrive through
     *        (decision 0034), or {@code null}
     * @param receiver the controller the handler runs on, which may inherit it from a base class: {@code this}
     *        calls run that controller's methods; {@code null} when only the handler's own class is known
     */
    @Supports(Feature.CALL_PATHS)
    record Mapping(Ingress ingress, JavaSootMethod handler, boolean functional, Ingress transport, Ingress webSocket,
            ClassType receiver, List<JavaSootMethod> filters) {

        Mapping(Ingress ingress, JavaSootMethod handler, boolean functional, Ingress transport, Ingress webSocket,
                ClassType receiver) {
            this(ingress, handler, functional, transport, webSocket, receiver, List.of());
        }

        Mapping(Ingress ingress, JavaSootMethod handler) {
            this(ingress, handler, false, null, null, null);
        }

        Mapping(Ingress ingress, JavaSootMethod handler, boolean functional) {
            this(ingress, handler, functional, null, null, null);
        }

        Mapping(Ingress ingress, JavaSootMethod handler, boolean functional, Ingress transport) {
            this(ingress, handler, functional, transport, null, null);
        }

        Mapping(Ingress ingress, JavaSootMethod handler, boolean functional, Ingress transport, Ingress webSocket) {
            this(ingress, handler, functional, transport, webSocket, null);
        }

        Mapping withIngress(Ingress other) {
            return new Mapping(other, handler, functional, transport, webSocket, receiver, filters);
        }

        Mapping onReceiver(ClassType type) {
            return new Mapping(ingress, handler, functional, transport, webSocket, type, filters);
        }

        /**
         * A functional route's filters, which run before its handler, outermost first.
         */
        Mapping withFilters(List<JavaSootMethod> before) {
            return new Mapping(ingress, handler, functional, transport, webSocket, receiver, List.copyOf(before));
        }
    }

    /**
     * @param params the request parameters it requires ({@code params = "use_case=delegation"}), joined with {@code &}
     * @param conditions its {@code headers}, {@code consumes}, {@code produces} and (Spring 7) {@code version}, as
     *        {@code header:X-Api=2}, {@code consumes:application/json}, {@code version:1.1}
     */
    record MappingInfo(List<String> paths, List<String> methods, String params, List<String> conditions) {
    }

    /**
     * Prefixes of the conditions that aren't request parameters: the linker doesn't match them against a query.
     */
    static final List<String> CONDITIONS = List.of("header:", "consumes:", "produces:", "version:");

    private static final String ALIAS_FOR = "org.springframework.core.annotation.AliasFor";

    private final ScanContext context;

    RequestMappings(ScanContext context) {
        this.context = context;
    }

    List<Mapping> detect(SpringBeans beans) {
        List<Mapping> mappings = new ArrayList<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            if (!beans.isController(cls)) {
                continue;
            }
            List<String> prefixes = prefixes(cls);
            Optional<MappingInfo> declared = classInfo(cls);
            for (JavaSootMethod method : handlerMethods(cls)) {
                // Kotlin copies a suspend handler's annotations onto its static body, f$suspendImpl; javac copies an
                // override's onto its bridge, which only calls the override.
                if (suspendImpl(method) || MethodModifier.isBridge(method.getModifiers())
                        || MethodModifier.isSynthetic(method.getModifiers())) {
                    continue;
                }
                Optional<MappingInfo> info = mappingInfo(method)
                        .map(found -> declared.map(type -> combine(type, found)).orElse(found));
                if (info.isEmpty()) {
                    continue;
                }
                for (String route : routes(prefixes, info.get().paths())) {
                    for (String httpMethod : info.get().methods()) {
                        Ingress ingress = Ingress.of(httpMethod, route, MethodNames.codeRef(method.getSignature()))
                                .withParams(info.get().params());
                        mappings.add(new Mapping(ingress, method).onReceiver(cls.getType()));
                    }
                }
            }
        }
        return mappings;
    }

    /**
     * The class's {@code @RequestMapping} beyond its paths, taken as {@link #prefixes} takes them.
     */
    private Optional<MappingInfo> classInfo(JavaSootClass cls) {
        return context.findAnnotation(cls, SpringNames.REQUEST_MAPPING)
                .or(() -> above(cls.getType(), parent -> context.findAnnotation(parent, SpringNames.REQUEST_MAPPING)))
                .flatMap(RequestMappings::mappingInfo);
    }

    /**
     * Spring Framework 7.0.9's {@code RequestMappingInfo#combine} of the class's mapping and a method's: the methods
     * of both ({@code RequestMethodsRequestCondition}: either's is a union, none is any), the params and headers of
     * both, the method's {@code consumes}, {@code produces} and version where it has them, else the class's. The paths
     * are the method's; the class's prefix them.
     */
    static MappingInfo combine(MappingInfo type, MappingInfo method) {
        List<String> methods = new ArrayList<>(type.methods().stream().filter(found -> !found.equals("*")).toList());
        method.methods().stream().filter(found -> !found.equals("*") && !methods.contains(found))
                .forEach(methods::add);
        List<String> params = new ArrayList<>();
        for (String found : List.of(type.params(), method.params())) {
            if (found != null && !found.isEmpty()) {
                params.addAll(List.of(found.split("&")));
            }
        }
        List<String> conditions = new ArrayList<>(type.conditions().stream()
                .filter(condition -> condition.startsWith("header:")).toList());
        method.conditions().stream().filter(condition -> condition.startsWith("header:")
                && !conditions.contains(condition)).forEach(conditions::add);
        for (String kind : List.of("consumes:", "produces:", "version:")) {
            List<String> own = method.conditions().stream().filter(condition -> condition.startsWith(kind)).toList();
            conditions.addAll(own.isEmpty() ? type.conditions().stream().filter(condition -> condition
                    .startsWith(kind)).toList() : own);
        }
        return new MappingInfo(method.paths(), methods.isEmpty() ? List.of("*") : methods,
                String.join("&", params.stream().distinct().sorted().toList()), conditions);
    }

    /**
     * The paths of the class's {@code @RequestMapping}, which prefix its handlers' ({@code ""} without one). Without
     * its own, the class takes one from its interfaces or superclasses, as Spring's {@code findMergedAnnotation} does.
     */
    @Supports(Feature.LIBRARY_ENDPOINTS)
    List<String> prefixes(JavaSootClass cls) {
        return context.findAnnotation(cls, SpringNames.REQUEST_MAPPING)
                .or(() -> above(cls.getType(), parent -> context.findAnnotation(parent, SpringNames.REQUEST_MAPPING)))
                .map(RequestMappings::paths).orElse(List.of(""));
    }

    /**
     * The methods a controller handles requests with, as Spring's {@code MethodIntrospector} finds them: its own,
     * then those it inherits without overriding from the application's superclasses (an abstract base controller)
     * and interfaces (default methods).
     */
    private List<JavaSootMethod> handlerMethods(JavaSootClass cls) {
        List<JavaSootMethod> methods = new ArrayList<>(cls.getMethods());
        Set<MethodSubSignature> declared = new HashSet<>();
        methods.forEach(method -> declared.add(method.getSubSignature()));
        List<ClassType> parents = new ArrayList<>(context.superClassesOf(cls.getType()));
        parents.addAll(context.interfacesOf(cls.getType()));
        for (ClassType parent : parents) {
            if (context.isApplication(parent)) {
                context.findClass(parent).ifPresent(found -> found.getMethods().stream()
                        .filter(method -> !method.isStatic() && !method.isAbstract()
                                && !method.getName().startsWith("<") && declared.add(method.getSubSignature()))
                        .forEach(methods::add));
            }
        }
        return methods;
    }

    /**
     * The first the lookup finds above a class, in Spring's type-hierarchy order: each interface (then its own),
     * then the superclass (then its own); only the application's.
     */
    private <T> Optional<T> above(ClassType type, Function<JavaSootClass, Optional<T>> lookup) {
        Optional<JavaSootClass> cls = context.findClass(type);
        if (cls.isEmpty()) {
            return Optional.empty();
        }
        List<ClassType> parents = new ArrayList<>(cls.get().getInterfaces());
        cls.get().getSuperclass().ifPresent(parents::add);
        for (ClassType parent : parents) {
            Optional<T> found = context.isApplication(parent)
                    ? context.findClass(parent).flatMap(lookup).or(() -> above(parent, lookup)) : Optional.empty();
            if (found.isPresent()) {
                return found;
            }
        }
        return Optional.empty();
    }

    /**
     * Each prefix joined with each path, in that order. A trailing slash stays, as Spring Framework 7.0.9's
     * {@code PathPattern#combine} keeps it: the path's, or the prefix's when the path is empty. Its
     * {@code PathPatternParser} matches no optional trailing slash, so {@code /users/} answers that path only, and a
     * rule for {@code /users} doesn't reach it.
     */
    static List<String> routes(List<String> prefixes, List<String> paths) {
        return prefixes.stream().flatMap(prefix -> paths.stream().map(path -> {
            String route = join(prefix, path);
            return (path.isEmpty() ? prefix : path).endsWith("/") && !route.endsWith("/") ? route + "/" : route;
        })).toList();
    }

    /**
     * The method's {@code @RequestMapping} (or {@code @GetMapping}, ..., or a composed annotation): its paths and
     * HTTP methods. Without its own, the method takes the mapping of the method it implements or overrides, on an
     * interface (an OpenAPI-generated {@code UsersApi}) or a superclass, as Spring's {@code findMergedAnnotation}
     * does.
     */
    @Supports({Feature.SERVICE_CALLS, Feature.LIBRARY_ENDPOINTS})
    Optional<MappingInfo> mappingInfo(JavaSootMethod method) {
        // A generic base's create(T) is create(Object) in the bytecode: the override create(User) still overrides it.
        return declaredMappingInfo(method).or(() -> above(method.getDeclaringClassType(), parent -> parent
                .getMethod(method.getSubSignature()).or(() -> parent.getMethods().stream()
                        .filter(candidate -> MethodSecurity.overrides(context, candidate, method)).findFirst())
                .flatMap(this::declaredMappingInfo)));
    }

    private Optional<MappingInfo> declaredMappingInfo(JavaSootMethod method) {
        for (AnnotationUsage annotation : method.getAnnotations()) {
            Optional<MappingInfo> info = mappingInfo(annotation);
            if (info.isEmpty()) {
                // A composed annotation, e.g. a custom @GetJson meta-annotated with @RequestMapping (@GetMapping
                // and the other shortcuts target methods alone).
                for (AnnotationUsage meta : context.metaAnnotations(Annotations.name(annotation))) {
                    info = mappingInfo(meta).map(found -> aliasedPaths(annotation, Annotations.name(meta))
                            .map(paths -> new MappingInfo(paths, found.methods(), found.params(), found.conditions()))
                            .orElse(found));
                    if (info.isPresent()) {
                        break;
                    }
                }
            }
            if (info.isPresent()) {
                return info;
            }
        }
        return Optional.empty();
    }

    /**
     * The paths a composed annotation sets through its elements that are {@code @AliasFor} the mapping's
     * {@code path} or {@code value}, as Spring's merged annotation reads them: {@code @GetJson("/orders")} with
     * {@code @AliasFor(annotation = RequestMapping.class, attribute = "path") String[] value()}.
     */
    private Optional<List<String>> aliasedPaths(AnnotationUsage composed, String mapping) {
        List<String> paths = new ArrayList<>();
        for (JavaSootMethod element : context.findClass(Annotations.name(composed)).map(JavaSootClass::getMethods)
                .orElse(Set.of())) {
            for (AnnotationUsage alias : element.getAnnotations()) {
                String attribute = Annotations.string(alias, "attribute").or(() -> Annotations.string(alias, "value"))
                        .orElse(element.getName());
                if (Annotations.name(alias).equals(ALIAS_FOR)
                        && Annotations.className(alias, "annotation").filter(mapping::equals).isPresent()
                        && (attribute.equals("path") || attribute.equals("value"))) {
                    paths.addAll(Annotations.strings(composed, element.getName()));
                }
            }
        }
        return paths.isEmpty() ? Optional.empty() : Optional.of(paths);
    }

    private static Optional<MappingInfo> mappingInfo(AnnotationUsage annotation) {
        String name = Annotations.name(annotation);
        String shortcut = SpringNames.MAPPING_METHODS.get(name);
        String params = String.join("&", Annotations.strings(annotation, "params").stream().sorted().toList());
        List<String> conditions = new ArrayList<>();
        Annotations.strings(annotation, "headers").stream().sorted().forEach(found -> conditions.add("header:" + found));
        Annotations.strings(annotation, "consumes").stream().sorted()
                .forEach(found -> conditions.add("consumes:" + found));
        Annotations.strings(annotation, "produces").stream().sorted()
                .forEach(found -> conditions.add("produces:" + found));
        Annotations.string(annotation, "version").filter(found -> !found.isEmpty())
                .ifPresent(found -> conditions.add("version:" + found));
        if (shortcut != null) {
            return Optional.of(new MappingInfo(paths(annotation), List.of(shortcut), params, conditions));
        }
        if (name.equals(SpringNames.REQUEST_MAPPING)) {
            List<String> methods = Annotations.strings(annotation, "method");
            return Optional.of(new MappingInfo(paths(annotation), methods.isEmpty() ? List.of("*") : methods,
                    params, conditions));
        }
        return Optional.empty();
    }

    /**
     * Each Ingress once: a mapping repeated for the same handler is dropped; a different handler that ends up with an
     * Ingress id already taken (a SOAP operation's local part in two namespaces, overloaded listener methods) is told
     * apart by its handler, so their paths don't mix under one id.
     */
    @Supports(Feature.CALL_PATHS)
    static List<Mapping> unique(List<Mapping> mappings) {
        Map<String, JavaSootMethod> taken = new HashMap<>();
        List<Mapping> result = new ArrayList<>();
        for (Mapping mapping : mappings) {
            Ingress ingress = mapping.ingress();
            JavaSootMethod first = taken.putIfAbsent(ingress.id(), mapping.handler());
            // javac copies a method's annotations to its bridge: the same mapping again.
            if (first != null && (first.equals(mapping.handler()) || MethodModifier.isBridge(mapping.handler()
                    .getModifiers()) || MethodModifier.isSynthetic(mapping.handler().getModifiers()))) {
                continue;
            }
            if (first != null) {
                ingress = ingress.andParams("handler=" + MethodNames.key(mapping.handler().getSignature()));
                // The same handler under the same id again (a method mapped twice): its Ingress is already there.
                if (taken.putIfAbsent(ingress.id(), mapping.handler()) != null) {
                    continue;
                }
            }
            result.add(mapping.withIngress(ingress));
        }
        return result;
    }

    /**
     * Handlers of one path and method told apart by {@code headers}, {@code consumes}, {@code produces} or
     * {@code version} (API versions) are separate Ingress, those conditions after their params:
     * {@code GET /users?version:2}. A handler alone on its path keeps its id.
     */
    List<Mapping> distinct(List<Mapping> mappings) {
        Map<String, Set<JavaSootMethod>> handlers = new HashMap<>();
        mappings.forEach(mapping -> handlers.computeIfAbsent(mapping.ingress().id(), id -> new HashSet<>())
                .add(mapping.handler()));
        List<Mapping> result = new ArrayList<>();
        for (Mapping mapping : mappings) {
            List<String> conditions = handlers.get(mapping.ingress().id()).size() < 2 ? List.of()
                    : mappingInfo(mapping.handler()).map(MappingInfo::conditions).orElse(List.of());
            if (conditions.isEmpty()) {
                result.add(mapping);
                continue;
            }
            result.add(mapping.withIngress(mapping.ingress().andParams(String.join("&", conditions))));
        }
        return result;
    }

    private static List<String> paths(AnnotationUsage annotation) {
        List<String> paths = new ArrayList<>(Annotations.strings(annotation, "value"));
        paths.addAll(Annotations.strings(annotation, "path"));
        return paths.isEmpty() ? List.of("") : paths;
    }

    /**
     * Kotlin's static body of a suspend function, {@code f$suspendImpl}, which carries a copy of its annotations: the
     * function itself is the handler.
     */
    static boolean suspendImpl(JavaSootMethod method) {
        return method.getName().endsWith("$suspendImpl");
    }

    static String join(String prefix, String path) {
        String joined = ("/" + prefix + "/" + path).replaceAll("/+", "/");
        return joined.length() > 1 && joined.endsWith("/") ? joined.substring(0, joined.length() - 1) : joined;
    }

    /**
     * A path variable's regular expression dropped: {@code {label:.*}} is {@code {label}},
     * {@code {zip: \\d{5}}} is {@code {zip}}.
     */
    static String withoutPatterns(String route) {
        StringBuilder result = new StringBuilder();
        int depth = 0;
        boolean skipping = false;
        for (char c : route.toCharArray()) {
            if (c == '{' && depth++ == 0) {
                skipping = false;
                result.append(c);
                continue;
            }
            if (c == '}' && --depth == 0) {
                skipping = false;
                result.append(c);
                continue;
            }
            if (depth == 1 && c == ':') {
                skipping = true;
            }
            if (!skipping) {
                result.append(c);
            }
        }
        return result.toString();
    }
}
