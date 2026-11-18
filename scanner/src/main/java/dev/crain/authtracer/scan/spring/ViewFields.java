package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.stream.Stream;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.ClassFileMetadata.GenericType;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.flow.GenericTypes;
import dev.crain.authtracer.scan.flow.ResponseFields;
import dev.crain.authtracer.scan.flow.Shape;
import dev.crain.authtracer.scan.flow.TypeProperties;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0035: what a rendered view exposes, as the fields of a response of type {@code view:owners/ownerDetails}.
 * With its Thymeleaf template or JSP, one field per model path the template reads ({@code owner.pets[].name}), each
 * with a flow from the domain field it shows ({@code Pet.name}) and, inside a {@code sec:authorize} element, a field
 * check. Without a template AuthTracer can find, every model attribute, with all its properties.
 * <p>
 * Decision 0081 (AUTHZ-14): a guard by URL asks what the request rules ask of that request, as Spring's
 * {@code WebInvocationPrivilegeEvaluator} does (7.1.1 {@code AuthorizationManagerWebInvocationPrivilegeEvaluator}
 * asks the {@code AuthorizationFilter}'s manager); a URL no chain authorizes is allowed.
 */
@Supports(Feature.VIEW_FIELDS)
final class ViewFields {

    private static final String VIEW_RESOLVER_REGISTRY =
            "org.springframework.web.servlet.config.annotation.ViewResolverRegistry";

    private final ScanContext context;
    private final GraphBuilder graph;
    private final TypeProperties properties;
    private final GenericTypes types;
    private final ResponseFields responseFields;
    /**
     * What the request rules ask of a request, by method and path.
     */
    private final BiFunction<String, String, Optional<Requirement>> requestRules;
    private final String servletPath;
    /**
     * Thymeleaf's templates, then the JSPs a JSP view resolver renders.
     */
    private final List<ViewTemplates> templates = new ArrayList<>();

    /**
     * @param requestRules what the request rules ask of a request, by method and path within the application
     */
    ViewFields(ScanContext context, GraphBuilder graph, TypeProperties properties, GenericTypes types,
            ResponseFields responseFields, SecurityXml.Config xml,
            BiFunction<String, String, Optional<Requirement>> requestRules) {
        this.context = context;
        this.graph = graph;
        this.properties = properties;
        this.types = types;
        this.responseFields = responseFields;
        this.requestRules = requestRules;
        this.servletPath = context.properties().get("spring.mvc.servlet.path")
                .map(path -> ("/" + path).replaceAll("/+", "/").replaceAll("/$", "")).orElse("");
        templates.add(new ViewTemplates(context.input().resourceDirs(), relative(context.properties()
                .get("spring.thymeleaf.prefix").orElse("classpath:/templates/")), context.properties()
                        .get("spring.thymeleaf.suffix").orElse(".html"), ViewTemplates.Dialect.THYMELEAF));
        // FreeMarker: the template loader path (classpath:/templates/), its prefix and .ftlh.
        String freeMarkerPath = context.properties().get("spring.freemarker.template-loader-path")
                .orElse("classpath:/templates/").split(",")[0].trim();
        templates.add(new ViewTemplates(context.input().resourceDirs(), relative(freeMarkerPath.endsWith("/")
                ? freeMarkerPath : freeMarkerPath + "/") + context.properties().get("spring.freemarker.prefix")
                        .orElse(""), context.properties().get("spring.freemarker.suffix").orElse(".ftlh"),
                ViewTemplates.Dialect.FREEMARKER));
        jspResolver(xml).ifPresent(resolver -> templates.add(new ViewTemplates(
                context.input().resourceDirs().stream().flatMap(dir -> Stream.of(dir,
                        dir.resolve("META-INF/resources"))).toList(), relative(resolver.prefix()), resolver.suffix(),
                ViewTemplates.Dialect.JSP)));
    }

    private static String relative(String prefix) {
        return prefix.replaceFirst("^classpath\\*?:", "").replaceFirst("^/", "");
    }

    /**
     * Where JSP views are: Boot's {@code spring.mvc.view.prefix}/{@code suffix}, an XML-defined
     * {@code InternalResourceViewResolver}, or one the application's code creates or registers with constants.
     */
    private Optional<SecurityXml.ViewResolver> jspResolver(SecurityXml.Config xml) {
        Optional<String> prefix = context.properties().get("spring.mvc.view.prefix");
        Optional<String> suffix = context.properties().get("spring.mvc.view.suffix");
        if (prefix.isPresent() || suffix.isPresent()) {
            return Optional.of(new SecurityXml.ViewResolver(prefix.orElse(""), suffix.orElse("")));
        }
        if (xml.viewResolver().isPresent()) {
            return xml.viewResolver();
        }
        String foundPrefix = null;
        String foundSuffix = null;
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    Optional<AbstractInvokeExpr> found = Locals.invoke(stmt);
                    if (found.isEmpty()) {
                        continue;
                    }
                    AbstractInvokeExpr invoke = found.get();
                    String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
                    String name = invoke.getMethodSignature().getName();
                    List<String> constants = invoke.getArgs().stream().map(arg -> arg instanceof StringConstant
                            constant ? constant.getValue() : null).toList();
                    if (owner.equals(VIEW_RESOLVER_REGISTRY) && name.equals("jsp")) {
                        // registry.jsp(): /WEB-INF/ and .jsp.
                        return Optional.of(constants.size() == 2 && !constants.contains(null)
                                ? new SecurityXml.ViewResolver(constants.get(0), constants.get(1))
                                : new SecurityXml.ViewResolver("/WEB-INF/", ".jsp"));
                    }
                    if (!SecurityXml.JSP_VIEW_RESOLVERS.contains(owner) || constants.contains(null)) {
                        continue;
                    }
                    if (name.equals("<init>") && constants.size() == 2) {
                        foundPrefix = constants.get(0);
                        foundSuffix = constants.get(1);
                    }
                    else if (name.equals("setPrefix") && constants.size() == 1) {
                        foundPrefix = constants.getFirst();
                    }
                    else if (name.equals("setSuffix") && constants.size() == 1) {
                        foundSuffix = constants.getFirst();
                    }
                }
            }
        }
        return foundPrefix == null && foundSuffix == null ? Optional.empty()
                : Optional.of(new SecurityXml.ViewResolver(foundPrefix == null ? "" : foundPrefix,
                        foundSuffix == null ? "" : foundSuffix));
    }

    /**
     * Adds the view's fields for the request path, and returns its field checks, in template order.
     */
    List<String> expose(String path, ViewModels.View view) {
        List<ViewTemplates.Read> reads = new ArrayList<>();
        // Each template's file, for its checks' locations.
        Map<String, String> files = new HashMap<>();
        boolean templated = false;
        for (String name : view.names()) {
            for (ViewTemplates reader : templates) {
                Optional<List<ViewTemplates.Read>> found = reader.reads(name);
                if (found.isPresent()) {
                    templated = true;
                    reads.addAll(found.get());
                    found.get().forEach(read -> {
                        files.putIfAbsent(read.template(), reader.file(read.template()));
                        files.putIfAbsent(read.guardTemplate(), reader.file(read.guardTemplate()));
                    });
                    break;
                }
            }
        }
        if (!templated) {
            view.attributes().forEach((name, type) -> {
                graph.node(Field.of(view.owner(), name, name, type.name()));
                responseFields.expose(path, type.name(), Shape.EMPTY);
            });
            return List.of();
        }
        // Only the model's attributes: other names are the template's own (fragment parameters, local variables) or
        // its context's (request, session).
        Map<String, List<ViewTemplates.Read>> byPath = new LinkedHashMap<>();
        reads.stream().filter(read -> view.attributes().containsKey(read.path().split("[.\\[]", 2)[0]))
                .forEach(read -> byPath.computeIfAbsent(read.path(), key -> new ArrayList<>()).add(read));
        List<String> checks = new ArrayList<>();
        byPath.forEach((modelPath, readsOfPath) -> {
            Optional<Source> source = source(modelPath, view.attributes());
            Field field = graph.node(Field.of(view.owner(), modelPath.replace('.', ':'), modelPath,
                    source.map(Source::type).orElse("?")));
            source.ifPresent(found -> {
                graph.node(Field.of(found.owner(), found.property().name(), found.property().jsonName(),
                        found.property().type()));
                graph.flow(Flow.local(path, Field.id(found.owner(), found.property().name()), field.id(),
                        FieldSource.DIRECT));
            });
            // Shown unguarded anywhere, the field isn't guarded; shown under different guards, passing any of them
            // shows it.
            if (readsOfPath.stream().noneMatch(read -> read.guards().isEmpty())) {
                ViewTemplates.Read guarded = readsOfPath.getFirst();
                List<Requirement> alternatives = readsOfPath.stream().map(read -> {
                    List<Requirement> required = read.guards().stream().map(this::guard).toList();
                    return required.size() == 1 ? required.getFirst() : Requirement.and(required);
                }).distinct().toList();
                // The view and every guard in the id: another view showing the same fragment's field has its own
                // check, as does one showing it under only some of the guards.
                String guards = String.join(",", readsOfPath.stream().map(read -> read.guardTemplate() + ":"
                        + read.guardLine()).distinct().toList());
                AuthorizationLocation check = graph.node(new AuthorizationLocation("location:FIELD:template:"
                        + view.owner() + ":" + guards + ":" + modelPath, "sec:authorize",
                        AuthorizationLocation.Scope.FIELD, AuthorizationLocation.Phase.POST,
                        alternatives.size() == 1 ? alternatives.getFirst() : Requirement.or(alternatives),
                        CodeRef.ofClass(files.get(guarded.guardTemplate())).atLine(guarded.guardLine()), field.name(),
                        null, new AuthorizationLocation.Denial(AuthorizationLocation.Denial.Kind.NULL, null), false,
                        view.owner()));
                checks.add(check.id());
            }
        });
        return checks;
    }

    /**
     * What a guard asks: its expression's requirement, or for {@code url:GET /admin} what the request rules ask of
     * that request ({@code ${..}} in it as a path variable, the query left out, the DispatcherServlet's path
     * dropped, since the rules are given the path within the servlet).
     */
    private Requirement guard(String guard) {
        if (!guard.startsWith(ViewTemplates.URL_GUARD)) {
            return SpelRequirements.standard(guard);
        }
        String[] request = guard.substring(ViewTemplates.URL_GUARD.length()).split(" ", 2);
        String path = request[1].replaceAll("\\$\\{[^}]*}", "{value}").replaceFirst("[?#].*$", "");
        if (!servletPath.isEmpty() && (path.equals(servletPath) || path.startsWith(servletPath + "/"))) {
            path = path.substring(servletPath.length());
        }
        return requestRules.apply(request[0], path.isEmpty() ? "/" : path).orElse(Requirement.permitAll());
    }

    /**
     * The domain field a model path shows: {@code owner.pets[].name} is {@code Pet.name}.
     *
     * @param type the shown value's type
     */
    private record Source(String owner, TypeProperties.Property property, String type) {
    }

    /**
     * @param modelPath a path from one of the attributes
     */
    private Optional<Source> source(String modelPath, Map<String, GenericType> attributes) {
        String[] segments = modelPath.split("\\.");
        GenericType current = attributes.get(segments[0].replace("[]", ""));
        if (segments[0].endsWith("[]")) {
            current = types.element(current);
        }
        Source found = null;
        for (int i = 1; i < segments.length; i++) {
            boolean many = segments[i].endsWith("[]");
            String name = segments[i].replace("[]", "");
            Optional<TypeProperties.Property> property = properties.byName(current.name(), name);
            if (property.isEmpty()) {
                return Optional.empty();
            }
            GenericType declared = context.classFiles().genericFieldType(current.name(), name)
                    .orElse(new GenericType(property.get().type(), List.of()));
            found = new Source(current.name(), property.get(), declared.name());
            current = many ? types.element(declared) : declared;
        }
        return Optional.ofNullable(found);
    }
}
