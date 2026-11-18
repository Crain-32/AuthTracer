package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.constant.ClassConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.ClassType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0052: JAX-RS resources on Spring Boot's Jersey support (Jersey 4). A {@code ResourceConfig} (a subclass, or
 * a {@code @Bean}) registers resource classes ({@code register(X.class)}, {@code packages("..")}; without either
 * AuthTracer can read, every {@code @Path} class); each {@code @GET}/{@code @POST}/... method is an Ingress at the
 * application path ({@code spring.jersey.application-path}, else {@code @ApplicationPath}), the class's {@code @Path}
 * and the method's. The servlet filter chain checks them like any request; resources that are Spring beans get method
 * security too.
 */
@Supports(Feature.HTTP_ENDPOINTS)
final class JaxRsResources {

    private static final String RESOURCE_CONFIG = "org.glassfish.jersey.server.ResourceConfig";
    private static final String PATH = "jakarta.ws.rs.Path";
    private static final String APPLICATION_PATH = "jakarta.ws.rs.ApplicationPath";
    private static final Map<String, String> METHODS = Map.of("jakarta.ws.rs.GET", "GET", "jakarta.ws.rs.POST", "POST",
            "jakarta.ws.rs.PUT", "PUT", "jakarta.ws.rs.DELETE", "DELETE", "jakarta.ws.rs.PATCH", "PATCH",
            "jakarta.ws.rs.HEAD", "HEAD", "jakarta.ws.rs.OPTIONS", "OPTIONS");
    private static final Set<String> REGISTER = Set.of("register", "registerClasses");

    private static final String ROLES_FEATURE = "org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature";

    static final String MECHANISM = "@RolesAllowed (Jersey)";

    private final ScanContext context;
    private final String rolePrefix;
    /**
     * By resource method: the check Jersey's {@code RolesAllowedDynamicFeature} makes before the resource method runs.
     */
    private final Map<JavaSootMethod, AuthorizationLocation> jerseyChecks = new HashMap<>();

    /**
     * @param rolePrefix the GrantedAuthorityDefaults prefix, which isUserInRole adds to a role without it
     */
    JaxRsResources(ScanContext context, String rolePrefix) {
        this.context = context;
        this.rolePrefix = rolePrefix;
    }

    Map<JavaSootMethod, AuthorizationLocation> jerseyChecks() {
        return jerseyChecks;
    }

    List<RequestMappings.Mapping> detect() {
        List<RequestMappings.Mapping> mappings = new ArrayList<>();
        if (context.findClass(RESOURCE_CONFIG).isEmpty()) {
            return mappings;
        }
        List<String> registered = new ArrayList<>();
        List<String> packages = new ArrayList<>();
        String applicationPath = null;
        boolean configured = false;
        for (JavaSootClass cls : context.applicationClasses()) {
            boolean subclass = context.superClassesOf(cls.getType()).stream()
                    .anyMatch(type -> type.getFullyQualifiedName().equals(RESOURCE_CONFIG));
            if (subclass) {
                configured = true;
                applicationPath = context.findAnnotation(cls, APPLICATION_PATH)
                        .flatMap(annotation -> Annotations.string(annotation, "value")).orElse(applicationPath);
            }
            for (JavaSootMethod method : cls.getMethods()) {
                boolean bean = context.hasAnnotation(method, SpringNames.BEAN) && method.getReturnType()
                        instanceof ClassType type && (type.getFullyQualifiedName().equals(RESOURCE_CONFIG)
                                || context.superClassesOf(type).stream()
                                        .anyMatch(superType -> superType.getFullyQualifiedName().equals(RESOURCE_CONFIG)));
                if (!method.hasBody() || !(subclass || bean)) {
                    continue;
                }
                configured = true;
                for (Stmt stmt : method.getBody().getStmts()) {
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                    if (invoke.isEmpty()) {
                        continue;
                    }
                    String name = invoke.get().getMethodSignature().getName();
                    if (REGISTER.contains(name)) {
                        // register(X.class), and the varargs array of registerClasses(X.class, Y.class).
                        invoke.get().getArgs().stream().flatMap(arg -> arg instanceof Local array
                                ? Locals.elements(method.getBody(), array).stream() : Stream.of(arg))
                                .filter(ClassConstant.class::isInstance)
                                .map(constant -> className((ClassConstant) constant)).forEach(registered::add);
                    }
                    else if (name.equals("packages")) {
                        packages.addAll(strings(method, invoke.get()));
                    }
                }
            }
        }
        if (!configured) {
            return mappings;
        }
        // Spring Boot's JerseyAutoConfiguration: the property, else the subclass's @ApplicationPath.
        String annotated = applicationPath;
        String base = context.properties().get("spring.jersey.application-path")
                .or(() -> Optional.ofNullable(annotated)).orElse("");
        // Jersey's own @RolesAllowed filter, a feature registered like a resource.
        boolean roles = registered.remove(ROLES_FEATURE);
        boolean all = registered.isEmpty() && packages.isEmpty();
        for (JavaSootClass cls : context.applicationClasses()) {
            String name = cls.getType().getFullyQualifiedName();
            Optional<String> classPath = context.findAnnotation(cls, PATH)
                    .flatMap(annotation -> Annotations.string(annotation, "value"));
            if (classPath.isEmpty() || !(all || registered.contains(name) || packages.stream()
                    .anyMatch(pkg -> name.startsWith(pkg + ".")))) {
                continue;
            }
            for (JavaSootMethod method : cls.getMethods()) {
                Optional<String> httpMethod = METHODS.entrySet().stream()
                        .filter(entry -> context.hasAnnotation(method, entry.getKey())).map(Map.Entry::getValue)
                        .findFirst();
                if (httpMethod.isEmpty()) {
                    continue;
                }
                String methodPath = context.findAnnotation(method, PATH)
                        .flatMap(annotation -> Annotations.string(annotation, "value")).orElse("");
                String route = RequestMappings.withoutPatterns(RequestMappings.join(RequestMappings.join(base,
                        classPath.get()), methodPath));
                Ingress ingress = Ingress.of(httpMethod.get(), route, MethodNames.codeRef(method.getSignature()));
                mappings.add(new RequestMappings.Mapping(ingress, method));
                if (roles) {
                    jerseyCheck(cls, method).ifPresent(check -> jerseyChecks.put(method, check));
                }
            }
        }
        return mappings;
    }

    /**
     * {@code RolesAllowedDynamicFeature}: the method's {@code @DenyAll}, {@code @RolesAllowed} or {@code @PermitAll},
     * else the class's {@code @RolesAllowed}, checked with
     * {@code SecurityContext.isUserInRole}, which Spring Security's request wrapper answers from the authorities with
     * the {@code ROLE_} prefix.
     */
    @Supports(Feature.METHOD_SECURITY)
    private Optional<AuthorizationLocation> jerseyCheck(JavaSootClass cls, JavaSootMethod method) {
        // RolesAllowedDynamicFeature's order: the method's @DenyAll, @RolesAllowed, @PermitAll, then the class's
        // @RolesAllowed.
        Requirement requirement = requirement(context.hasAnnotation(method, SpringNames.DENY_ALL),
                context.findAnnotation(method, SpringNames.ROLES_ALLOWED),
                context.hasAnnotation(method, SpringNames.PERMIT_ALL))
                .or(() -> requirement(false, context.findAnnotation(cls, SpringNames.ROLES_ALLOWED), false))
                .orElse(null);
        if (requirement == null) {
            return Optional.empty();
        }
        return Optional.of(new AuthorizationLocation("location:METHOD:" + MethodNames.key(method.getSignature())
                + ":jersey-roles", MECHANISM, AuthorizationLocation.Scope.METHOD,
                AuthorizationLocation.Phase.PRE, requirement, MethodNames.codeRef(method.getSignature()), null, null,
                AuthorizationLocation.Denial.THROW, false));
    }

    private Optional<Requirement> requirement(boolean denyAll, Optional<AnnotationUsage> rolesAllowed,
            boolean permitAll) {
        if (denyAll) {
            return Optional.of(Requirement.denyAll());
        }
        Optional<Requirement> roles = rolesAllowed.map(annotation -> Requirement.anyAuthority(Annotations
                .strings(annotation, "value").stream().map(role -> role.startsWith(rolePrefix) ? role
                        : rolePrefix + role).toList()));
        return roles.isPresent() || !permitAll ? roles : Optional.of(Requirement.permitAll());
    }

    private static String className(ClassConstant constant) {
        String descriptor = constant.getValue();
        if (descriptor.startsWith("L") && descriptor.endsWith(";")) {
            descriptor = descriptor.substring(1, descriptor.length() - 1);
        }
        return descriptor.replace('/', '.');
    }

    private static List<String> strings(JavaSootMethod method, AbstractInvokeExpr invoke) {
        return invoke.getArgs().stream().flatMap(argument -> Locals.strings(method.getBody(), argument).stream())
                .toList();
    }
}
