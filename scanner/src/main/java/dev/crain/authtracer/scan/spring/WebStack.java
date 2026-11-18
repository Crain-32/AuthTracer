package dev.crain.authtracer.scan.spring;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.ref.JStaticFieldRef;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Whether the application runs on Spring WebFlux (reactive) or the Servlet stack (decisions 0009, 0079). A Spring Boot
 * application runs the one Boot picks, as 4.1.1 does: {@code WebApplicationType.deduce()} asks its deducers in order
 * ({@code WebMvcWebApplicationTypeDeducer}, {@code @Order(10)}: Servlet when {@code jakarta.servlet.Servlet},
 * {@code DispatcherServlet} and {@code ConfigurableWebApplicationContext} are present; then
 * {@code WebFluxWebApplicationTypeDeducer}, {@code @Order(20)}: reactive when {@code Mono} and
 * {@code DispatcherHandler} are), else Servlet when the Servlet API and {@code ConfigurableWebApplicationContext} are;
 * {@code SpringApplication#setWebApplicationType} (also through {@code SpringApplicationBuilder#web}) replaces that,
 * and {@code spring.main.web-application-type} replaces both, since {@code run} binds {@code spring.main} to the
 * application afterwards. The security configuration it declares doesn't choose: a {@code SecurityWebFilterChain} in
 * a Servlet application never runs. Without Spring Boot, the stack is the one its security configuration is for, else
 * the classpath's.
 */
@Supports({Feature.REQUEST_RULES, Feature.CALL_PATHS})
final class WebStack {

    static final String SECURITY_WEB_FILTER_CHAIN = "org.springframework.security.web.server.SecurityWebFilterChain";
    static final String SECURITY_FILTER_CHAIN = "org.springframework.security.web.SecurityFilterChain";
    static final String ENABLE_WEBFLUX_SECURITY =
            "org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity";
    static final String ENABLE_WEB_SECURITY =
            "org.springframework.security.config.annotation.web.configuration.EnableWebSecurity";
    private static final String SPRING_APPLICATION = "org.springframework.boot.SpringApplication";
    private static final String APPLICATION_BUILDER = "org.springframework.boot.builder.SpringApplicationBuilder";
    private static final String WEB_APPLICATION_TYPE = "org.springframework.boot.WebApplicationType";
    private static final String DISPATCHER_SERVLET = "org.springframework.web.servlet.DispatcherServlet";
    private static final String DISPATCHER_HANDLER = "org.springframework.web.reactive.DispatcherHandler";
    private static final String SERVLET = "jakarta.servlet.Servlet";
    private static final String WEB_CONTEXT = "org.springframework.web.context.ConfigurableWebApplicationContext";

    private WebStack() {
    }

    static boolean reactive(ScanContext context) {
        if (context.findClass(SPRING_APPLICATION).isEmpty()) {
            return declaredReactive(context);
        }
        Optional<String> type = context.properties().get("spring.main.web-application-type")
                .or(() -> chosenInCode(context));
        return type.map(chosen -> chosen.replaceAll("[-_]", "").trim().equalsIgnoreCase("reactive"))
                .orElseGet(() -> deducedReactive(context));
    }

    /**
     * Boot 4.1.1's {@code WebApplicationType.deduce()}: each deducer is in the Boot module of its stack.
     */
    private static boolean deducedReactive(ScanContext context) {
        if (present(context, "org.springframework.boot.webmvc.WebMvcWebApplicationTypeDeducer", SERVLET,
                DISPATCHER_SERVLET, WEB_CONTEXT)) {
            return false;
        }
        return present(context, "org.springframework.boot.webflux.WebFluxWebApplicationTypeDeducer",
                "reactor.core.publisher.Mono", DISPATCHER_HANDLER);
    }

    private static boolean present(ScanContext context, String... classes) {
        for (String name : classes) {
            if (context.findClass(name).isEmpty()) {
                return false;
            }
        }
        return true;
    }

    /**
     * The type the application's code gives {@code SpringApplication} ({@code app.setWebApplicationType(REACTIVE)},
     * Kotlin's {@code runApplication<App> { webApplicationType = REACTIVE }}, {@code builder.web(REACTIVE)}).
     */
    private static Optional<String> chosenInCode(ScanContext context) {
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt).filter(WebStack::setsType);
                    if (invoke.isPresent()) {
                        Value argument = invoke.get().getArg(0);
                        Value value = argument instanceof Local local
                                ? Locals.definition(method.getBody(), local).orElse(argument) : argument;
                        if (value instanceof JStaticFieldRef field && field.getFieldSignature().getDeclClassType()
                                .getFullyQualifiedName().equals(WEB_APPLICATION_TYPE)) {
                            return Optional.of(field.getFieldSignature().getName().toLowerCase(Locale.ROOT));
                        }
                    }
                }
            }
        }
        return Optional.empty();
    }

    private static boolean setsType(AbstractInvokeExpr invoke) {
        String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = invoke.getMethodSignature().getName();
        return invoke.getArgCount() == 1 && (owner.equals(SPRING_APPLICATION) && name.equals("setWebApplicationType")
                || owner.equals(APPLICATION_BUILDER) && name.equals("web"));
    }

    private static boolean declaredReactive(ScanContext context) {
        if (declares(context, SECURITY_WEB_FILTER_CHAIN, ENABLE_WEBFLUX_SECURITY)) {
            return true;
        }
        if (declares(context, SECURITY_FILTER_CHAIN, ENABLE_WEB_SECURITY)) {
            return false;
        }
        return context.findClass(DISPATCHER_SERVLET).isEmpty() && context.findClass(DISPATCHER_HANDLER).isPresent();
    }

    private static boolean declares(ScanContext context, String chainType, String enableAnnotation) {
        return context.anyClassAnnotated(enableAnnotation)
                || !SpringBeans.beanMethodsOf(context, Set.of(chainType)).isEmpty();
    }

    /**
     * Security configuration for the other stack never runs: a {@code SecurityWebFilterChain} (or, without one,
     * {@code @EnableWebFluxSecurity}) in a Servlet application filters nothing, nor does a {@code SecurityFilterChain}
     * (or {@code @EnableWebSecurity}) in a reactive one.
     */
    @Supports(Feature.FINDING_NOT_ENFORCED)
    static void report(ScanContext context, GraphBuilder graph, boolean reactive) {
        String chainType = reactive ? SECURITY_FILTER_CHAIN : SECURITY_WEB_FILTER_CHAIN;
        String enable = reactive ? ENABLE_WEB_SECURITY : ENABLE_WEBFLUX_SECURITY;
        String why = reactive ? "this is a reactive application, which has no servlet filters"
                : "this is a Servlet application (Spring Boot picks the Servlet stack when Spring MVC's"
                        + " DispatcherServlet is on the classpath, unless spring.main.web-application-type=reactive),"
                        + " so the request rules are the Servlet chain's";
        List<JavaSootMethod> chains = SpringBeans.beanMethodsOf(context, Set.of(chainType));
        for (JavaSootMethod method : chains) {
            graph.finding(new Finding(Finding.Kind.NOT_ENFORCED, "The " + MethodNames.simpleName(chainType) + " "
                    + MethodNames.key(method.getSignature()) + " never runs: " + why,
                    MethodNames.codeRef(method.getSignature())));
        }
        for (JavaSootClass cls : chains.isEmpty() ? context.applicationClasses() : List.<JavaSootClass>of()) {
            if (context.hasAnnotation(cls, enable)) {
                graph.finding(new Finding(Finding.Kind.NOT_ENFORCED, "@" + MethodNames.simpleName(enable) + " on "
                        + cls.getType().getFullyQualifiedName() + " secures nothing: " + why,
                        CodeRef.ofClass(cls.getType().getFullyQualifiedName())));
            }
        }
    }
}
