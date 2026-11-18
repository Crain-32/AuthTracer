package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Might;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.GroovyCalls;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.constant.NullConstant;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.PrimitiveType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * FIELD-06 (decision 0077): an application's own {@code AuthorizationAdvisor} beans. Spring Security 7.1.1's
 * {@code AuthorizationProxyConfiguration.authorizationProxyFactory} gives the proxy factory every
 * {@code AuthorizationAdvisor} bean, so such an advisor guards the objects {@code @AuthorizeReturnObject} methods
 * and {@code AuthorizationProxyFactory#proxy} return; like any advisor, it guards beans too where an auto-proxy
 * creator applies it (see {@link MethodAdvisors}). Its pointcut is read where it is an
 * {@code AspectJExpressionPointcut} or an {@code AnnotationMatchingPointcut} built with constants; its advice is
 * not read, so it is a custom requirement, and a finding says so.
 */
@Supports({Feature.METHOD_SECURITY, Feature.FIELD_CHECKS})
final class CustomAdvisors {

    private static final String AUTHORIZATION_ADVISOR =
            "org.springframework.security.authorization.method.AuthorizationAdvisor";
    private static final String ASPECTJ_POINTCUT = "org.springframework.aop.aspectj.AspectJExpressionPointcut";
    private static final String ANNOTATION_POINTCUT =
            "org.springframework.aop.support.annotation.AnnotationMatchingPointcut";
    private static final String ROLE = "org.springframework.context.annotation.Role";

    /**
     * @param expression the pointcut as an AspectJ expression
     * @param beans whether an auto-proxy creator applies it to beans
     * @param proxies whether it guards the objects the proxy factory proxies
     */
    record Advisor(JavaSootClass type, Pointcuts.Pointcut pointcut, String expression, int order, boolean beans,
            boolean proxies) {
    }

    private final List<Advisor> advisors = new ArrayList<>();

    /**
     * @param proxyFactory whether Spring Security's {@code AuthorizationProxyFactory} bean exists
     *        ({@code @EnableMethodSecurity} imports {@code AuthorizationProxyConfiguration})
     */
    @Supports({Feature.FINDING_NOT_ENFORCED, Feature.FINDING_OPAQUE_CONFIG})
    CustomAdvisors(ScanContext context, GraphBuilder graph, SpringBeans beans, boolean proxyFactory) {
        Pointcuts pointcuts = new Pointcuts(context);
        boolean boot = AutoProxyCreators.boot(context);
        boolean aspectJ = AutoProxyCreators.aspectJ(context);
        for (JavaSootClass cls : context.applicationClasses()) {
            if (cls.isInterface() || cls.isAbstract() || !beans.isBean(cls.getType())
                    || !SpringBeans.assignable(context, cls.getType(), Set.of(AUTHORIZATION_ADVISOR))) {
                continue;
            }
            // The same auto-proxy creators as MethodAdvisors': AspectJ's applies every advisor, the others those
            // with the infrastructure role.
            boolean onBeans = aspectJ || infrastructure(context, cls) && (proxyFactory || boot);
            if (!onBeans && !proxyFactory) {
                graph.finding(new Finding(Finding.Kind.NOT_ENFORCED, "The AuthorizationAdvisor bean " + cls.getName()
                        + " never runs: nothing auto-proxies beans and there is no AuthorizationProxyFactory"
                        + " (no @EnableMethodSecurity" + AutoProxyCreators.bootOff(context) + ")",
                        CodeRef.ofClass(cls.getName())));
                continue;
            }
            Optional<String> expression = expression(cls);
            Optional<Pointcuts.Pointcut> pointcut = expression.flatMap(pointcuts::parse);
            pointcut.ifPresent(found -> advisors.add(new Advisor(cls, found, expression.get(), order(cls), onBeans,
                    proxyFactory)));
            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The AuthorizationAdvisor bean " + cls.getName()
                    + " runs advice of its own on " + (onBeans && proxyFactory ? "the beans and the objects"
                            + " AuthorizationProxyFactory proxies (@AuthorizeReturnObject)" : onBeans ? "the beans"
                                    : "the objects AuthorizationProxyFactory proxies (@AuthorizeReturnObject)")
                    + " that its pointcut matches"
                    + (pointcut.isPresent() ? " (" + expression.get() + "); AuthTracer doesn't read what it decides,"
                            + " so it shows there as a custom check"
                            : expression.map(found -> " (" + found + ", which AuthTracer can't read)").orElse("")
                                    + "; AuthTracer doesn't read its pointcut or what it decides, so the methods it"
                                    + " guards show no check for it"), CodeRef.ofClass(cls.getName())));
        }
    }

    List<Advisor> advisors() {
        return advisors;
    }

    /**
     * {@code @Role(BeanDefinition.ROLE_INFRASTRUCTURE)} on the class, or on a {@code @Bean} method that creates it.
     */
    private static boolean infrastructure(ScanContext context, JavaSootClass cls) {
        if (role(cls.getAnnotations())) {
            return true;
        }
        for (JavaSootMethod bean : SpringBeans.beanMethods(context)) {
            boolean creates = bean.getReturnType().equals(cls.getType()) || bean.hasBody() && bean.getBody()
                    .getStmts().stream().anyMatch(stmt -> stmt instanceof AbstractDefinitionStmt definition
                            && definition.getRightOp() instanceof JNewExpr created
                            && created.getType().equals(cls.getType()));
            if (creates && role(bean.getAnnotations())) {
                return true;
            }
        }
        return false;
    }

    private static boolean role(Iterable<AnnotationUsage> annotations) {
        for (AnnotationUsage annotation : annotations) {
            if (Annotations.name(annotation).equals(ROLE)
                    && Annotations.integer(annotation, "value").filter(role -> role == 2).isPresent()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Its {@code getOrder()}'s constant; 0 when it isn't one.
     */
    private static int order(JavaSootClass cls) {
        for (JavaSootMethod method : cls.getMethods()) {
            if (method.getName().equals("getOrder") && method.getParameterCount() == 0 && method.hasBody()) {
                List<Stmt> returns = method.getBody().getStmts().stream().filter(JReturnStmt.class::isInstance)
                        .toList();
                if (returns.size() == 1 && ((JReturnStmt) returns.getFirst()).getOp() instanceof IntConstant order) {
                    return order.getValue();
                }
            }
        }
        return 0;
    }

    /**
     * The one pointcut the class builds, as an AspectJ expression: an {@code AspectJExpressionPointcut}'s
     * {@code setExpression("..")}, or an {@code AnnotationMatchingPointcut} of constant annotation types.
     */
    @Might("Read pointcuts built from Spring's Pointcuts and ComposablePointcut, and ones a getPointcut() delegates to")
    private static Optional<String> expression(JavaSootClass cls) {
        List<Optional<String>> found = new ArrayList<>();
        for (JavaSootMethod method : cls.getMethods()) {
            if (!method.hasBody()) {
                continue;
            }
            for (Stmt stmt : method.getBody().getStmts()) {
                Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                if (invoke.isEmpty()) {
                    continue;
                }
                String owner = invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
                String name = invoke.get().getMethodSignature().getName();
                List<Immediate> args = invoke.get().getArgs();
                if (owner.equals(ASPECTJ_POINTCUT) && name.equals("setExpression") && args.size() == 1) {
                    found.add(args.getFirst() instanceof StringConstant text ? Optional.of(text.getValue())
                            : Optional.empty());
                }
                else if (owner.equals(ANNOTATION_POINTCUT) && List.of("<init>", "forMethodAnnotation",
                        "forClassAnnotation").contains(name)) {
                    found.add(annotationExpression(name, args));
                }
            }
        }
        return found.size() == 1 ? found.getFirst() : Optional.empty();
    }

    /**
     * {@code new AnnotationMatchingPointcut(classType[, methodType][, checkInherited])},
     * {@code forMethodAnnotation(type)} and {@code forClassAnnotation(type)}, with constant (or {@code null}) types.
     */
    private static Optional<String> annotationExpression(String name, List<Immediate> args) {
        List<Optional<String>> types = args.stream().filter(arg -> !(arg.getType() instanceof PrimitiveType))
                .map(arg -> arg instanceof NullConstant ? Optional.of("") : GroovyCalls.className(arg)).toList();
        if (types.isEmpty() || types.stream().anyMatch(Optional::isEmpty)) {
            return Optional.empty();
        }
        String classType = name.equals("forMethodAnnotation") ? "" : types.getFirst().get();
        String methodType = name.equals("forMethodAnnotation") ? types.getFirst().get()
                : types.size() > 1 ? types.get(1).get() : "";
        List<String> parts = new ArrayList<>();
        if (!classType.isEmpty()) {
            parts.add("@within(" + classType + ")");
        }
        if (!methodType.isEmpty()) {
            parts.add("@annotation(" + methodType + ")");
        }
        return parts.isEmpty() ? Optional.empty() : Optional.of(String.join(" && ", parts));
    }
}
