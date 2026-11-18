package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.spring.HttpSecurityRules.Matcher;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0097: the beans Spring Security's XML namespace refers to by name ({@code request-matcher-ref},
 * {@code authorization-manager-ref}): a {@code <bean id class>} of the XML, or a component or {@code @Bean} method of
 * the application's code.
 */
@Supports({Feature.REQUEST_RULES, Feature.METHOD_SECURITY})
final class XmlReferences {

    private static final String REQUEST_MATCHER = "org.springframework.security.web.util.matcher.RequestMatcher";
    private static final String REGEX_MATCHER = "org.springframework.security.web.util.matcher.RegexRequestMatcher";
    private static final String REQUEST = "jakarta.servlet.http.HttpServletRequest";
    private static final Set<String> HTTP_METHODS = Set.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE",
            "OPTIONS", "TRACE");

    private final ScanContext context;
    private final SecurityXml.Config xml;

    XmlReferences(ScanContext context, SecurityXml.Config xml) {
        this.context = context;
        this.xml = xml;
    }

    /**
     * The {@code RequestMatcher} bean of that name: Spring's {@code RegexRequestMatcher} given constant
     * constructor arguments, or the application's class or lambda, whose test AuthTracer reads as it reads a
     * {@code requestMatchers(..)} lambda (HTTP-06); else a matcher that may match any request (decision 0051).
     *
     * @param servletPath the DispatcherServlet's path, empty for {@code /}
     */
    Matcher requestMatcher(String name, String servletPath) {
        SecurityXml.Bean bean = xml.beansById().get(name);
        if (bean != null && bean.className().equals(REGEX_MATCHER) && !bean.arguments().isEmpty()
                && !bean.arguments().contains(null)) {
            // RegexRequestMatcher(pattern, httpMethod[, caseInsensitive]); an empty method is any method.
            String method = bean.arguments().size() > 1 && HTTP_METHODS.contains(bean.arguments().get(1))
                    ? bean.arguments().get(1) : null;
            return Matcher.regex(method, bean.arguments().getFirst());
        }
        Optional<JavaSootMethod> test = bean != null ? classTest(context.type(bean.className()))
                : appBean(name).flatMap(found -> found.factory() == null || context.isApplication(found.type())
                        ? classTest(found.type()) : Optional.empty());
        if (test.isPresent()) {
            return MatcherLambdas.read(context, test.get().getSignature(), List.of(), servletPath)
                    .orElse(Matcher.custom("RequestMatcher"));
        }
        Optional<JavaSootMethod> factory = bean == null ? appBean(name).map(DecisionCode.Bean::factory)
                : Optional.empty();
        return factory.flatMap(method -> lambda(method, servletPath)).orElse(Matcher.custom("RequestMatcher"));
    }

    /**
     * What the {@code AuthorizationManager} bean of that name decides, when it is the application's code: an XML
     * bean of an application class, a component, or a {@code @Bean} method's class or lambda.
     */
    @Supports(Feature.CUSTOM_DECISIONS)
    Optional<Requirement> manager(String name, String expression) {
        SecurityXml.Bean bean = xml.beansById().get(name);
        if (bean != null) {
            return DecisionCode.of(context).created(context.type(bean.className()), expression);
        }
        return DecisionCode.of(context).namedManager(name, expression);
    }

    /**
     * The {@code @Bean} method of that name, when the application's code has one.
     */
    Optional<JavaSootMethod> beanMethod(String name) {
        return xml.beansById().containsKey(name) ? Optional.empty()
                : appBean(name).map(DecisionCode.Bean::factory);
    }

    private Optional<DecisionCode.Bean> appBean(String name) {
        return DecisionCode.of(context).named(name);
    }

    /**
     * An application class's {@code matches(HttpServletRequest)}.
     */
    private Optional<JavaSootMethod> classTest(ClassType type) {
        if (!context.isApplication(type) || !SpringBeans.assignable(context, type, Set.of(REQUEST_MATCHER))) {
            return Optional.empty();
        }
        return context.findClass(type).stream().map(JavaSootClass::getMethods).flatMap(java.util.Collection::stream)
                .filter(method -> method.getName().equals("matches") && method.getParameterCount() == 1
                        && method.getParameterType(0).toString().equals(REQUEST) && method.hasBody())
                .findFirst();
    }

    /**
     * The lambda or method reference a {@code @Bean RequestMatcher} method returns, read with the constants it
     * captures.
     */
    private Optional<Matcher> lambda(JavaSootMethod factory, String servletPath) {
        if (factory == null || !factory.hasBody()) {
            return Optional.empty();
        }
        for (Stmt stmt : factory.getBody().getStmts()) {
            if (stmt instanceof JReturnStmt returned && returned.getOp() instanceof Local local
                    && Locals.definition(factory.getBody(), local).orElse(null) instanceof JDynamicInvokeExpr dynamic) {
                Optional<MethodSignature> target = DecisionCode.lambdaTarget(dynamic)
                        .filter(found -> context.isApplication(found.getDeclClassType()));
                if (target.isEmpty()) {
                    return Optional.empty();
                }
                List<String> captured = new ArrayList<>();
                for (Immediate arg : dynamic.getArgs()) {
                    Value value = arg instanceof Local copy ? Locals.definition(factory.getBody(), copy).orElse(arg)
                            : arg;
                    captured.add(value instanceof StringConstant constant ? constant.getValue() : null);
                }
                boolean instance = context.findMethod(target.get()).filter(found -> !found.isStatic()).isPresent();
                return MatcherLambdas.read(context, target.get(), instance && !captured.isEmpty()
                        ? captured.subList(1, captured.size()) : captured, servletPath);
            }
        }
        return Optional.empty();
    }

    /**
     * Decision 0097: configuration attributes ({@code use-expressions="false"}, {@code <global-method-security>}'s
     * {@code <protect-pointcut>}, legacy {@code <intercept-methods>}) as the default voters read them: 7.2
     * {@code AffirmativeBased} grants when one voter does, and denies when all abstain; {@code RoleVoter} takes the
     * {@code ROLE_} attributes (any of them), {@code AuthenticatedVoter} the {@code IS_AUTHENTICATED_*} ones. An
     * attribute neither takes abstains.
     *
     * @param trimmed whether Spring trims each attribute ({@code SecurityConfig.createListFromCommaDelimitedString});
     *        {@code <global-method-security>} keeps the spaces, so {@code " ROLE_B"} is no role attribute
     */
    @Supports(Feature.REQUIREMENTS)
    static Requirement attributes(String access, boolean trimmed) {
        List<String> roles = new ArrayList<>();
        List<Requirement> any = new ArrayList<>();
        for (String attribute : Arrays.stream(access.split(",", -1)).map(token -> trimmed ? token.trim() : token)
                .toList()) {
            switch (attribute) {
                case "IS_AUTHENTICATED_FULLY" -> any.add(Requirement.fullyAuthenticated());
                // AuthenticatedVoter: a remember-me session or a full sign-in (decision 0105).
                case "IS_AUTHENTICATED_REMEMBERED" -> any.add(Requirement.authenticated());
                case "IS_AUTHENTICATED_ANONYMOUSLY" -> any.add(Requirement.permitAll());
                default -> {
                    if (attribute.startsWith("ROLE_")) {
                        roles.add(attribute);
                    }
                }
            }
        }
        if (!roles.isEmpty()) {
            any.addFirst(Requirement.anyAuthority(roles));
        }
        List<Requirement> distinct = any.stream().distinct().toList();
        Requirement requirement = distinct.isEmpty() ? Requirement.denyAll() : distinct.size() == 1
                ? distinct.getFirst() : Requirement.or(distinct);
        return requirement.withSource(access);
    }
}
