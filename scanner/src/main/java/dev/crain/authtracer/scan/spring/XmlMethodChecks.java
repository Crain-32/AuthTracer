package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.AuthorizationLocation.Denial;
import dev.crain.authtracer.graph.AuthorizationLocation.Phase;
import dev.crain.authtracer.graph.AuthorizationLocation.Scope;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0097: the method checks Spring Security's XML namespace sets up without annotations.
 * <ul>
 * <li>{@code <method-security>}'s {@code <protect-pointcut>}s (7.1.1 {@code MethodSecurityBeanDefinitionParser}): one
 * {@code AuthorizationManagerBeforeMethodInterceptor}, ordered {@code FIRST}, on the bean methods any of them
 * matches, where the first that matches decides with its SpEL {@code access}, as a
 * {@code MethodExpressionAuthorizationManager} with the default expression handler reads it ({@code ROLE_}, no
 * RoleHierarchy). The annotations' checks run too.</li>
 * <li>{@code <global-method-security>}'s (legacy): the first pointcut that matches gives a method its configuration
 * attributes ({@code ProtectPointcutPostProcessor}), but the annotation sources come before it
 * ({@code GlobalMethodSecurityBeanDefinitionParser} adds it last to the {@code DelegatingMethodSecurityMetadataSource},
 * whose first source with attributes wins): only a method without an enabled annotation gets it.</li>
 * <li>A bean's {@code <intercept-methods>} ({@code InterceptMethodsBeanDefinitionDecorator}): a proxy of its own
 * around that bean, whose {@code PointcutDelegatingAuthorizationManager} asks every method for the first
 * {@code <protect>} that matches its name ({@code PrefixBasedMethodMatcher}: the name, {@code prefix*} or
 * {@code *suffix}), and denies a method none matches. With {@code use-authorization-manager="false"}, a
 * {@code MethodSecurityInterceptor} instead: the most specific name wins, and a method none matches is let
 * through.</li>
 * </ul>
 */
@Supports(Feature.METHOD_SECURITY)
final class XmlMethodChecks {

    /**
     * A check and its interceptor's order among the method's.
     */
    record Check(int order, AuthorizationLocation location) {
    }

    private record Guard(Pointcuts.Pointcut pointcut, SecurityXml.ProtectPointcut source, Requirement requirement) {
    }

    private final GraphBuilder graph;
    private final SpringBeans beans;
    private final SpelRequirements defaults;
    private final List<Guard> pointcuts = new ArrayList<>();
    private final List<Guard> legacyPointcuts = new ArrayList<>();
    private final Map<String, SecurityXml.InterceptMethods> intercepted = new HashMap<>();
    private final Map<SecurityXml.InterceptMethods, Requirement> managers = new HashMap<>();

    /**
     * @param defaults SpEL as Spring's default method expression handler reads it
     */
    @Supports({Feature.FINDING_ALWAYS_DENIED, Feature.FINDING_OPAQUE_CONFIG})
    XmlMethodChecks(ScanContext context, GraphBuilder graph, SpringBeans beans, SecurityXml.Config xml,
            SpelRequirements defaults) {
        this.graph = graph;
        this.beans = beans;
        this.defaults = defaults;
        Pointcuts parser = new Pointcuts(context);
        for (SecurityXml.ProtectPointcut found : xml.pointcuts()) {
            // 7.1.1 MethodSecurityBeanDefinitionParser#replaceBooleanOperators; the legacy element's AspectJ reads
            // the words itself.
            String expression = found.expression().replace(" and ", " && ").replace(" or ", " || ")
                    .replace(" not ", " ! ");
            Optional<Pointcuts.Pointcut> pointcut = parser.parse(expression);
            if (pointcut.isEmpty()) {
                graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The <protect-pointcut> at " + found.file()
                        + ":" + found.line() + " uses a pointcut AuthTracer can't read (" + found.expression()
                        + "); the methods it guards show no check for it", xmlRef(found.file(), found.line())));
                continue;
            }
            (found.legacy() ? legacyPointcuts : pointcuts).add(new Guard(pointcut.get(), found, found.legacy()
                    ? XmlReferences.attributes(found.access(), false) : defaults.parse(found.access())));
        }
        XmlReferences references = new XmlReferences(context, xml);
        for (SecurityXml.InterceptMethods methods : xml.interceptMethods()) {
            intercepted.put(methods.beanClass(), methods);
            if (methods.managerRef() != null) {
                String expression = "authorization-manager-ref(" + methods.managerRef() + ")";
                managers.put(methods, references.manager(methods.managerRef(), expression).orElseGet(() -> {
                    graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The <intercept-methods> of "
                            + methods.beanClass() + " at " + methods.file() + ":" + methods.line() + " hands its"
                            + " methods to the AuthorizationManager bean " + methods.managerRef() + ", which"
                            + " AuthTracer can't read: they show it as an opaque requirement",
                            xmlRef(methods.file(), methods.line())));
                    return Requirement.expression(expression);
                }));
            }
            if (!methods.legacy()) {
                methods.protects().stream().filter(protect -> protect.method().contains(".")).forEach(protect ->
                        graph.finding(new Finding(Finding.Kind.ALWAYS_DENIED, "The <protect method=\""
                                + protect.method() + "\"> of " + methods.beanClass() + " at " + methods.file() + ":"
                                + protect.line() + " never matches: Spring Security 7.1.1's PrefixBasedMethodMatcher"
                                + " compares the qualified name with the method's own, so the methods it names get"
                                + " no protect and are denied", xmlRef(methods.file(), protect.line()))));
            }
        }
    }

    /**
     * The XML's checks on the method, in addition to its annotations' ({@code annotated}: whether an enabled
     * annotation gave it any).
     */
    List<Check> checks(JavaSootClass cls, JavaSootMethod method, boolean annotated) {
        // MethodSecurity hands it no constructors.
        if (cls.isInterface() || method.isPrivate() || method.isFinal() || method.isStatic()) {
            return List.of();
        }
        List<Check> checks = new ArrayList<>();
        String key = MethodNames.key(method.getSignature());
        CodeRef target = MethodNames.codeRef(method.getSignature());
        if (beans.isBean(cls.getType())) {
            pointcuts.stream().filter(guard -> guard.pointcut().matches(cls, method)).findFirst().ifPresent(guard ->
                    checks.add(new Check(Integer.MIN_VALUE, pointcut(key, target, guard, "protect-pointcut"))));
            if (!annotated) {
                legacyPointcuts.stream().filter(guard -> guard.pointcut().matches(cls, method)).findFirst()
                        .ifPresent(guard -> checks.add(new Check(0, pointcut(key, target, guard,
                                "protect-pointcut (global-method-security)"))));
            }
        }
        SecurityXml.InterceptMethods methods = intercepted.get(cls.getName());
        if (methods != null) {
            interceptMethods(key, target, method.getName(), methods).ifPresent(location -> checks.add(new Check(
                    Integer.MAX_VALUE, location)));
        }
        return checks;
    }

    private AuthorizationLocation pointcut(String key, CodeRef target, Guard guard, String mechanism) {
        return graph.node(new AuthorizationLocation("location:METHOD:" + key + ":protect-pointcut:"
                + guard.source().file() + ":" + guard.source().line(), mechanism, Scope.METHOD, Phase.PRE,
                guard.requirement(), target, null, guard.source().expression(), Denial.THROW, true));
    }

    private Optional<AuthorizationLocation> interceptMethods(String key, CodeRef target, String name,
            SecurityXml.InterceptMethods methods) {
        String id = "location:METHOD:" + key + ":intercept-methods:" + methods.file() + ":" + methods.line();
        if (methods.legacy()) {
            // 7.2 MapBasedMethodSecurityMetadataSource#addSecureMethod: the longest name that matches; a name without
            // a dot is the bean class's.
            Optional<SecurityXml.Protect> protect = methods.protects().stream()
                    .filter(found -> legacyMatches(found.method(), methods.beanClass(), name))
                    .reduce((first, next) -> qualified(next.method(), methods.beanClass()).length()
                            >= qualified(first.method(), methods.beanClass()).length() ? next : first);
            return protect.map(found -> graph.node(new AuthorizationLocation(id, "intercept-methods"
                    + " (MethodSecurityInterceptor)", Scope.METHOD, Phase.PRE, XmlReferences.attributes(
                            found.access(), true), target, null, "protect " + found.method(), Denial.THROW, true)));
        }
        Optional<SecurityXml.Protect> protect = methods.protects().stream()
                .filter(found -> !found.method().contains(".") && nameMatches(found.method(), name)).findFirst();
        if (protect.isEmpty()) {
            return Optional.of(graph.node(new AuthorizationLocation(id, "intercept-methods (no protect matched:"
                    + " denied)", Scope.METHOD, Phase.PRE, Requirement.denyAll(), target, null, "unmatched",
                    Denial.THROW, true)));
        }
        Requirement requirement = methods.managerRef() != null ? managers.get(methods)
                : defaults.parse(protect.get().access());
        return Optional.of(graph.node(new AuthorizationLocation(id, "intercept-methods", Scope.METHOD, Phase.PRE,
                requirement, target, null, "protect " + protect.get().method(), Denial.THROW, true)));
    }

    /**
     * 7.1.1 {@code PrefixBasedMethodMatcher#matches}: the name itself, {@code prefix*} or {@code *suffix}.
     */
    private static boolean nameMatches(String mapped, String name) {
        return name.equals(mapped) || mapped.endsWith("*") && name.startsWith(mapped.substring(0, mapped.length()
                - 1)) || mapped.startsWith("*") && name.endsWith(mapped.substring(1));
    }

    private static boolean legacyMatches(String mapped, String beanClass, String name) {
        String qualified = qualified(mapped, beanClass);
        int dot = qualified.lastIndexOf('.');
        return qualified.substring(0, dot).equals(beanClass) && nameMatches(qualified.substring(dot + 1), name);
    }

    private static String qualified(String mapped, String beanClass) {
        return mapped.contains(".") ? mapped : beanClass + "." + mapped;
    }

    /**
     * Where an XML element is: the file, at its line.
     */
    private static CodeRef xmlRef(String file, int line) {
        return CodeRef.ofClass(file).atLine(line);
    }
}
