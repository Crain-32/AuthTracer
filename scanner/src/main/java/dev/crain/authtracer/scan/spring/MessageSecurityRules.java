package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.spring.HttpSecurityRules.Matcher;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JNewArrayExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.ref.JStaticFieldRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0039 (MSG-01 to MSG-05): Spring Security's authorization of inbound STOMP messages. With
 * {@code @EnableWebSocketSecurity}, the {@code AuthorizationManager<Message<?>>} bean decides each message: usually
 * {@code MessageMatcherDelegatingAuthorizationManager.Builder} rules, first match wins and no match is denied (7.1.1
 * {@code AuthorizationChannelInterceptor} denies a {@code null} result); without the bean,
 * {@code anyMessage().authenticated()}. Its {@code hasRole} is {@code AuthorityAuthorizationManager}'s: {@code ROLE_}
 * and no role hierarchy. An {@code AuthorizationChannelInterceptor} the application adds to the inbound channel
 * itself (MSG-05) is read the same way. Decision 0097 (MSG-06): the XML namespace's
 * {@code <websocket-message-broker>}, whose {@code <intercept-message>}s are rules of the same builder, in document
 * order, ended by {@code anyMessage().permitAll()} (7.1.1 {@code WebSocketMessageBrokerSecurityBeanDefinitionParser}),
 * so a message none matches is let through.
 */
@Supports(Feature.REQUEST_RULES)
final class MessageSecurityRules {

    static final String MECHANISM = "Message authorization (STOMP)";
    private static final String ENABLE =
            "org.springframework.security.config.annotation.web.socket.EnableWebSocketSecurity";
    private static final String DELEGATING =
            "org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager";
    private static final String BUILDER = DELEGATING + "$Builder";
    private static final String CONSTRAINT = BUILDER + "$Constraint";
    private static final String EXPRESSION_MANAGER =
            "org.springframework.security.messaging.access.expression.MessageExpressionAuthorizationManager";
    private static final String CHANNEL_INTERCEPTOR =
            "org.springframework.security.messaging.access.intercept.AuthorizationChannelInterceptor";
    private static final String AUTHORIZATION_MANAGER =
            "org.springframework.security.authorization.AuthorizationManager";
    private static final String CHANNEL_REGISTRATION = "org.springframework.messaging.simp.config.ChannelRegistration";
    private static final String MESSAGE = "org.springframework.messaging.Message";
    private static final String SIMP_MESSAGE_TYPE = "org.springframework.messaging.simp.SimpMessageType";
    private static final SpelRequirements ROLES = new SpelRequirements("ROLE_");

    /**
     * @param label how the rule's matcher is written, e.g. {@code simpDestMatchers(/app/**)}
     */
    private record Rule(Matcher matcher, String label, Requirement requirement, Integer line) {
    }

    /**
     * Where the rules are: a manager bean method, the annotated class (the default), or the inbound channel's
     * configurer method; decision 0097: an XML file.
     *
     * @param unmatched what a message no rule matches gets: denied, or let through by the XML's last rule
     */
    private record Rules(CodeRef declaredIn, String key, List<Rule> rules, boolean unmatched) {

        Rules(CodeRef declaredIn, String key, List<Rule> rules) {
            this(declaredIn, key, rules, false);
        }
    }

    private record Builder(List<Rule> rules) {
    }

    private record Constraint(Builder builder, Matcher matcher, String label) {
    }

    private record Manager(Requirement requirement) {
    }

    private record Built(List<Rule> rules) {
    }

    /**
     * An array's elements: the constants, and those that aren't.
     */
    private record Strings(List<String> values, List<Value> unknown, List<Requirement> managers) {

        Strings() {
            this(new ArrayList<>(), new ArrayList<>(), new ArrayList<>());
        }
    }

    private final ScanContext context;
    private final GraphBuilder graph;
    private final List<Rules> rules = new ArrayList<>();
    private final Set<String> reported = new HashSet<>();
    /**
     * The manager bean methods the XML hands the inbound channel's interceptor.
     */
    private final Set<JavaSootMethod> xmlManagers = new HashSet<>();

    MessageSecurityRules(ScanContext context, GraphBuilder graph, SecurityXml.Config xml) {
        this.context = context;
        this.graph = graph;
        rules.addAll(xml(xml));
        detect().ifPresent(rules::add);
    }

    /**
     * Decision 0097 (MSG-06): each {@code <websocket-message-broker>} is an {@code AuthorizationChannelInterceptor}
     * (or, with {@code use-authorization-manager="false"}, a {@code ChannelSecurityInterceptor}, whose metadata source
     * also takes the first rule that matches and lets a message none matches through). Without an {@code id}, its
     * {@code MessageSecurityPostProcessor} puts it first on the {@code clientInboundChannel}; with one, the channel
     * has it only when the configuration gives it there.
     */
    @Supports({Feature.FINDING_OPAQUE_CONFIG, Feature.FINDING_NOT_ENFORCED})
    private List<Rules> xml(SecurityXml.Config xml) {
        List<Rules> found = new ArrayList<>();
        XmlReferences references = new XmlReferences(context, xml);
        for (SecurityXml.MessageBroker broker : xml.messageBrokers()) {
            CodeRef declaredIn = CodeRef.ofClass(broker.file());
            String key = broker.file() + ":websocket-message-broker:" + broker.line();
            String element = "The <websocket-message-broker" + (broker.id() == null ? "" : " id=\"" + broker.id()
                    + "\"") + "> at " + broker.file() + ":" + broker.line();
            if (broker.id() != null && !xml.stomp().map(stomp -> stomp.inboundInterceptors().contains(broker.id()))
                    .orElse(false)) {
                Optional<JavaSootMethod> wiring = channelWiring();
                graph.finding(wiring.map(method -> new Finding(Finding.Kind.OPAQUE_CONFIG, element + " runs only"
                        + " where the inbound channel is given it; " + MethodNames.key(method.getSignature())
                        + " gives the channel interceptors AuthTracer doesn't read, so its rules are not shown",
                        MethodNames.codeRef(method.getSignature()))).orElseGet(() -> new Finding(
                                Finding.Kind.NOT_ENFORCED, element + " never runs: with an id, the inbound channel"
                                        + " must be given it (<websocket:client-inbound-channel>), and nothing gives"
                                        + " it there", declaredIn.atLine(broker.line()))));
                continue;
            }
            if (broker.managerRef() != null) {
                String expression = "authorization-manager-ref(" + broker.managerRef() + ")";
                Optional<JavaSootMethod> bean = references.beanMethod(broker.managerRef())
                        .filter(method -> method.hasBody() && isMessageManager(method));
                if (bean.isPresent()) {
                    xmlManagers.add(bean.get());
                    found.add(new Rules(MethodNames.codeRef(bean.get().getSignature()),
                            MethodNames.key(bean.get().getSignature()), interpret(bean.get())));
                    continue;
                }
                Requirement requirement = references.manager(broker.managerRef(), expression).orElseGet(() -> {
                    graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, element + " hands every message to the"
                            + " AuthorizationManager bean " + broker.managerRef() + ", which AuthTracer can't read:"
                            + " the messages show it as an opaque requirement", declaredIn.atLine(broker.line())));
                    return Requirement.expression(expression);
                });
                found.add(new Rules(declaredIn, key, List.of(new Rule(Matcher.paths(null, List.of("/**")),
                        "anyMessage", requirement, broker.line()))));
                continue;
            }
            if (broker.expressionHandler() != null) {
                graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, element + " evaluates its rules with the"
                        + " expression handler bean " + broker.expressionHandler() + ", which AuthTracer reads as"
                        + " Spring's default (the ROLE_ prefix, no RoleHierarchy)", declaredIn.atLine(broker.line())));
            }
            List<Rule> brokerRules = new ArrayList<>();
            for (SecurityXml.InterceptMessage rule : broker.rules()) {
                if (rule.access() == null || rule.pattern() == null && rule.type() == null) {
                    // Spring refuses these when it starts.
                    continue;
                }
                String label = rule.pattern() == null ? "type=" + rule.type() : rule.type() == null
                        ? "pattern=" + rule.pattern() : "pattern=" + rule.pattern() + " type=" + rule.type();
                brokerRules.add(new Rule(Matcher.paths(rule.type(), List.of(rule.pattern() == null ? "/**"
                        : rule.pattern())), "intercept-message " + label, ROLES.parse(rule.access()), rule.line()));
            }
            found.add(new Rules(declaredIn, key, brokerRules, true));
        }
        return found;
    }

    /**
     * An application method that gives the inbound channel interceptors ({@code ChannelRegistration.interceptors}).
     */
    private Optional<JavaSootMethod> channelWiring() {
        return context.applicationClasses().stream().flatMap(cls -> cls.getMethods().stream())
                .filter(JavaSootMethod::hasBody)
                .filter(method -> method.getBody().getStmts().stream().flatMap(stmt -> Locals.invoke(stmt).stream())
                        .anyMatch(invoke -> invoke.getMethodSignature().getName().equals("interceptors")
                                && invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName()
                                        .equals(CHANNEL_REGISTRATION)))
                .findFirst();
    }

    @Supports(Feature.FINDING_NOT_ENFORCED)
    private Optional<Rules> detect() {
        boolean enabled = context.anyClassAnnotated(ENABLE);
        boolean manual = context.applicationClasses().stream().flatMap(cls -> cls.getMethods().stream())
                .anyMatch(method -> method.hasBody() && createsChannelInterceptor(method));
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                if (context.hasAnnotation(method, SpringNames.BEAN) && isMessageManager(method)
                        && !xmlManagers.contains(method)) {
                    if (enabled) {
                        return Optional.of(new Rules(MethodNames.codeRef(method.getSignature()),
                                MethodNames.key(method.getSignature()), interpret(method)));
                    }
                    // Only @EnableWebSocketSecurity, or the application's own channel interceptor, hands the bean to
                    // the inbound channel (Spring Boot 4.1.1 auto-configures neither).
                    if (!manual) {
                        graph.finding(new Finding(Finding.Kind.NOT_ENFORCED, "The message AuthorizationManager bean "
                                + MethodNames.key(method.getSignature()) + " never runs: nothing adds it to the"
                                + " inbound channel without @EnableWebSocketSecurity",
                                MethodNames.codeRef(method.getSignature())));
                    }
                }
                // MSG-05: registration.interceptors(new AuthorizationChannelInterceptor(manager)).
                if (createsChannelInterceptor(method)) {
                    return Optional.of(new Rules(MethodNames.codeRef(method.getSignature()),
                            MethodNames.key(method.getSignature()), interpret(method)));
                }
            }
        }
        return context.applicationClasses().stream().filter(cls -> context.hasAnnotation(cls, ENABLE)).findFirst()
                .map(cls -> new Rules(CodeRef.ofClass(cls.getType().getFullyQualifiedName()),
                        cls.getType().getFullyQualifiedName(), List.of(new Rule(Matcher.paths(null, List.of("/**")),
                                "anyMessage", Requirement.authenticated(), null))));
    }

    private boolean isMessageManager(JavaSootMethod method) {
        return method.getReturnType() instanceof ClassType returned
                && returned.getFullyQualifiedName().equals(AUTHORIZATION_MANAGER)
                && context.classFiles().genericReturnType(method.getSignature())
                        .filter(generic -> generic.arguments().size() == 1
                                && generic.arguments().getFirst().name().equals(MESSAGE))
                        .isPresent();
    }

    private static boolean createsChannelInterceptor(JavaSootMethod method) {
        return method.getBody().getStmts().stream().anyMatch(stmt -> stmt instanceof AbstractDefinitionStmt definition
                && definition.getRightOp() instanceof JNewExpr created
                && created.getType().getFullyQualifiedName().equals(CHANNEL_INTERCEPTOR));
    }

    /**
     * The rules a method's builder calls add, or the one manager it returns (or hands the channel interceptor) for
     * every message (MSG-03).
     */
    private List<Rule> interpret(JavaSootMethod method) {
        Map<Local, Object> values = new HashMap<>();
        List<Rule> found = null;
        for (Stmt stmt : method.getBody().getStmts()) {
            Integer line = stmt.getPositionInfo().getStmtPosition().getFirstLine();
            if (stmt instanceof AbstractDefinitionStmt definition) {
                if (definition.getLeftOp() instanceof JArrayRef element
                        && values.get(element.getBase()) instanceof Strings array) {
                    // SootUp stores through a local: $stack3 = <SimpMessageType: MESSAGE>; $stack2[0] = $stack3.
                    Value stored = definition.getRightOp() instanceof Local local
                            ? Locals.definition(method.getBody(), local).orElse(local) : definition.getRightOp();
                    if (definition.getRightOp() instanceof Local local && values.get(local) instanceof Manager manager) {
                        array.managers().add(manager.requirement());
                    }
                    else {
                        text(stored).ifPresentOrElse(array.values()::add, () -> array.unknown().add(stored));
                    }
                    continue;
                }
                if (definition.getLeftOp() instanceof Local local) {
                    Object value = evaluate(method, definition.getRightOp(), values, line);
                    if (value != null) {
                        values.put(local, value);
                    }
                }
            }
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isPresent() && invoke.get().getMethodSignature().getName().equals("<init>")
                    && invoke.get() instanceof AbstractInstanceInvokeExpr instance) {
                String type = invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
                if (type.equals(EXPRESSION_MANAGER) && invoke.get().getArgCount() == 1
                        && invoke.get().getArg(0) instanceof StringConstant expression) {
                    // MSG-04: new MessageExpressionAuthorizationManager("..."), with destination variables.
                    values.put(instance.getBase(), new Manager(ROLES.parse(expression.getValue())));
                }
                if (type.equals(CHANNEL_INTERCEPTOR) && invoke.get().getArgCount() == 1) {
                    found = rules(values.get(argument(invoke.get().getArg(0))), line);
                }
            }
            else if (invoke.isPresent() && !(stmt instanceof AbstractDefinitionStmt)) {
                evaluate(method, invoke.get(), values, line);
            }
            if (stmt instanceof JReturnStmt returned && returned.getOp() instanceof Local local && found == null) {
                found = rules(values.get(local), line);
            }
        }
        return found == null ? List.of() : found;
    }

    private static Local argument(Immediate value) {
        return value instanceof Local local ? local : null;
    }

    private static List<Rule> rules(Object value, Integer line) {
        if (value instanceof Built built) {
            return built.rules();
        }
        if (value instanceof Manager manager) {
            return List.of(new Rule(Matcher.paths(null, List.of("/**")), "anyMessage", manager.requirement(), line));
        }
        return List.of(new Rule(Matcher.paths(null, List.of("/**")), "anyMessage",
                Requirement.expression("AuthorizationManager<Message<?>>"), line));
    }

    @Supports(Feature.CUSTOM_DECISIONS)
    private Object evaluate(JavaSootMethod method, Value right, Map<Local, Object> values, Integer line) {
        if (right instanceof JParameterRef parameter) {
            return method.getParameterType(parameter.getIndex()) instanceof ClassType type
                    && type.getFullyQualifiedName().equals(BUILDER) ? new Builder(new ArrayList<>()) : null;
        }
        if (right instanceof Local local) {
            return values.get(local);
        }
        if (right instanceof JNewArrayExpr) {
            return new Strings();
        }
        // Decision 0064: a custom manager, or a lambda, decides the messages it is given.
        if (right instanceof JNewExpr created) {
            return DecisionCode.of(context).created(created.getType(), "access(" + MethodNames.simpleName(created
                    .getType().getFullyQualifiedName()) + ")").map(Manager::new).orElse(null);
        }
        Optional<MethodSignature> lambda = DecisionCode.lambdaTarget(right)
                .filter(target -> context.isApplication(target.getDeclClassType())
                        && DecisionCode.isManagerLambda(target));
        if (lambda.isPresent()) {
            return new Manager(DecisionCode.of(context).lambda(lambda.get(), "access(" + lambda.get().getName()
                    + ")"));
        }
        if (!(right instanceof AbstractInvokeExpr invoke)) {
            return null;
        }
        String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = invoke.getMethodSignature().getName();
        List<String> texts = new ArrayList<>();
        boolean unknown = false;
        for (Immediate arg : invoke.getArgs()) {
            if (arg instanceof StringConstant constant) {
                texts.add(constant.getValue());
            }
            else if (arg instanceof Local local && values.get(local) instanceof Strings array) {
                texts.addAll(array.values());
                unknown |= !array.unknown().isEmpty();
            }
        }
        if (!(invoke instanceof AbstractInstanceInvokeExpr instance)) {
            if (owner.equals(DELEGATING) && name.equals("builder")) {
                return new Builder(new ArrayList<>());
            }
            return BuiltInManagers.factory(owner, name, invoke.getMethodSignature().getParameterTypes().stream()
                    .map(Object::toString).toList(), managerArgs(invoke, values)).map(Manager::new).orElse(null);
        }
        Object receiver = values.get(instance.getBase());
        if (receiver instanceof Builder builder) {
            String label = name + "(" + String.join(",", texts) + (!unknown ? "" : texts.isEmpty() ? "?" : ",?") + ")";
            return switch (name) {
                case "anyMessage" -> new Constraint(builder, Matcher.paths(null, List.of("/**")), "anyMessage");
                case "nullDestMatcher" -> new Constraint(builder, Matcher.custom("nullDestMatcher"), "nullDestMatcher");
                case "simpTypeMatchers" -> new Constraint(builder, matcher(texts.stream()
                        .map(type -> Matcher.paths(type, List.of("/**"))).toList(), unknown), label);
                case "simpDestMatchers" -> new Constraint(builder, matcher(List.of(Matcher.paths(null, texts)),
                        unknown), label);
                case "simpMessageDestMatchers" -> new Constraint(builder, matcher(List.of(Matcher.paths(
                        StompMappings.MESSAGE, texts)), unknown), label);
                case "simpSubscribeDestMatchers" -> new Constraint(builder, matcher(List.of(Matcher.paths(
                        StompMappings.SUBSCRIBE, texts)), unknown), label);
                case "matchers" -> new Constraint(builder, Matcher.custom("matchers(MessageMatcher)"),
                        "matchers(MessageMatcher)");
                case "build" -> new Built(List.copyOf(builder.rules()));
                default -> null;
            };
        }
        if (receiver instanceof Constraint constraint && owner.equals(CONSTRAINT)) {
            // Decision 0063: the Constraint's methods are AuthorityAuthorizationManager's and
            // AuthenticatedAuthorizationManager's; a role that isn't a constant is shown as unread.
            Requirement requirement = switch (name) {
                case "access" -> invoke.getArgCount() == 1 && invoke.getArg(0) instanceof Local local
                        && values.get(local) instanceof Manager manager ? manager.requirement()
                                : Requirement.expression("access(AuthorizationManager)");
                case "hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority" -> BuiltInManagers.named(name,
                        managerArgs(invoke, values), ROLES).orElse(Requirement.expression(name + "(?)"));
                default -> BuiltInManagers.named(name, managerArgs(invoke, values), ROLES).orElse(null);
            };
            if (requirement != null) {
                constraint.builder().rules().add(new Rule(constraint.matcher(), constraint.label(), requirement,
                        line));
            }
            return constraint.builder();
        }
        return null;
    }

    /**
     * MSG-03: the arguments of a call to one of Spring Security's managers, e.g.
     * {@code AuthorityAuthorizationManager.hasRole("USER")}, as the built-in managers' table reads them.
     */
    private static List<BuiltInManagers.Arg> managerArgs(AbstractInvokeExpr invoke, Map<Local, Object> values) {
        List<BuiltInManagers.Arg> args = new ArrayList<>();
        for (Immediate arg : invoke.getArgs()) {
            Object value = arg instanceof Local local ? values.get(local) : null;
            args.add(arg instanceof StringConstant constant ? new BuiltInManagers.Text(constant.getValue())
                    : value instanceof Strings array && !array.managers().isEmpty()
                            ? new BuiltInManagers.Managers(array.managers(), array.unknown().isEmpty()
                                    && array.values().isEmpty())
                            : value instanceof Strings array ? new BuiltInManagers.Texts(array.values(),
                                    array.unknown().isEmpty())
                                    : value instanceof Manager manager
                                            ? new BuiltInManagers.Manager(manager.requirement())
                                            : BuiltInManagers.UNKNOWN);
        }
        return args;
    }

    /**
     * Decision 0051: a type or destination that isn't a constant may match any message.
     */
    private static Matcher matcher(List<Matcher> read, boolean unknown) {
        return Matcher.anyOf(read, unknown ? List.of(Matcher.NOT_CONSTANT) : List.of());
    }

    private static Optional<String> text(Value value) {
        if (value instanceof StringConstant constant) {
            return Optional.of(constant.getValue());
        }
        if (value instanceof JStaticFieldRef field
                && field.getFieldSignature().getDeclClassType().getFullyQualifiedName().equals(SIMP_MESSAGE_TYPE)) {
            return Optional.of(field.getFieldSignature().getName());
        }
        return Optional.empty();
    }

    /**
     * Each inbound interceptor's check: the first of its rules that matches the message or subscription, or what it
     * does when none does.
     */
    List<AuthorizationLocation> locationsFor(Ingress ingress) {
        return rules.stream().map(found -> locationFor(found, ingress)).toList();
    }

    private AuthorizationLocation locationFor(Rules found, Ingress ingress) {
        List<AuthorizationLocation> maybe = new ArrayList<>();
        for (int i = 0; i < found.rules().size(); i++) {
            Rule rule = found.rules().get(i);
            if (rule.matcher().matches(ingress.httpMethod(), ingress.route())) {
                return maybeFirst(maybe, location(found, i, rule));
            }
            // Decision 0051: a MessageMatcher AuthTracer can't evaluate may match first.
            if (rule.matcher().mayMatch()) {
                maybe.add(location(found, i, rule));
            }
        }
        return maybeFirst(maybe, graph.node(found.unmatched() ? new AuthorizationLocation("location:HTTP_REQUEST:"
                + found.key() + ":message:permitted", MECHANISM + " (no intercept-message matched: let through)",
                AuthorizationLocation.Scope.HTTP_REQUEST, AuthorizationLocation.Phase.PRE, Requirement.permitAll(),
                found.declaredIn(), null, "anyMessage", AuthorizationLocation.Denial.THROW, false)
                : new AuthorizationLocation("location:HTTP_REQUEST:" + found.key() + ":message:denied", MECHANISM
                        + " (no rule matched: denied)", AuthorizationLocation.Scope.HTTP_REQUEST,
                        AuthorizationLocation.Phase.PRE, Requirement.denyAll(), found.declaredIn(), null, null,
                        AuthorizationLocation.Denial.THROW, false)));
    }

    private AuthorizationLocation location(Rules found, int index, Rule rule) {
        return graph.node(new AuthorizationLocation("location:HTTP_REQUEST:" + found.key() + ":message:" + index
                + ":" + rule.label(), MECHANISM, AuthorizationLocation.Scope.HTTP_REQUEST,
                AuthorizationLocation.Phase.PRE, rule.requirement(), found.declaredIn().atLine(rule.line()),
                null, rule.label(), AuthorizationLocation.Denial.THROW, false));
    }

    /**
     * The rules that may match first, or the one that does: a Split location asking for the weakest.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private AuthorizationLocation maybeFirst(List<AuthorizationLocation> maybe, AuthorizationLocation matched) {
        if (maybe.isEmpty()) {
            return matched;
        }
        maybe.stream().filter(location -> reported.add(location.id())).forEach(location -> graph.finding(new Finding(
                Finding.Kind.OPAQUE_CONFIG, "The message rule " + location.routePattern() + " uses a MessageMatcher"
                        + " AuthTracer can't evaluate: the messages it matches get it instead of the rules after it",
                location.target())));
        List<AuthorizationLocation> alternatives = new ArrayList<>(maybe);
        alternatives.add(matched);
        List<Requirement> requirements = alternatives.stream().map(AuthorizationLocation::requirement).distinct()
                .toList();
        return graph.node(new AuthorizationLocation("location:SPLIT:" + matched.id() + ":or:" + maybe.stream()
                .map(AuthorizationLocation::routePattern).toList(), MECHANISM + " (a MessageMatcher may match first)",
                AuthorizationLocation.Scope.HTTP_REQUEST, AuthorizationLocation.Phase.PRE,
                requirements.size() == 1 ? requirements.getFirst() : Requirement.or(requirements), matched.target(),
                null, String.join(" or ", alternatives.stream().map(location -> location.routePattern() == null
                        ? "default" : location.routePattern()).toList()), AuthorizationLocation.Denial.THROW, false));
    }
}
