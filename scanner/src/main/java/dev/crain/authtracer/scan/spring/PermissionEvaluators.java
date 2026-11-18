package dev.crain.authtracer.scan.spring;

import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.ScanContext;
import org.springframework.expression.ParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0038 (EXPR-06): whether pre/post {@code hasPermission(..)} reaches a {@code PermissionEvaluator}. In
 * Spring Security 7.1.1, {@code @EnableMethodSecurity}'s {@code PrePostMethodSecurityConfiguration} builds its
 * {@code DefaultMethodSecurityExpressionHandler} with a {@code DenyAllPermissionEvaluator} and never looks up a
 * {@code PermissionEvaluator} bean; only a {@code MethodSecurityExpressionHandler} bean that is given one changes
 * that. The legacy {@code @EnableGlobalMethodSecurity} does use a {@code PermissionEvaluator} bean
 * ({@code GlobalMethodSecurityConfiguration}); the XML elements use their {@code <expression-handler>} bean's.
 */
@Supports(Feature.CUSTOM_DECISIONS)
final class PermissionEvaluators {

    static final String PERMISSION_EVALUATOR = "org.springframework.security.access.PermissionEvaluator";
    private static final String HANDLER =
            "org.springframework.security.access.expression.method.MethodSecurityExpressionHandler";
    private static final String DEFAULT_HANDLER =
            "org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler";

    private PermissionEvaluators() {
    }

    @Supports({Feature.FINDING_ALWAYS_DENIED, Feature.FINDING_ALWAYS_GRANTED})
    static boolean configured(ScanContext context, SpringBeans beans, Optional<SecurityXml.MethodSecurityConfig> xml,
            boolean legacy) {
        Optional<Boolean> handler = handlerBean(context, beans);
        if (handler.isPresent()) {
            return handler.get();
        }
        if (legacy && evaluatorBean(context, beans)) {
            return true;
        }
        return xml.map(SecurityXml.MethodSecurityConfig::permissionEvaluator).orElse(false);
    }

    /**
     * A {@code MethodSecurityExpressionHandler} bean: whether it is given an evaluator, or is the application's own
     * (which may make one); empty when there is none.
     */
    private static Optional<Boolean> handlerBean(ScanContext context, SpringBeans beans) {
        for (JavaSootClass cls : context.applicationClasses()) {
            if (isHandler(context, cls.getType()) && beans.isBean(cls.getType())) {
                return Optional.of(true);
            }
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody() || !context.hasAnnotation(method, SpringNames.BEAN)
                        || !(method.getReturnType() instanceof ClassType returned)
                        || !isHandler(context, returned)) {
                    continue;
                }
                boolean given = context.isApplication(returned);
                for (Stmt stmt : method.getBody().getStmts()) {
                    given |= Locals.invoke(stmt).filter(invoke -> invoke.getMethodSignature().getName()
                            .equals("setPermissionEvaluator")).isPresent();
                    given |= stmt instanceof AbstractDefinitionStmt definition
                            && definition.getRightOp() instanceof JNewExpr created
                            && context.isApplication(created.getType()) && isHandler(context, created.getType());
                }
                return Optional.of(given);
            }
        }
        return Optional.empty();
    }

    /**
     * Decision 0065 (EXPR-06, ACL-01): the evaluator class pre/post {@code hasPermission(..)} reaches: what the
     * {@code MethodSecurityExpressionHandler} bean (or the application's handler class) is given with
     * {@code setPermissionEvaluator(..)}, or with the legacy annotation the {@code PermissionEvaluator} bean. Empty when
     * AuthTracer can't tell which.
     */
    static Optional<ClassType> evaluator(ScanContext context, SpringBeans beans, boolean legacy) {
        DecisionCode decisionCode = DecisionCode.of(context);
        for (JavaSootClass cls : context.applicationClasses()) {
            boolean handlerClass = isHandler(context, cls.getType()) && beans.isBean(cls.getType());
            for (JavaSootMethod method : cls.getMethods()) {
                boolean handlerBean = method.hasBody() && context.hasAnnotation(method, SpringNames.BEAN)
                        && method.getReturnType() instanceof ClassType returned && isHandler(context, returned);
                if (!method.hasBody() || !handlerClass && !handlerBean) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    Optional<ClassType> given = Locals.invoke(stmt).filter(invoke -> invoke.getMethodSignature()
                            .getName().equals("setPermissionEvaluator") && invoke.getArgCount() == 1
                            && invoke.getArg(0) instanceof Local).flatMap(invoke -> given(context, decisionCode, method,
                                    (Local) invoke.getArg(0)));
                    if (given.isPresent()) {
                        return given;
                    }
                }
            }
        }
        return legacy ? decisionCode.beanClass(context.type(PERMISSION_EVALUATOR), "", PERMISSION_EVALUATOR)
                : Optional.empty();
    }

    /**
     * The class of the evaluator a local holds: one created here, a parameter (its class, or the one evaluator bean),
     * or what a bean method returns.
     */
    private static Optional<ClassType> given(ScanContext context, DecisionCode decisionCode, JavaSootMethod method,
            Local local) {
        Optional<Value> definition = Locals.definition(method.getBody(), local);
        if (definition.isEmpty()) {
            return Optional.empty();
        }
        return switch (definition.get()) {
            case JNewExpr created -> Optional.of(created.getType());
            case JParameterRef parameter when method.getParameterType(parameter.getIndex()) instanceof ClassType type ->
                    decisionCode.beanClass(type, method.getBody().getParameterLocal(parameter.getIndex()).getName(),
                            PERMISSION_EVALUATOR);
            case AbstractInvokeExpr call when call.getMethodSignature().getType() instanceof ClassType type ->
                    decisionCode.beanClass(type, call.getMethodSignature().getName(), PERMISSION_EVALUATOR);
            default -> Optional.empty();
        };
    }

    /**
     * Each {@code hasPermission(..)} as the evaluator's method decides it: {@code hasPermission(target, permission)}
     * calls {@code hasPermission(Authentication, Object, Object)}, {@code hasPermission(id, type, permission)} the
     * four-argument one.
     */
    static Requirement decided(Requirement requirement, ClassType evaluator, DecisionCode decisionCode) {
        return switch (requirement.kind()) {
            case EXPRESSION -> isHasPermission(requirement.expression()) && requirement.decidedBy() == null
                    ? decisionCode.permission(evaluator, arguments(requirement.expression()), requirement.expression())
                    : requirement;
            case AND, OR, NOT -> {
                var operands = requirement.operands().stream().map(operand -> decided(operand, evaluator,
                        decisionCode)).toList();
                yield operands.equals(requirement.operands()) ? requirement : requirement.withOperands(operands);
            }
            default -> requirement;
        };
    }

    private static int arguments(String expression) {
        try {
            return new SpelExpressionParser().parseRaw(expression).getAST().getChildCount();
        }
        catch (ParseException ex) {
            return 3;
        }
    }

    private static boolean isHandler(ScanContext context, ClassType type) {
        String name = type.getFullyQualifiedName();
        return name.equals(HANDLER) || name.equals(DEFAULT_HANDLER)
                || context.superClassesOf(type).stream().anyMatch(superClass -> superClass.getFullyQualifiedName()
                        .equals(DEFAULT_HANDLER))
                || context.interfacesOf(type).stream().anyMatch(type2 -> type2.getFullyQualifiedName().equals(HANDLER));
    }

    /**
     * A {@code PermissionEvaluator} bean: a {@code @Bean} method returning one, or a bean class implementing it.
     */
    private static boolean evaluatorBean(ScanContext context, SpringBeans beans) {
        for (JavaSootClass cls : context.applicationClasses()) {
            if (implementsEvaluator(context, cls.getType()) && beans.isBean(cls.getType())) {
                return true;
            }
            for (JavaSootMethod method : cls.getMethods()) {
                if (context.hasAnnotation(method, SpringNames.BEAN) && method.getReturnType() instanceof ClassType returned
                        && implementsEvaluator(context, returned)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean implementsEvaluator(ScanContext context, ClassType type) {
        return type.getFullyQualifiedName().equals(PERMISSION_EVALUATOR) || context.interfacesOf(type).stream()
                .anyMatch(found -> found.getFullyQualifiedName().equals(PERMISSION_EVALUATOR));
    }

    /**
     * The requirement with each {@code hasPermission(..)} denying everyone, as {@code DenyAllPermissionEvaluator}
     * does; its source text stays as written. Decision 0092: its negation ({@code !hasPermission(..)},
     * {@code hasPermission(..) == false}) admits everyone.
     */
    @Supports({Feature.FINDING_ALWAYS_DENIED, Feature.FINDING_ALWAYS_GRANTED})
    static Requirement denied(Requirement requirement) {
        return switch (requirement.kind()) {
            case EXPRESSION -> isHasPermission(requirement.expression())
                    ? Requirement.denyAll().withSource(requirement.expression()) : requirement;
            case AND, OR, NOT -> {
                var operands = requirement.operands().stream().map(PermissionEvaluators::denied).toList();
                if (requirement.kind() == Requirement.Kind.NOT
                        && operands.getFirst().kind() == Requirement.Kind.DENY_ALL) {
                    yield Requirement.permitAll().withSource(requirement.expression() != null
                            ? requirement.expression() : "!" + operands.getFirst().expression());
                }
                yield operands.equals(requirement.operands()) ? requirement : requirement.withOperands(operands);
            }
            default -> requirement;
        };
    }

    static boolean mentionsHasPermission(Requirement requirement) {
        return requirement.kind() == Requirement.Kind.EXPRESSION && isHasPermission(requirement.expression())
                || requirement.operands().stream().anyMatch(PermissionEvaluators::mentionsHasPermission);
    }

    /**
     * {@code hasPermission(..)} on its own: the call's closing parenthesis ends the expression.
     */
    private static boolean isHasPermission(String expression) {
        if (expression == null || !expression.startsWith("hasPermission(")) {
            return false;
        }
        int depth = 0;
        for (int i = "hasPermission".length(); i < expression.length(); i++) {
            char c = expression.charAt(i);
            depth += c == '(' ? 1 : c == ')' ? -1 : 0;
            if (depth == 0) {
                return i == expression.length() - 1;
            }
        }
        return false;
    }
}
