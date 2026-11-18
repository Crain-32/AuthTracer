package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.SortedMap;
import java.util.SortedSet;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Requirement;
import org.springframework.expression.ParseException;
import org.springframework.expression.spel.SpelNode;
import org.springframework.expression.spel.ast.BeanReference;
import org.springframework.expression.spel.ast.BooleanLiteral;
import org.springframework.expression.spel.ast.CompoundExpression;
import org.springframework.expression.spel.ast.MethodReference;
import org.springframework.expression.spel.ast.OpAnd;
import org.springframework.expression.spel.ast.OpEQ;
import org.springframework.expression.spel.ast.OpNE;
import org.springframework.expression.spel.ast.OpOr;
import org.springframework.expression.spel.ast.OperatorNot;
import org.springframework.expression.spel.ast.PropertyOrFieldReference;
import org.springframework.expression.spel.ast.StringLiteral;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import sootup.core.types.ClassType;

/**
 * Normalizes Spring Security's SpEL authorization expressions into {@link Requirement}s.
 * Anything that isn't a security-expression-root call stays an {@link Requirement.Kind#EXPRESSION}.
 */
@Supports(Feature.REQUIREMENTS)
public final class SpelRequirements {

    private static final SpelExpressionParser PARSER = new SpelExpressionParser();
    private static final SpelRequirements DEFAULT = new SpelRequirements("ROLE_");

    private final String rolePrefix;
    private final String strippedPrefix;
    /**
     * Resolves {@code @bean.method(..)} to the application code that decides it; {@code null} leaves bean calls as
     * expressions.
     */
    private final DecisionCode beans;
    /**
     * EXPR-05: the expression root of the application's handler, whose methods expressions may call; {@code null} for
     * Spring's.
     */
    private final ClassType root;
    /**
     * The root is made where the annotations never call, so an expression calling its methods fails.
     */
    private final boolean rootIgnored;

    SpelRequirements(String rolePrefix) {
        this(rolePrefix, rolePrefix);
    }

    /**
     * @param rolePrefix what the factory adds to a role
     * @param strippedPrefix what the expression root takes off a role first, its handler's default role prefix (the
     *        {@code GrantedAuthorityDefaults} bean's): 7.1.1's {@code SecurityExpressionRoot.hasRole}
     */
    SpelRequirements(String rolePrefix, String strippedPrefix) {
        this(rolePrefix, strippedPrefix, null, null, false);
    }

    private SpelRequirements(String rolePrefix, String strippedPrefix, DecisionCode beans, ClassType root,
            boolean rootIgnored) {
        this.rolePrefix = rolePrefix;
        this.strippedPrefix = strippedPrefix;
        this.beans = beans;
        this.root = root;
        this.rootIgnored = rootIgnored;
    }

    /**
     * Decision 0064 (EXPR-03): the same, with {@code @bean.method(..)} resolved to the bean's method.
     */
    @Supports(Feature.CUSTOM_DECISIONS)
    SpelRequirements withBeans(DecisionCode decisionCode) {
        return new SpelRequirements(rolePrefix, strippedPrefix, decisionCode, root, rootIgnored);
    }

    /**
     * Decision 0091 (EXPR-05): the same, with calls to the methods of the handler's own root resolved to them.
     *
     * @param ignored the annotations never use the root, so such a call fails
     */
    @Supports(Feature.CUSTOM_DECISIONS)
    SpelRequirements withRoot(ClassType handlerRoot, boolean ignored) {
        return new SpelRequirements(rolePrefix, strippedPrefix, beans, handlerRoot, ignored);
    }

    /**
     * An expression written outside the code, e.g. a policy's {@code requires}: Spring's default {@code ROLE_} prefix.
     */
    @Supports({Feature.POLICIES, Feature.VIEW_FIELDS})
    public static Requirement standard(String expression) {
        return DEFAULT.parse(expression);
    }

    /**
     * A requirement widened by a service's RoleHierarchy, as the scan widens that service's role checks, so the two
     * can be compared: with {@code ROLE_ADMIN > ROLE_HR}, {@code ROLE_HR} becomes any of the two.
     *
     * @param roleHierarchy each role's directly implied roles, {@code null} for none
     */
    @Supports(Feature.POLICIES)
    public static Requirement widened(Requirement requirement, SortedMap<String, SortedSet<String>> roleHierarchy) {
        return roleHierarchy == null ? requirement : new RoleHierarchies(roleHierarchy).expand(requirement);
    }

    Requirement parse(String expression) {
        try {
            SpelNode ast = PARSER.parseRaw(expression).getAST();
            return convert(ast).withSource(expression);
        }
        catch (ParseException ex) {
            return Requirement.expression(expression);
        }
    }

    String role(String role) {
        String bare = !strippedPrefix.isEmpty() && role.startsWith(strippedPrefix)
                ? role.substring(strippedPrefix.length()) : role;
        return bare.startsWith(rolePrefix) ? bare : rolePrefix + bare;
    }

    private Requirement convert(SpelNode node) {
        if (node instanceof OpAnd) {
            return Requirement.and(children(node));
        }
        if (node instanceof OpOr) {
            return Requirement.or(children(node));
        }
        if (node instanceof OperatorNot) {
            return Requirement.not(convert(node.getChild(0)));
        }
        // Decision 0092: a check compared with true or false is the check or its negation.
        if ((node instanceof OpEQ || node instanceof OpNE) && node.getChildCount() == 2) {
            for (int i = 0; i < 2; i++) {
                if (node.getChild(i) instanceof BooleanLiteral literal) {
                    Requirement compared = convert(node.getChild(1 - i));
                    return "true".equals(literal.toStringAST()) == node instanceof OpEQ ? compared
                            : Requirement.not(compared);
                }
            }
        }
        if (node instanceof CompoundExpression && beans != null && node.getChildCount() == 2
                && node.getChild(0) instanceof BeanReference bean && node.getChild(1) instanceof MethodReference method) {
            List<String> literals = new ArrayList<>();
            for (int i = 0; i < method.getChildCount(); i++) {
                literals.add(method.getChild(i) instanceof StringLiteral literal
                        ? String.valueOf(literal.getLiteralValue().getValue()) : null);
            }
            return beans.beanCall(bean.getName(), method.getName(), literals, node.toStringAST());
        }
        if (node instanceof BooleanLiteral) {
            return "true".equals(node.toStringAST()) ? Requirement.permitAll() : Requirement.denyAll();
        }
        if (node instanceof PropertyOrFieldReference property) {
            // The security expression root's properties: authenticated is isAuthenticated(), and so on.
            return switch (property.getName()) {
                case "permitAll" -> Requirement.permitAll();
                case "denyAll" -> Requirement.denyAll();
                case "authenticated" -> Requirement.authenticated();
                // Remember-me sessions pass isAuthenticated() but not isFullyAuthenticated(); isRememberMe() passes them
                // only.
                case "fullyAuthenticated" -> Requirement.fullyAuthenticated();
                case "rememberMe" -> Requirement.rememberMe();
                // isAnonymous(), final in 7.1.1's SecurityExpressionRoot: only callers who haven't signed in.
                case "anonymous" -> Requirement.anonymous();
                default -> Requirement.expression(node.toStringAST());
            };
        }
        if (node instanceof MethodReference method) {
            List<String> arguments = stringArguments(method);
            if (arguments != null) {
                switch (method.getName()) {
                    case "hasRole", "hasAnyRole":
                        return Requirement.anyAuthority(arguments.stream().map(this::role).toList());
                    case "hasAllRoles":
                        return Requirement.allAuthorities(arguments.stream().map(this::role).toList());
                    case "hasAuthority", "hasAnyAuthority":
                        return Requirement.anyAuthority(arguments);
                    case "hasAllAuthorities":
                        return Requirement.allAuthorities(arguments);
                    case "isAuthenticated":
                        if (arguments.isEmpty()) {
                            return Requirement.authenticated();
                        }
                        break;
                    case "isFullyAuthenticated":
                        if (arguments.isEmpty()) {
                            return Requirement.fullyAuthenticated();
                        }
                        break;
                    case "isRememberMe":
                        if (arguments.isEmpty()) {
                            return Requirement.rememberMe();
                        }
                        break;
                    case "isAnonymous":
                        if (arguments.isEmpty()) {
                            return Requirement.anonymous();
                        }
                        break;
                    case "permitAll":
                        return Requirement.permitAll();
                    case "denyAll":
                        return Requirement.denyAll();
                    default:
                        break;
                }
            }
            if (beans != null && root != null) {
                List<String> literals = new ArrayList<>();
                for (int i = 0; i < method.getChildCount(); i++) {
                    literals.add(method.getChild(i) instanceof StringLiteral literal
                            ? String.valueOf(literal.getLiteralValue().getValue()) : null);
                }
                Optional<Requirement> custom = beans.rootCall(root, method.getName(), literals, node.toStringAST(),
                        rootIgnored);
                if (custom.isPresent()) {
                    return custom.get();
                }
            }
        }
        return Requirement.expression(node.toStringAST());
    }

    private List<Requirement> children(SpelNode node) {
        List<Requirement> children = new ArrayList<>();
        for (int i = 0; i < node.getChildCount(); i++) {
            children.add(convert(node.getChild(i)));
        }
        return children;
    }

    /**
     * The method's arguments when all of them are string literals, otherwise {@code null}.
     */
    private static List<String> stringArguments(MethodReference method) {
        List<String> arguments = new ArrayList<>();
        for (int i = 0; i < method.getChildCount(); i++) {
            if (!(method.getChild(i) instanceof StringLiteral literal)) {
                return null;
            }
            arguments.add(String.valueOf(literal.getLiteralValue().getValue()));
        }
        return arguments;
    }
}
