package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Requirement;

/**
 * Decision 0063 (AUTHZ-03, AUTHZ-04): Spring Security 7.1.1's built-in managers, as one table every reader of managers
 * shares: the {@code access(..)} DSL, method-security advisors, message, RSocket and gRPC rules. Each interpreter
 * hands over what it knows about a call's arguments; the overload is told apart by the called method's parameter
 * types ({@code hasAnyRole(String, String[])} takes its own prefix, {@code hasAnyRole(String...)} doesn't). Managers
 * built by these factories have no RoleHierarchy unless {@code setRoleHierarchy} gives them one, and always the
 * {@code ROLE_} prefix.
 */
@Supports(Feature.REQUIREMENTS)
final class BuiltInManagers {

    static final String PACKAGE = "org.springframework.security.authorization.";
    private static final String OAUTH2 = "org.springframework.security.oauth2.core.authorization.";
    /**
     * The static factories' prefix: {@code AuthorityAuthorizationManager.hasRole("X")} is {@code ROLE_X}.
     */
    static final SpelRequirements ROLE_PREFIX = new SpelRequirements("ROLE_");
    /**
     * What an operand of {@code anyOf}/{@code allOf} that isn't a manager AuthTracer read stands for.
     */
    static final String UNREAD_MANAGER = "AuthorizationManager";

    /**
     * What an interpreter knows about one argument of a factory call.
     */
    sealed interface Arg {
    }

    record Text(String value) implements Arg {
    }

    /**
     * A {@code String[]} (or {@code List<String>}): its constant elements, and whether every element is one.
     */
    record Texts(List<String> values, boolean complete) implements Arg {
    }

    /**
     * A manager, built-in or custom, as a requirement.
     */
    record Manager(Requirement requirement) implements Arg {
    }

    /**
     * An {@code AuthorizationManager[]}: the managers read, and whether every element is one.
     */
    record Managers(List<Requirement> requirements, boolean complete) implements Arg {
    }

    /**
     * {@code new AuthorizationDecision(granted)}, the default {@code anyOf}/{@code allOf} decision.
     */
    record Decision(boolean granted) implements Arg {
    }

    record Unknown() implements Arg {
    }

    static final Arg UNKNOWN = new Unknown();

    private BuiltInManagers() {
    }

    /**
     * Whether the class is one of the managers' factory classes, so a call on it is read here or not at all.
     */
    static boolean isFactoryClass(String owner) {
        return simpleName(owner) != null;
    }

    /**
     * A call to one of the static factories; empty when it isn't one, or its arguments aren't constants.
     *
     * @param parameterTypes the called method's parameter types ({@code java.lang.String[]}), {@code null} for a
     *        dynamic (Groovy) call, which is told apart by its arguments
     */
    static Optional<Requirement> factory(String owner, String name, List<String> parameterTypes, List<Arg> args) {
        String simpleName = simpleName(owner);
        if (simpleName == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(switch (simpleName) {
            case "AuthorityAuthorizationManager" -> prefixed(name, parameterTypes, args)
                    ? roles(name, args.subList(1, 2), role -> ((Text) args.getFirst()).value() + role, true, args)
                    : authorities(name, args, ROLE_PREFIX);
            case "AuthorityReactiveAuthorizationManager" -> authorities(name, args, ROLE_PREFIX);
            case "AllAuthoritiesAuthorizationManager", "AllAuthoritiesReactiveAuthorizationManager" ->
                name.equals("hasAllPrefixedAuthorities") && args.size() == 2 && args.getFirst() instanceof Text prefix
                        ? roles(name, args.subList(1, 2), role -> prefix.value() + role, false, args)
                        : authorities(name, args, ROLE_PREFIX);
            case "AuthenticatedAuthorizationManager" -> args.isEmpty() ? authentication(name) : null;
            case "AuthenticatedReactiveAuthorizationManager" -> name.equals("authenticated")
                    ? Requirement.authenticated() : null;
            case "SingleResultAuthorizationManager" -> switch (name) {
                case "permitAll" -> Requirement.permitAll();
                case "denyAll" -> Requirement.denyAll();
                default -> null;
            };
            case "AuthorizationManagers" -> composite(name, args);
            case "OAuth2AuthorizationManagers", "OAuth2ReactiveAuthorizationManagers" -> scopes(name, args, "SCOPE_");
            default -> null;
        });
    }

    /**
     * A rule method of a DSL that builds these managers, or a manager factory's method: {@code hasRole("X")} on an
     * {@code AuthorizedUrl}, a STOMP {@code Constraint}, an RSocket {@code Access}, a gRPC call, or an
     * {@code AuthorizationManagerFactory}. Empty when it isn't one, or its arguments aren't constants.
     *
     * @param roles the role prefix in effect
     */
    static Optional<Requirement> named(String name, List<Arg> args, SpelRequirements roles) {
        Requirement authentication = args.isEmpty() ? authentication(name) : null;
        if (authentication != null) {
            return Optional.of(authentication);
        }
        return Optional.ofNullable(switch (name) {
            case "permitAll" -> args.isEmpty() ? Requirement.permitAll() : null;
            case "denyAll" -> args.isEmpty() ? Requirement.denyAll() : null;
            default -> authorities(name, args, roles);
        });
    }

    /**
     * {@code OAuth2AuthorizationManagerFactory}'s and {@code OAuth2AuthorizationManagers}' scope methods:
     * {@code hasScope("x")} is {@code hasAuthority(prefix + "x")}.
     */
    static Requirement scopes(String name, List<Arg> args, String prefix) {
        List<String> scopes = texts(args).orElse(null);
        if (scopes == null) {
            return null;
        }
        List<String> authorities = scopes.stream().map(scope -> prefix + scope).toList();
        return switch (name) {
            case "hasScope", "hasAnyScope" -> Requirement.anyAuthority(authorities).withSource(source(name, scopes));
            case "hasAllScopes" -> Requirement.allAuthorities(authorities).withSource(source(name, scopes));
            default -> null;
        };
    }

    private static Requirement authentication(String name) {
        return switch (name) {
            case "authenticated" -> Requirement.authenticated();
            case "fullyAuthenticated" -> Requirement.fullyAuthenticated();
            case "rememberMe" -> Requirement.rememberMe();
            case "anonymous" -> Requirement.anonymous();
            default -> null;
        };
    }

    private static Requirement authorities(String name, List<Arg> args, SpelRequirements roles) {
        return switch (name) {
            case "hasRole", "hasAnyRole" -> roles(name, args, roles::role, true, args);
            case "hasAllRoles" -> roles(name, args, roles::role, false, args);
            case "hasAuthority", "hasAnyAuthority" -> roles(name, args, Function.identity(), true, args);
            case "hasAllAuthorities" -> roles(name, args, Function.identity(), false, args);
            default -> null;
        };
    }

    /**
     * @param named the arguments that name the roles or authorities
     * @param all every argument, for the source text
     */
    private static Requirement roles(String name, List<Arg> named, Function<String, String> authority, boolean any,
            List<Arg> all) {
        List<String> names = texts(named).orElse(null);
        if (names == null) {
            return null;
        }
        List<String> authorities = names.stream().map(authority).toList();
        return (any ? Requirement.anyAuthority(authorities) : Requirement.allAuthorities(authorities))
                .withSource(source(name, texts(all).orElse(names)));
    }

    /**
     * {@code anyOf(..)}, {@code allOf(..)} with or without a default decision, and {@code not(..)}. The default
     * decision answers when every manager abstains, which only a custom one can: then {@code anyOf(granted, ..)}
     * admits anyone.
     */
    private static Requirement composite(String name, List<Arg> args) {
        if (name.equals("not")) {
            return args.size() == 1 && args.getFirst() instanceof Manager manager
                    ? Requirement.not(manager.requirement()) : null;
        }
        boolean granted = !args.isEmpty() && args.getFirst() instanceof Decision decision && decision.granted();
        List<Requirement> operands = new ArrayList<>();
        boolean custom = false;
        for (Arg arg : args) {
            switch (arg) {
                case Managers managers -> {
                    operands.addAll(managers.requirements());
                    if (!managers.complete()) {
                        operands.add(Requirement.expression(UNREAD_MANAGER));
                    }
                }
                case Manager manager -> operands.add(manager.requirement());
                case Decision ignored -> {
                }
                default -> operands.add(Requirement.expression(UNREAD_MANAGER));
            }
        }
        for (Requirement operand : operands) {
            custom |= operand.kind() == Requirement.Kind.EXPRESSION;
        }
        if (operands.isEmpty()) {
            return null;
        }
        if (name.equals("anyOf") && granted && custom) {
            operands.add(Requirement.permitAll());
        }
        return switch (name) {
            case "anyOf" -> operands.size() == 1 ? operands.getFirst() : Requirement.or(operands);
            case "allOf" -> operands.size() == 1 ? operands.getFirst() : Requirement.and(operands);
            default -> null;
        };
    }

    /**
     * Whether the call is {@code hasAnyRole(String rolePrefix, String[] roles)}: javac picks it only for an explicit
     * array after a string.
     */
    private static boolean prefixed(String name, List<String> parameterTypes, List<Arg> args) {
        if (!name.equals("hasAnyRole") || args.size() != 2 || !(args.getFirst() instanceof Text)) {
            return false;
        }
        return parameterTypes == null ? args.get(1) instanceof Texts
                : parameterTypes.size() == 2 && parameterTypes.get(0).equals("java.lang.String");
    }

    /**
     * The strings the arguments are, when every one is a constant.
     */
    static Optional<List<String>> texts(List<Arg> args) {
        List<String> texts = new ArrayList<>();
        for (Arg arg : args) {
            if (arg instanceof Text text) {
                texts.add(text.value());
            }
            else if (arg instanceof Texts strings && strings.complete()) {
                texts.addAll(strings.values());
            }
            else {
                return Optional.empty();
            }
        }
        return texts.isEmpty() ? Optional.empty() : Optional.of(texts);
    }

    private static String source(String name, List<String> args) {
        return name + "(" + String.join(",", args) + ")";
    }

    private static String simpleName(String owner) {
        String simpleName = owner.startsWith(PACKAGE) ? owner.substring(PACKAGE.length())
                : owner.startsWith(OAUTH2) ? owner.substring(OAUTH2.length()) : null;
        return simpleName == null || simpleName.contains(".") ? null : switch (simpleName) {
            case "AuthorityAuthorizationManager", "AuthorityReactiveAuthorizationManager",
                    "AllAuthoritiesAuthorizationManager", "AllAuthoritiesReactiveAuthorizationManager",
                    "AuthenticatedAuthorizationManager", "AuthenticatedReactiveAuthorizationManager",
                    "SingleResultAuthorizationManager", "AuthorizationManagers", "OAuth2AuthorizationManagers",
                    "OAuth2ReactiveAuthorizationManagers" -> simpleName;
            default -> null;
        };
    }
}
