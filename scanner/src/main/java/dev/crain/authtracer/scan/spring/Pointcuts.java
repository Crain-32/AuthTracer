package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Might;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.types.ClassType;
import sootup.core.types.Type;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * The AspectJ pointcut expressions Spring AOP advisors are usually given (METHOD-11), read without AspectJ:
 * {@code execution(..)}, {@code within(..)}, {@code @annotation(..)} and {@code @within(..)}, joined with
 * {@code &&}, {@code ||} and {@code !}. Type patterns are fully qualified: {@code *} matches within one name,
 * {@code ..} any number of packages. An annotation designator naming a binding or a simple name is not read.
 */
@Supports(Feature.METHOD_SECURITY)
final class Pointcuts {

    /**
     * A parsed expression: whether it matches a method declared in (or inherited by) a class.
     */
    @FunctionalInterface
    interface Pointcut {
        boolean matches(JavaSootClass cls, JavaSootMethod method);
    }

    private final ScanContext context;

    Pointcuts(ScanContext context) {
        this.context = context;
    }

    /**
     * Empty when the expression uses something outside the subset ({@code args}, {@code bean}, {@code target}...).
     */
    @Might("Evaluate the rest of the AspectJ pointcut language (args, this, target, bean) with AspectJ itself")
    Optional<Pointcut> parse(String expression) {
        try {
            Parser parser = new Parser(tokens(expression));
            Pointcut pointcut = parser.or();
            return parser.done() ? Optional.of(pointcut) : Optional.empty();
        }
        catch (IllegalArgumentException unsupported) {
            return Optional.empty();
        }
    }

    private static List<String> tokens(String expression) {
        List<String> tokens = new ArrayList<>();
        int i = 0;
        while (i < expression.length()) {
            char c = expression.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
            }
            else if (expression.startsWith("&&", i) || expression.startsWith("||", i)) {
                tokens.add(expression.substring(i, i + 2));
                i += 2;
            }
            else if ("!()&|".indexOf(c) >= 0) {
                // A lone & or | is a token of its own, which no rule accepts.
                tokens.add(String.valueOf(c));
                i++;
            }
            else {
                int start = i;
                while (i < expression.length() && !Character.isWhitespace(expression.charAt(i))
                        && "!()&|".indexOf(expression.charAt(i)) < 0) {
                    i++;
                }
                tokens.add(expression.substring(start, i));
            }
        }
        return tokens;
    }

    private final class Parser {

        private final List<String> tokens;
        private int next;

        Parser(List<String> tokens) {
            this.tokens = tokens;
        }

        boolean done() {
            return next == tokens.size();
        }

        Pointcut or() {
            Pointcut left = and();
            while (peek("||") || peek("or")) {
                next++;
                Pointcut first = left;
                Pointcut second = and();
                left = (cls, method) -> first.matches(cls, method) || second.matches(cls, method);
            }
            return left;
        }

        Pointcut and() {
            Pointcut left = not();
            while (peek("&&") || peek("and")) {
                next++;
                Pointcut first = left;
                Pointcut second = not();
                left = (cls, method) -> first.matches(cls, method) && second.matches(cls, method);
            }
            return left;
        }

        Pointcut not() {
            if (peek("!") || peek("not")) {
                next++;
                Pointcut negated = not();
                return (cls, method) -> !negated.matches(cls, method);
            }
            if (peek("(")) {
                next++;
                Pointcut inner = or();
                expect(")");
                return inner;
            }
            return designator();
        }

        /**
         * {@code name(...)}: the arguments are everything up to the matching parenthesis.
         */
        Pointcut designator() {
            String name = take();
            expect("(");
            StringBuilder argument = new StringBuilder();
            int depth = 1;
            while (true) {
                String token = take();
                if (token.equals("(")) {
                    depth++;
                }
                if (token.equals(")") && --depth == 0) {
                    break;
                }
                argument.append(argument.isEmpty() || token.equals(")") || token.equals("(")
                        || argument.charAt(argument.length() - 1) == '(' ? "" : " ").append(token);
            }
            String text = argument.toString().trim();
            return switch (name) {
                case "execution" -> execution(text);
                case "within" -> {
                    Predicate<String> type = typePattern(text);
                    yield (cls, method) -> type.test(name(cls.getType()));
                }
                case "@annotation", "@within" -> {
                    if (!text.matches("[\\w$]+(\\.[\\w$]+)+")) {
                        // A simple name, or a binding to the advice's parameter, whose type AuthTracer doesn't read.
                        throw new IllegalArgumentException(text);
                    }
                    yield name.equals("@annotation") ? (cls, method) -> context.hasAnnotation(method, text)
                            : (cls, method) -> context.hasAnnotation(cls, text);
                }
                default -> throw new IllegalArgumentException(name);
            };
        }

        private boolean peek(String token) {
            return next < tokens.size() && tokens.get(next).equals(token);
        }

        private String take() {
            if (next >= tokens.size()) {
                throw new IllegalArgumentException("end of expression");
            }
            return tokens.get(next++);
        }

        private void expect(String token) {
            if (!take().equals(token)) {
                throw new IllegalArgumentException("expected " + token);
            }
        }
    }

    /**
     * {@code [modifiers] returnType [declaringType.]name(params) [throws ..]}.
     */
    private Pointcut execution(String pattern) {
        String text = pattern.replaceAll("\\s+throws\\s+.*$", "");
        int open = text.indexOf('(');
        // The designator's argument has balanced parentheses, so the last ) closes the parameters.
        int close = text.lastIndexOf(')');
        if (open < 0) {
            throw new IllegalArgumentException(pattern);
        }
        List<String> head = new ArrayList<>(List.of(text.substring(0, open).trim().split("\\s+")));
        List<String> parameters = text.substring(open + 1, close).isBlank() ? List.of()
                : List.of(text.substring(open + 1, close).split("\\s*,\\s*"));
        boolean publicOnly = head.remove("public");
        boolean protectedOnly = head.remove("protected");
        if (head.size() != 2) {
            throw new IllegalArgumentException(pattern);
        }
        Predicate<String> returns = typePattern(head.get(0));
        String qualified = head.get(1);
        int dot = qualified.lastIndexOf('.');
        Predicate<String> declaring = dot < 0 ? any -> true : typePattern(qualified.substring(0, dot)
                .replaceAll("\\.$", ".."));
        String namePattern = dot < 0 ? qualified : qualified.substring(dot + 1);
        if (!namePattern.matches("[\\w$*]+")) {
            throw new IllegalArgumentException(pattern);
        }
        Pattern methodName = wildcard(namePattern);
        return (cls, method) -> (!publicOnly || method.isPublic()) && (!protectedOnly || method.isProtected())
                && returns.test(name(method.getReturnType()))
                && methodName.matcher(method.getName()).matches()
                && parametersMatch(parameters, method.getParameterTypes().stream().map(Pointcuts::name).toList())
                && declaredBy(cls, method).stream().anyMatch(declaring);
    }

    /**
     * The class and the supertypes that declare the same method, since a pattern may name an interface.
     */
    private List<String> declaredBy(JavaSootClass cls, JavaSootMethod method) {
        List<String> types = new ArrayList<>(List.of(name(cls.getType())));
        List<ClassType> supertypes = new ArrayList<>(context.superClassesOf(cls.getType()));
        supertypes.addAll(context.interfacesOf(cls.getType()));
        for (ClassType supertype : supertypes) {
            context.findClass(supertype).filter(found -> found.getMethod(method.getSubSignature()).isPresent())
                    .ifPresent(found -> types.add(name(supertype)));
        }
        return types;
    }

    private static boolean parametersMatch(List<String> patterns, List<String> types) {
        if (patterns.isEmpty()) {
            return types.isEmpty();
        }
        String first = patterns.getFirst();
        if (first.equals("..")) {
            for (int skip = 0; skip <= types.size(); skip++) {
                if (parametersMatch(patterns.subList(1, patterns.size()), types.subList(skip, types.size()))) {
                    return true;
                }
            }
            return false;
        }
        return !types.isEmpty() && typePattern(first).test(types.getFirst())
                && parametersMatch(patterns.subList(1, patterns.size()), types.subList(1, types.size()));
    }

    /**
     * A type pattern against a fully qualified name; {@code java.lang} types and primitives may be named simply.
     * Anything else AspectJ allows in one ({@code Repo+}, {@code @Ann *}, {@code (A || B)}) is not read.
     */
    private static Predicate<String> typePattern(String pattern) {
        if (pattern.equals("*")) {
            return any -> true;
        }
        if (!pattern.matches("[\\w$.*\\[\\]]+")) {
            throw new IllegalArgumentException(pattern);
        }
        StringBuilder regex = new StringBuilder();
        String[] pieces = pattern.split("\\.\\.", -1);
        for (int i = 0; i < pieces.length; i++) {
            if (i > 0) {
                // A trailing .. (com.acme.admin..*(..) declares com.acme.admin..) is any type in or below it.
                regex.append(i == pieces.length - 1 && pieces[i].isEmpty() ? "(?:\\.[^.]+)+"
                        : "\\.(?:[^.]+\\.)*");
            }
            regex.append(wildcard(pieces[i]).pattern().replace(".*", "[^.]*"));
        }
        Pattern compiled = Pattern.compile(regex.toString());
        return name -> compiled.matcher(name).matches()
                || !pattern.contains(".") && name.startsWith("java.lang.") && compiled.matcher(name.substring(10))
                        .matches();
    }

    private static Pattern wildcard(String text) {
        return Pattern.compile(Pattern.quote(text).replace("*", "\\E.*\\Q"));
    }

    private static String name(Type type) {
        String name = type instanceof ClassType classType ? classType.getFullyQualifiedName() : type.toString();
        return name.replace('$', '.');
    }
}
