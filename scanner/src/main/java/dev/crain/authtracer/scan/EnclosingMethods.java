package dev.crain.authtracer.scan;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * The method a lambda body or a Groovy closure is written in. Compilers number them: javac's {@code
 * lambda$employee$2} by its place in the class, Kotlin's {@code employee$lambda$0} in the function, Groovy's
 * {@code Outer$_employee_closure1} class in the class, so a name taken from one changes when another is added before
 * it; the method it is written in doesn't. The code ajc moves out of a method it weaves (its around bodies, and the
 * closures that run them) is named by that method too.
 */
@Supports(Feature.APPLICATION_GRAPH)
public final class EnclosingMethods {

    /**
     * A closure class, {@code Outer$_method_closure1} or within another one {@code Outer$_method_closure1$_closure2}:
     * the class it is written in, then its own name.
     */
    private static final Pattern CLOSURE = Pattern.compile("(.+)\\$_(?:[^$]*_)?closure\\d+");
    /**
     * The closure ajc makes for around advice on a woven method, {@code Owner$AjcClosure1}, whose {@code run} calls
     * the around body it moved the method's code to, {@code name_aroundBody0}.
     */
    private static final Pattern AJC_CLOSURE = Pattern.compile("(.+)\\$AjcClosure\\d+");
    private static final Pattern AROUND_BODY = Pattern.compile(".+_aroundBody\\d+");
    /**
     * A method as {@link MethodNames#key} writes it: {@code app.Orders#lambda$list$0(boolean)}.
     */
    private static final Pattern KEY = Pattern.compile(
            "[A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)+#[\\w$]+\\([^()]*\\)");
    private static final int DEPTH = 8;

    private final ScanContext context;
    private final Map<String, JavaSootMethod> enclosing = new HashMap<>();

    public EnclosingMethods(ScanContext context) {
        this.context = context;
    }

    /**
     * The call site, in the method its lambda or closure is written in: the same line.
     */
    public CodeRef site(JavaSootMethod method, CodeRef site) {
        JavaSootMethod outer = of(method);
        return outer == method ? site
                : MethodNames.codeRef(outer.getSignature()).atLine(site.line());
    }

    /**
     * Decision 0089 (amended): the method as a path or a finding names it: the method its lambda or closure is
     * written in, with no number that changes as other lambdas are added.
     */
    public String key(JavaSootMethod method) {
        return MethodNames.key(of(method).getSignature());
    }

    /**
     * Decision 0089 (amended): the finding as it names code: a lambda body or closure is "a lambda in" the method it
     * is written in, and found at its line there.
     */
    public Finding named(Finding finding) {
        Matcher keys = KEY.matcher(finding.message());
        StringBuilder message = new StringBuilder();
        while (keys.find()) {
            String lambda = keys.start() == 0 ? "A lambda in " : "a lambda in ";
            keys.appendReplacement(message, Matcher.quoteReplacement(written(keys.group())
                    .map(method -> lambda + key(method)).orElse(keys.group())));
        }
        keys.appendTail(message);
        CodeRef location = finding.location();
        Optional<JavaSootMethod> lambda = location == null || location.method() == null ? Optional.empty()
                : written(location.key());
        return new Finding(finding.kind(), message.toString(), lambda.map(method -> {
            CodeRef outer = codeRef(method);
            return location.line() != null ? outer.atLine(location.line()) : outer;
        }).orElse(location));
    }

    /**
     * The lambda body or closure the key names, if it is one of the application's.
     */
    private Optional<JavaSootMethod> written(String key) {
        int hash = key.indexOf('#');
        String name = key.substring(hash + 1, key.indexOf('('));
        String owner = key.substring(0, hash);
        if (!name.startsWith("lambda$") && !name.contains("$lambda$")
                && !(name.equals("doCall") && CLOSURE.matcher(owner).matches())) {
            return Optional.empty();
        }
        return context.findClass(owner).filter(cls -> context.isApplication(cls.getType()))
                .flatMap(cls -> cls.getMethods().stream().filter(method -> method.hasBody()
                        && MethodNames.key(method.getSignature()).equals(key)).findFirst())
                .filter(this::written);
    }

    /**
     * Where the method is: a lambda's or closure's first line, in the method it is written in.
     */
    public CodeRef codeRef(JavaSootMethod method) {
        JavaSootMethod outer = of(method);
        return outer == method ? MethodNames.codeRef(method.getSignature())
                : MethodNames.codeRef(outer.getSignature()).atLine(firstLine(method));
    }

    /**
     * Whether the method is a lambda body or a closure some application method writes.
     */
    public boolean written(JavaSootMethod method) {
        return of(method) != method;
    }

    private static Integer firstLine(JavaSootMethod method) {
        return method.getBody().getStmts().stream().mapToInt(stmt -> stmt.getPositionInfo().getStmtPosition()
                .getFirstLine()).filter(line -> line > 0).min().stream().boxed().findFirst().orElse(null);
    }

    /**
     * The method that isn't a lambda body or a closure the method is written in; the method itself when it is none.
     */
    public JavaSootMethod of(JavaSootMethod method) {
        String key = MethodNames.key(method.getSignature());
        JavaSootMethod known = enclosing.get(key);
        if (known == null) {
            known = method;
            for (int depth = 0; depth < DEPTH; depth++) {
                Optional<JavaSootMethod> writer = writer(known);
                if (writer.isEmpty()) {
                    break;
                }
                known = writer.get();
            }
            enclosing.put(key, known);
        }
        return known;
    }

    /**
     * The method that creates the lambda (its {@code invokedynamic} names the body) or the closure (it makes a
     * {@code new} one), in the application.
     */
    private Optional<JavaSootMethod> writer(JavaSootMethod method) {
        String name = method.getName();
        // Kotlin doesn't mark its lambda bodies synthetic; an invokedynamic must name the body either way.
        boolean lambda = name.startsWith("lambda$") || name.contains("$lambda$");
        String owner = method.getDeclaringClassType().getFullyQualifiedName();
        Matcher closure = CLOSURE.matcher(owner);
        if (lambda) {
            return context.findClass(method.getDeclaringClassType())
                    .flatMap(cls -> creator(cls, value -> value instanceof JDynamicInvokeExpr dynamic
                            && dynamic.getBootstrapArgs().stream().anyMatch(argument -> argument instanceof MethodHandle
                                    handle && handle.getReferenceSignature().equals(method.getSignature()))));
        }
        Matcher woven = AJC_CLOSURE.matcher(owner);
        if (name.equals("run") && woven.matches()) {
            // ajc's: the woven method (or the around body of an advice around it) makes it.
            return context.findClass(woven.group(1)).flatMap(cls -> creator(cls, value -> value instanceof JNewExpr
                    created && created.getType().getFullyQualifiedName().equals(owner)));
        }
        if (AROUND_BODY.matcher(name).matches()) {
            // Its closure's run calls it.
            return context.applicationClasses().stream()
                    .filter(cls -> AJC_CLOSURE.matcher(cls.getName()).matches()
                            && cls.getName().startsWith(owner + "$AjcClosure"))
                    .flatMap(cls -> creator(cls, value -> value instanceof AbstractInvokeExpr invoke
                            && invoke.getMethodSignature().equals(method.getSignature())).stream())
                    .findFirst();
        }
        if (name.equals("doCall") && closure.matches()) {
            // Written in the outer class, or in a closure written there.
            return context.applicationClasses().stream()
                    .filter(cls -> cls.getName().startsWith(closure.group(1)) && !cls.getName().equals(owner))
                    .flatMap(cls -> creator(cls, value -> value instanceof JNewExpr created
                            && created.getType().getFullyQualifiedName().equals(owner)).stream())
                    .findFirst();
        }
        return Optional.empty();
    }

    private static Optional<JavaSootMethod> creator(JavaSootClass cls, Predicate<Value> creates) {
        for (JavaSootMethod candidate : cls.getMethods()) {
            if (!candidate.hasBody()) {
                continue;
            }
            for (Stmt stmt : candidate.getBody().getStmts()) {
                if (stmt instanceof AbstractDefinitionStmt definition && creates.test(definition.getRightOp())
                        || Locals.invoke(stmt).filter(creates::test).isPresent()) {
                    return Optional.of(candidate);
                }
            }
        }
        return Optional.empty();
    }
}
