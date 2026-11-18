package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.scan.EnclosingMethods;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.ArrayType;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootMethod;

/**
 * What a value the application's configuration hands Spring is built from (decision 0074): the objects it creates,
 * followed through locals, branches, values a lambda captures, the application's helper methods and its one
 * {@code @Bean} of an injected type; the library calls that return one; and what AuthTracer can't follow.
 */
@Supports({Feature.AUTHORITY_SOURCE, Feature.CALL_CREDENTIALS})
final class BuiltValues {

    private static final int DEPTH = 3;

    sealed interface Source permits Created, Called, Unread {
    }

    /**
     * A {@code new} of the type into the local, in the method.
     */
    record Created(ClassType type, JavaSootMethod method, Local local) implements Source {

        /**
         * The calls made on the object in the method that creates it: its constructor ({@code <init>}) and setters.
         */
        List<AbstractInstanceInvokeExpr> calls(String name) {
            return method.getBody().getStmts().stream().map(Locals::invoke).flatMap(Optional::stream)
                    .filter(invoke -> invoke instanceof AbstractInstanceInvokeExpr instance
                            && instance.getBase().equals(local) && invoke.getMethodSignature().getName().equals(name))
                    .map(AbstractInstanceInvokeExpr.class::cast).toList();
        }
    }

    /**
     * A library call that returns the value, in the method.
     */
    record Called(AbstractInvokeExpr call, JavaSootMethod method) implements Source {
    }

    /**
     * What AuthTracer can't follow: {@code a lambda in Config#manager}, {@code the field manager}.
     */
    record Unread(String what) implements Source {
    }

    private final ScanContext context;
    private final EnclosingMethods enclosing;
    private final Set<JavaSootMethod> following = new HashSet<>();

    BuiltValues(ScanContext context, EnclosingMethods enclosing) {
        this.context = context;
        this.enclosing = enclosing;
    }

    /**
     * What the value may be, one source for each way it is built.
     */
    List<Source> of(JavaSootMethod method, Immediate value) {
        return of(method, value, 0);
    }

    /**
     * What a {@code @Bean} method returns.
     */
    List<Source> returnedBy(JavaSootMethod method) {
        return returns(method, 0);
    }

    /**
     * The values a varargs array or a {@code List.of(..)} holds, each with its sources; the value itself otherwise.
     */
    List<List<Source>> parts(JavaSootMethod method, Immediate value) {
        List<List<Source>> parts = new ArrayList<>();
        if (value instanceof Local array && array.getType() instanceof ArrayType) {
            for (Stmt stmt : method.getBody().getStmts()) {
                if (stmt instanceof AbstractDefinitionStmt definition && definition.getLeftOp() instanceof JArrayRef
                        element && element.getBase().equals(array) && definition.getRightOp() instanceof Local part) {
                    parts.add(of(method, part));
                }
            }
            return parts;
        }
        Optional<Value> list = value instanceof Local local ? Locals.definition(method.getBody(), local)
                : Optional.empty();
        if (list.isPresent() && list.get() instanceof AbstractInvokeExpr call
                && call.getMethodSignature().getDeclClassType().getFullyQualifiedName().equals("java.util.List")) {
            call.getArgs().forEach(part -> parts.add(of(method, part)));
            return parts;
        }
        parts.add(of(method, value));
        return parts;
    }

    private List<Source> of(JavaSootMethod method, Immediate value, int depth) {
        List<Value> definitions = value instanceof Local local ? Locals.definitions(method.getBody(), local)
                : List.of();
        if (definitions.isEmpty()) {
            return List.of(new Unread("a value the scan can't follow"));
        }
        List<Source> sources = new ArrayList<>();
        for (Value definition : definitions) {
            sources.addAll(of(method, (Local) value, definition, depth));
        }
        return sources;
    }

    private List<Source> of(JavaSootMethod method, Local local, Value value, int depth) {
        return switch (value) {
            case JNewExpr created -> List.of(new Created(created.getType(), method, local));
            case Local other -> of(method, other, depth);
            // Kotlin casts what it passes to the setter's type.
            case JCastExpr cast when cast.getOp() instanceof Local other -> of(method, other, depth);
            case JParameterRef parameter -> captured(method, parameter.getIndex(), depth)
                    .orElseGet(() -> injected(parameter.getType().toString(), depth));
            case JDynamicInvokeExpr dynamic -> List.of(new Unread("a lambda in " + where(method)));
            case AbstractInvokeExpr call -> returned(method, call, depth);
            case JFieldRef field -> List.of(new Unread("the field " + field.getFieldSignature().getName()));
            default -> List.of(new Unread("a value the scan can't follow"));
        };
    }

    /**
     * What a lambda body's parameter holds when it is a value the lambda captures: the argument the
     * {@code invokedynamic} that makes it passes, in the method that makes it.
     */
    private Optional<List<Source>> captured(JavaSootMethod lambda, int index, int depth) {
        if (enclosing.of(lambda) == lambda) {
            return Optional.empty();
        }
        for (JavaSootMethod writer : context.findClass(lambda.getDeclaringClassType()).orElseThrow().getMethods()) {
            Optional<AbstractInvokeExpr> creates = writer.hasBody() ? writer.getBody().getStmts().stream()
                    .map(Locals::invoke).flatMap(Optional::stream)
                    .filter(invoke -> invoke instanceof JDynamicInvokeExpr dynamic && dynamic.getBootstrapArgs()
                            .stream().anyMatch(argument -> argument instanceof MethodHandle handle
                                    && handle.getReferenceSignature().equals(lambda.getSignature())))
                    .findFirst() : Optional.empty();
            if (creates.isPresent()) {
                return index < creates.get().getArgCount() ? Optional.of(of(writer, creates.get().getArg(index),
                        depth + 1)) : Optional.empty();
            }
        }
        return Optional.empty();
    }

    /**
     * A value the method is handed: the application's one {@code @Bean} of that type, as it builds it.
     */
    private List<Source> injected(String type, int depth) {
        List<JavaSootMethod> beans = SpringBeans.beanMethodsOf(context, Set.of(type)).stream()
                .filter(JavaSootMethod::hasBody).toList();
        return beans.size() == 1 ? returns(beans.getFirst(), depth)
                : List.of(new Unread("an injected " + MethodNames.simpleName(type)));
    }

    /**
     * What an application method returns; a library call as itself.
     */
    private List<Source> returned(JavaSootMethod method, AbstractInvokeExpr call, int depth) {
        Optional<JavaSootMethod> callee = context.findMethod(call.getMethodSignature())
                .filter(found -> found.hasBody() && context.isApplication(found.getDeclaringClassType()));
        if (callee.isEmpty()) {
            return List.of(new Called(call, method));
        }
        return returns(callee.get(), depth);
    }

    private List<Source> returns(JavaSootMethod method, int depth) {
        if (depth >= DEPTH || !following.add(method)) {
            return List.of(new Unread(where(method) + "()"));
        }
        List<Source> sources = new ArrayList<>();
        method.getBody().getStmts().stream().filter(JReturnStmt.class::isInstance)
                .forEach(stmt -> sources.addAll(of(method, ((JReturnStmt) stmt).getOp(), depth + 1)));
        following.remove(method);
        return sources;
    }

    /**
     * {@code Config#manager}: the method a lambda's body is written in.
     */
    private String where(JavaSootMethod method) {
        JavaSootMethod outer = enclosing.of(method);
        return MethodNames.simpleName(outer.getDeclaringClassType().getFullyQualifiedName()) + "#" + outer.getName();
    }
}
