package dev.crain.authtracer.scan;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.Body;
import sootup.core.types.ClassType;

/**
 * Intraprocedural def lookups on Jimple bodies.
 */
@Supports(Feature.APPLICATION_GRAPH)
public final class Locals {

    private Locals() {
    }

    /**
     * The call the statement makes, if it makes one.
     */
    public static Optional<AbstractInvokeExpr> invoke(Stmt stmt) {
        return stmt.isInvokableStmt() ? stmt.asInvokableStmt().getInvokeExpr() : Optional.empty();
    }

    /**
     * The value first assigned to the local, e.g. the invoke that produced it.
     */
    public static Optional<Value> definition(Body body, Local local) {
        for (Stmt stmt : body.getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt definition && definition.getLeftOp().equals(local)) {
                return Optional.of(definition.getRightOp());
            }
        }
        return Optional.empty();
    }

    /**
     * The class created into the local, when its first definition is a {@code new}.
     */
    public static Optional<ClassType> created(Body body, Local local) {
        return definition(body, local).filter(JNewExpr.class::isInstance).map(created -> ((JNewExpr) created)
                .getType());
    }

    /**
     * Every value assigned to the local, in statement order: a local the branches of a conditional each assign
     * ({@code cond ? "a" : "b"}) has one per branch.
     */
    public static List<Value> definitions(Body body, Local local) {
        List<Value> definitions = new ArrayList<>();
        for (Stmt stmt : body.getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt definition && definition.getLeftOp().equals(local)) {
                definitions.add(definition.getRightOp());
            }
        }
        return definitions;
    }

    /**
     * The values stored into an array local, in statement order, each followed to its definition when it is stored
     * through a local ({@code $stack3 = <SimpMessageType: MESSAGE>; $stack2[0] = $stack3}).
     */
    public static List<Value> elements(Body body, Local array) {
        List<Value> elements = new ArrayList<>();
        for (Stmt stmt : body.getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt definition && definition.getLeftOp() instanceof JArrayRef element
                    && element.getBase().equals(array)) {
                Value value = definition.getRightOp();
                elements.add(value instanceof Local local ? definition(body, local).orElse(local) : value);
            }
        }
        return elements;
    }

    /**
     * A varargs argument's string constants: the strings stored into the array local, as a varargs call's
     * {@code ("/a", "/b")} passes them.
     */
    public static List<String> strings(Body body, Value value) {
        return value instanceof Local array ? elements(body, array).stream().filter(StringConstant.class::isInstance)
                .map(element -> ((StringConstant) element).getValue()).toList() : List.of();
    }

    /**
     * A string or int constant's value, else what an evaluation of the method so far holds for the local.
     */
    public static Object evaluated(Immediate argument, Map<Local, Object> values) {
        if (argument instanceof StringConstant constant) {
            return constant.getValue();
        }
        if (argument instanceof IntConstant constant) {
            return constant.getValue();
        }
        return argument instanceof Local local ? values.get(local) : null;
    }

    /**
     * A string constant, else the string an evaluation of the method so far holds for the local.
     */
    public static Optional<String> text(Value value, Map<Local, Object> values) {
        if (value instanceof StringConstant constant) {
            return Optional.of(constant.getValue());
        }
        return value instanceof Local local && values.get(local) instanceof String text ? Optional.of(text)
                : Optional.empty();
    }

    /**
     * The parameter index when the local holds a method parameter.
     */
    public static OptionalInt parameterIndex(Body body, Local local) {
        return definition(body, local)
                .filter(JParameterRef.class::isInstance)
                .map(value -> OptionalInt.of(((JParameterRef) value).getIndex()))
                .orElse(OptionalInt.empty());
    }
}
