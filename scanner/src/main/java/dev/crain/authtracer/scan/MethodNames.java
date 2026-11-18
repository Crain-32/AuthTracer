package dev.crain.authtracer.scan;

import java.util.stream.Collectors;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.core.types.Type;

/**
 * Readable, stable names for methods: {@code find(long)}, {@code com.example.Service#find(long)}.
 */
@Supports(Feature.APPLICATION_GRAPH)
public final class MethodNames {

    private MethodNames() {
    }

    public static String method(MethodSignature signature) {
        return signature.getName() + "(" + signature.getParameterTypes().stream()
                .map(MethodNames::typeName)
                .collect(Collectors.joining(",")) + ")";
    }

    public static String key(MethodSignature signature) {
        return signature.getDeclClassType().getFullyQualifiedName() + "#" + method(signature);
    }

    public static CodeRef codeRef(MethodSignature signature) {
        return CodeRef.ofMethod(signature.getDeclClassType().getFullyQualifiedName(), method(signature));
    }

    public static CodeRef codeRef(MethodSignature signature, Stmt stmt) {
        return codeRef(signature).atLine(stmt.getPositionInfo().getStmtPosition().getFirstLine());
    }

    /**
     * A class's name without its package; a nested class keeps its outer one, as {@code Outer$Inner}.
     */
    public static String simpleName(String className) {
        return className.substring(className.lastIndexOf('.') + 1);
    }

    private static String typeName(Type type) {
        return type instanceof ClassType classType ? classType.getFullyQualifiedName() : type.toString();
    }
}
