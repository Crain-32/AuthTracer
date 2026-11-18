package dev.crain.authtracer.graph;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * A place in the scanned code: a class, optionally a method sub-signature and a source line.
 */
@Supports(Feature.APPLICATION_GRAPH)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CodeRef(String className, String method, Integer line) {

    public static CodeRef ofClass(String className) {
        return new CodeRef(className, null, null);
    }

    public static CodeRef ofMethod(String className, String method) {
        return new CodeRef(className, method, null);
    }

    public CodeRef atLine(Integer line) {
        return new CodeRef(className, method, line != null && line > 0 ? line : null);
    }

    /**
     * {@code Class#method(args)}, without the line, used inside node ids.
     */
    public String key() {
        return method == null ? className : className + "#" + method;
    }
}
