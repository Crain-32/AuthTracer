package dev.crain.authtracer.diff;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * Text interpolated into the Markdown tables the diff and the CLI print.
 */
@Supports({Feature.DIFF, Feature.COMMAND_LINE})
public final class Markdown {

    private Markdown() {
    }

    /**
     * A table cell: a {@code |} would end it and a line break the row, as an endpoint's params or a check's
     * expression can hold ({@code hasRole('A') || hasRole('B')}).
     */
    public static String cell(String value) {
        return value == null ? "" : value.replace("|", "\\|").replaceAll("\\R", " ");
    }

    /**
     * A table cell in code font, e.g. an endpoint.
     */
    public static String code(String value) {
        return "`" + cell(value) + "`";
    }
}
