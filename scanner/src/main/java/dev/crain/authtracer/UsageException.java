package dev.crain.authtracer;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * What was asked can't be done as asked: an option is missing or malformed, or a path names no project. The command
 * line exits with 2 for it; a file whose content is wrong is an error (3), not a usage mistake.
 */
@Supports(Feature.COMMAND_LINE)
public class UsageException extends IllegalArgumentException {

    public UsageException(String message) {
        super(message);
    }
}
