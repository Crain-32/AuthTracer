package dev.crain.authtracer.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * A known, deliberately deferred change. Used instead of long comments so deferred work is greppable.
 */
@Documented
@Retention(RetentionPolicy.SOURCE)
public @interface Might {

    /**
     * What might change, and when.
     */
    String value();
}
