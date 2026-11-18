package dev.crain.authtracer.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The features this code is needed for: take it away and they break, or say less.
 * <p>
 * Every top-level class says which features it supports. A method or nested class says so too when it serves a
 * feature its class otherwise doesn't, typically where a finding is raised or one feature's output is made. Code that
 * every scan needs supports {@link Feature#APPLICATION_GRAPH}, which every other feature of a graph relies on.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.CONSTRUCTOR})
public @interface Supports {

    Feature[] value();
}
