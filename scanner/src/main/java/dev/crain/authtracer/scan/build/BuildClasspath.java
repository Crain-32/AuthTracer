package dev.crain.authtracer.scan.build;

import java.nio.file.Path;
import java.util.List;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * A built project's compiled classes, resources and runtime libraries.
 */
@Supports(Feature.PROJECT_BUILDS)
public record BuildClasspath(List<Path> classDirs, List<Path> resourceDirs, List<Path> libraries) {
}
