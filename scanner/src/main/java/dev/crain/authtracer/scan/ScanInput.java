package dev.crain.authtracer.scan;

import java.nio.file.Path;
import java.util.List;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.provided.ProvidedFacts;

/**
 * What to scan: one service's compiled classes plus the libraries they run with.
 *
 * @param classDirs the service's own compiled classes; these are the application classes
 * @param libraries runtime jars, used to resolve framework annotations and types
 * @param resourceDirs where {@code application.yaml}/{@code application.properties} live
 * @param packagePrefixes when not empty, only application classes in these packages are scanned
 * @param facts the Provided facts for this service
 */
@Supports(Feature.APPLICATION_GRAPH)
public record ScanInput(String service, String revision, List<Path> classDirs, List<Path> libraries,
        List<Path> resourceDirs, List<String> packagePrefixes, ProvidedFacts facts) {

    public ScanInput {
        classDirs = List.copyOf(classDirs);
        libraries = List.copyOf(libraries);
        resourceDirs = List.copyOf(resourceDirs);
        packagePrefixes = List.copyOf(packagePrefixes);
    }

    /**
     * Whether the class is in one of the packages (or their subpackages): {@code dev.a} covers {@code dev.a.X} and
     * {@code dev.a.b.Y}, not {@code dev.ab.Z}.
     */
    public boolean includes(String className) {
        return packagePrefixes.isEmpty() || packagePrefixes.stream()
                .anyMatch(prefix -> className.startsWith(prefix.endsWith(".") ? prefix : prefix + "."));
    }
}
