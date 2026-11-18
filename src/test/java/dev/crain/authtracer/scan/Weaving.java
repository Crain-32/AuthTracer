package dev.crain.authtracer.scan;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import org.aspectj.weaver.tools.GeneratedClassHandler;
import org.aspectj.weaver.tools.WeavingAdaptor;

/**
 * Weaves a fixture's compiled classes with the aspects in {@code spring-security-aspects}, through AspectJ's own
 * weaver: the bytecode an application compiled with ajc against those aspects has.
 */
public final class Weaving {

    private Weaving() {
    }

    /**
     * @param out the directory to write to; what it held is removed first
     * @return {@code out}, holding the fixture's classes, woven, and the closures the weaving made
     */
    public static Path weave(String fixturePackage, Path out) {
        try {
            if (Files.isDirectory(out)) {
                try (Stream<Path> old = Files.walk(out)) {
                    for (Path path : old.sorted(Comparator.reverseOrder()).toList()) {
                        Files.delete(path);
                    }
                }
            }
            Files.createDirectories(out);
            List<URL> classpath = new ArrayList<>();
            URL aspects = null;
            for (Path library : FixtureScans.paths("authtracer.fixtures.libraries")) {
                classpath.add(url(library));
                if (library.getFileName().toString().startsWith("spring-security-aspects-")) {
                    aspects = url(library);
                }
            }
            if (aspects == null) {
                throw new IllegalStateException("spring-security-aspects is not among the fixtures' libraries");
            }
            List<Path> roots = FixtureScans.paths("authtracer.fixtures.classes");
            roots.forEach(root -> classpath.add(url(root)));
            // AspectJ's weaver reads the JDK's own classes from its image.
            classpath.add(url(Path.of(System.getProperty("java.home"), "lib", "jrt-fs.jar")));
            GeneratedClassHandler closures = (name, originalBytes, wovenBytes) -> write(out, name, wovenBytes);
            WeavingAdaptor weaver = new WeavingAdaptor(closures, classpath.toArray(URL[]::new), new URL[] {aspects});
            String directory = "fixtures/" + fixturePackage;
            for (Path root : roots) {
                Path classes = root.resolve(directory);
                if (!Files.isDirectory(classes)) {
                    continue;
                }
                try (Stream<Path> files = Files.list(classes)) {
                    for (Path file : files.filter(f -> f.toString().endsWith(".class")).toList()) {
                        String name = root.relativize(file).toString().replace('/', '.').replaceAll("\\.class$", "");
                        byte[] bytes = Files.readAllBytes(file);
                        byte[] woven = weaver.weaveClass(name, bytes);
                        write(out, name, woven != null ? woven : bytes);
                    }
                }
            }
            return out;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static URL url(Path path) {
        try {
            return path.toUri().toURL();
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static void write(Path out, String className, byte[] bytes) {
        try {
            Path target = out.resolve(className.replace('.', '/') + ".class");
            Files.createDirectories(target.getParent());
            Files.write(target, bytes);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
