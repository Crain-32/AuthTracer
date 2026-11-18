package dev.crain.authtracer.mutation;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;

/**
 * Compiles one fixture package's sources, some of them changed, as Gradle compiles the fixtures ({@code -g},
 * {@code -parameters}), against the fixtures' classpath. One file manager serves every compilation, so the library
 * jars are opened once.
 */
final class MutantCompiler implements AutoCloseable {

    private static final List<String> OPTIONS = List.of("-g", "-parameters", "-proc:none", "-nowarn", "-Xlint:none",
            "-encoding", "UTF-8");

    private final JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    private final StandardJavaFileManager manager;

    MutantCompiler(List<Path> classpath) throws IOException {
        manager = compiler.getStandardFileManager(null, Locale.ROOT, StandardCharsets.UTF_8);
        manager.setLocationFromPaths(StandardLocation.CLASS_PATH, classpath);
    }

    /**
     * Compiles the files into {@code out}, each in {@code changed} with its new text.
     *
     * @return the errors, when it doesn't compile
     */
    Optional<String> compile(List<Path> files, Map<Path, String> changed, Path out) {
        try {
            Files.createDirectories(out);
            manager.setLocationFromPaths(StandardLocation.CLASS_OUTPUT, List.of(out));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        List<JavaFileObject> units = new ArrayList<>();
        for (Path file : files) {
            String text = changed.get(file);
            if (text == null) {
                manager.getJavaFileObjects(file).forEach(units::add);
            } else {
                units.add(new SimpleJavaFileObject(file.toUri(), JavaFileObject.Kind.SOURCE) {
                    @Override
                    public CharSequence getCharContent(boolean ignoreEncodingErrors) {
                        return text;
                    }
                });
            }
        }
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        boolean compiled = compiler.getTask(null, manager, diagnostics, OPTIONS, null, units).call();
        if (compiled) {
            return Optional.empty();
        }
        return Optional.of(diagnostics.getDiagnostics().stream()
                .filter(diagnostic -> diagnostic.getKind() == Diagnostic.Kind.ERROR)
                .map(diagnostic -> (diagnostic.getSource() == null ? "" : Path.of(diagnostic.getSource().toUri())
                        .getFileName() + ":" + diagnostic.getLineNumber() + " ") + diagnostic.getMessage(Locale.ROOT))
                .limit(3).collect(Collectors.joining("; ")));
    }

    @Override
    public void close() throws IOException {
        manager.close();
    }
}
