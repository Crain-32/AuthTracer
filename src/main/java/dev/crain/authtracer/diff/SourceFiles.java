package dev.crain.authtracer.diff;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.provided.ProvidedFacts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Finds the source file and line of a {@link CodeRef} in a Gradle or Maven project: under {@code src/<set>/java},
 * {@code kotlin} or {@code groovy}, by package and class name, or a resource under {@code src/<set>/resources} by its
 * path. Graphs record lines only for statements, so a method's line is found by its declaration in the source.
 */
@Supports({Feature.SARIF_ANNOTATIONS, Feature.AGENT_REPORT})
final class SourceFiles {

    private static final Logger log = LoggerFactory.getLogger(SourceFiles.class);

    /**
     * Where a CodeRef is, as SARIF wants it: a path relative to the repository root, with {@code /}.
     */
    record Location(String uri, int line) {
    }

    private static final Set<String> LANGUAGES = Set.of("java", "kotlin", "groovy", "resources", "webapp");
    private static final List<String> EXTENSIONS = List.of(".java", ".kt", ".groovy");
    /**
     * Annotations and modifiers that may come before a method's return type on its line.
     */
    private static final String MODIFIERS = "(@[\\w.]+(\\([^)]*\\))?\\s+)*"
            + "((public|protected|private|static|final|abstract|synchronized|default|open|override|suspend|internal"
            + "|operator|inline)\\s+)*";
    /**
     * A statement that reads like a declaration of the method it calls: {@code throw notFound(id);}.
     */
    private static final Pattern STATEMENT = Pattern.compile("^\\s*(return|throw|else|yield|new|assert|case)\\b");
    private static final Set<String> SKIPPED = Set.of("build", ".gradle", ".git", ".idea", "node_modules", "out");

    private final Path project;
    private final Path repository;
    private final List<Path> roots;

    private SourceFiles(Path project, Path repository, List<Path> roots) {
        this.project = project;
        this.repository = repository;
        this.roots = roots;
    }

    /**
     * Each service's sources, for the services whose project is at hand.
     */
    static final class ByService {

        private final Map<String, SourceFiles> files = new LinkedHashMap<>();

        ByService(Map<String, Path> projects) {
            projects.forEach((service, project) -> files.put(service, SourceFiles.of(project)));
        }

        /**
         * Where a change's site is; empty when it has none or its service's source isn't at hand.
         */
        Optional<Location> locate(DiffReport.Site site) {
            return Optional.ofNullable(site).filter(found -> files.containsKey(found.service()))
                    .flatMap(found -> files.get(found.service()).locate(found.code(), found.annotation()));
        }
    }

    static SourceFiles of(Path project) {
        Path absolute = project.toAbsolutePath().normalize();
        try (Stream<Path> paths = Files.walk(absolute, 4)) {
            List<Path> roots = paths.filter(Files::isDirectory)
                    .filter(dir -> LANGUAGES.contains(dir.getFileName().toString()))
                    .filter(dir -> dir.getNameCount() >= 3 && dir.getParent().getParent().getFileName().toString()
                            .equals("src"))
                    .filter(dir -> !SKIPPED.contains(absolute.relativize(dir).getName(0).toString()))
                    .sorted().toList();
            return new SourceFiles(absolute, repositoryOf(absolute), roots);
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    /**
     * @param annotation the annotation the code is marked with, e.g. {@code @PreAuthorize}: its line is preferred,
     *        as a change to the check is made there
     */
    Optional<Location> locate(CodeRef code, String annotation) {
        if (code == null) {
            return Optional.empty();
        }
        if (code.className().equals(ProvidedFacts.LOCAL_FILE)) {
            // A Provided fact, or a conflict between facts: the project's own facts file.
            Path file = project.resolve(ProvidedFacts.LOCAL_FILE);
            return Files.isRegularFile(file) ? Optional.of(new Location(repository.relativize(file).toString()
                    .replace('\\', '/'), code.line() != null ? code.line() : 1)) : Optional.empty();
        }
        if (code.className().contains("/") || code.className().matches(".*\\.(xml|html)")) {
            // A resource, e.g. a template's sec:authorize (decision 0035): its path and line as recorded.
            for (Path root : roots) {
                Path file = root.resolve(code.className());
                if (Files.isRegularFile(file)) {
                    return Optional.of(new Location(repository.relativize(file).toString().replace('\\', '/'),
                            code.line() != null ? code.line() : 1));
                }
            }
            return Optional.empty();
        }
        String outer = code.className().contains("$") ? code.className().substring(0, code.className().indexOf('$'))
                : code.className();
        int dot = outer.lastIndexOf('.');
        String packagePath = dot < 0 ? "" : outer.substring(0, dot).replace('.', '/');
        String simple = outer.substring(dot + 1);
        for (Path root : roots) {
            Path dir = root.resolve(packagePath);
            Optional<Path> file = file(dir, simple);
            if (file.isPresent()) {
                return Optional.of(new Location(repository.relativize(file.get()).toString().replace('\\', '/'),
                        annotated(file.get(), line(file.get(), simple, code), annotation)));
            }
        }
        return Optional.empty();
    }

    /**
     * {@code Simple.java}, {@code Simple.kt}, {@code Simple.groovy}; Kotlin's {@code FileKt} is {@code File.kt}; else
     * the Kotlin or Groovy file in the package that declares the class.
     */
    private static Optional<Path> file(Path dir, String simple) {
        for (String extension : EXTENSIONS) {
            if (Files.isRegularFile(dir.resolve(simple + extension))) {
                return Optional.of(dir.resolve(simple + extension));
            }
        }
        Path facade = dir.resolve(simple.replaceAll("Kt$", "") + ".kt");
        if (simple.endsWith("Kt") && Files.isRegularFile(facade)) {
            return Optional.of(facade);
        }
        if (!Files.isDirectory(dir)) {
            return Optional.empty();
        }
        Pattern declaration = declaration(simple);
        try (Stream<Path> files = Files.list(dir)) {
            return files.filter(file -> file.toString().endsWith(".kt") || file.toString().endsWith(".groovy"))
                    .sorted().filter(file -> declaration.matcher(read(file)).find()).findFirst();
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    /**
     * The recorded line, else the method's declaration, else the class's, else 1. Of overloads, the one whose
     * parameters the method key names, else the first with as many.
     */
    private static int line(Path file, String simple, CodeRef code) {
        if (code.line() != null) {
            return code.line();
        }
        List<String> lines = read(file).lines().toList();
        if (code.method() != null) {
            // A method key may name the method only, without its parameters (Data REST's findAll).
            int parameters = code.method().indexOf('(');
            String name = (parameters < 0 ? code.method() : code.method().substring(0, parameters))
                    .replaceAll("\\$.*", "");
            boolean constructor = name.equals("<init>");
            // A declaration: modifiers, then a return type, fun or def (a constructor needs none), each with the
            // method's type parameters if it has some, then the name.
            String returnType = constructor ? "" : "(fun\\s+(<.*?>\\s+)?|(<.*?>\\s+)?[\\w<>\\[\\],.?]+\\s+)";
            Pattern method = Pattern.compile("^\\s*" + MODIFIERS + returnType
                    + Pattern.quote(constructor ? simple : name) + "\\s*\\(");
            // Each declaration's line, and where its parameters start; with or without a body, not a statement
            // calling it.
            Map<Integer, Integer> declarations = new LinkedHashMap<>();
            for (int i = 0; i < lines.size(); i++) {
                Matcher found = method.matcher(lines.get(i));
                if (found.find() && !STATEMENT.matcher(lines.get(i)).find()) {
                    declarations.put(i, found.end());
                }
            }
            if (!declarations.isEmpty()) {
                int first = declarations.keySet().iterator().next();
                if (parameters < 0 || declarations.size() == 1) {
                    return first + 1;
                }
                List<String> wanted = parameterTypes(code.method().substring(parameters + 1,
                        code.method().lastIndexOf(')')), true);
                Map<Integer, List<String>> declared = new LinkedHashMap<>();
                declarations.forEach((index, column) -> declared.put(index, declaredTypes(lines, index, column)));
                return declared.entrySet().stream().filter(entry -> entry.getValue().equals(wanted))
                        .map(Map.Entry::getKey).findFirst()
                        .or(() -> declared.entrySet().stream().filter(entry -> entry.getValue().size() == wanted.size())
                                .map(Map.Entry::getKey).findFirst())
                        .orElse(first) + 1;
            }
        }
        Pattern declaration = declaration(simple);
        for (int i = 0; i < lines.size(); i++) {
            if (declaration.matcher(lines.get(i)).find()) {
                return i + 1;
            }
        }
        return 1;
    }

    /**
     * The simple, lower-cased type names of a parameter list: from a method key ({@code long,java.lang.String[]}),
     * or as declared in Java ({@code final long id, String... names}) or Kotlin ({@code id: Long, names: String}).
     */
    private static List<String> parameterTypes(String list, boolean key) {
        List<String> types = new ArrayList<>();
        for (String parameter : topLevel(list)) {
            String text = parameter.replaceAll("@[\\w.]+(\\([^)]*\\))?", "").replaceAll("<[^<>]*>", "")
                    .replaceAll("<[^<>]*>", "").strip();
            if (text.isEmpty()) {
                continue;
            }
            String type;
            if (key) {
                type = text;
            }
            else if (text.contains(":")) {
                type = text.substring(text.indexOf(':') + 1).split("=")[0].strip().replace("?", "");
            }
            else {
                String[] words = text.replace("...", "[] ").replace("final ", "").strip().split("\\s+");
                type = String.join("", Arrays.asList(words).subList(0, Math.max(1, words.length - 1)));
            }
            String simple = type.substring(type.lastIndexOf('.') + 1);
            types.add(simple.substring(simple.lastIndexOf('$') + 1).toLowerCase(Locale.ROOT));
        }
        return types;
    }

    /**
     * The parameter types of the declaration on line {@code index} whose parameters start at {@code column}, read up
     * to their closing parenthesis.
     */
    private static List<String> declaredTypes(List<String> lines, int index, int column) {
        StringBuilder text = new StringBuilder();
        int depth = 1;
        for (int i = index; i < lines.size() && i < index + 30; i++) {
            String line = i == index ? lines.get(i).substring(column) : lines.get(i);
            for (char c : line.toCharArray()) {
                if (c == '(') {
                    depth++;
                }
                else if (c == ')' && --depth == 0) {
                    return parameterTypes(text.toString(), false);
                }
                text.append(c);
            }
            text.append(' ');
        }
        return parameterTypes(text.toString(), false);
    }

    /**
     * Splits at the commas outside parentheses and angle brackets.
     */
    private static List<String> topLevel(String list) {
        List<String> parts = new ArrayList<>();
        int depth = 0;
        StringBuilder current = new StringBuilder();
        for (char c : list.toCharArray()) {
            if (c == '(' || c == '<') {
                depth++;
            }
            else if (c == ')' || c == '>') {
                depth--;
            }
            if (c == ',' && depth == 0) {
                parts.add(current.toString());
                current.setLength(0);
            }
            else {
                current.append(c);
            }
        }
        parts.add(current.toString());
        return parts;
    }

    private static Pattern declaration(String simple) {
        return Pattern.compile("\\b(class|object|interface|enum|record|trait)\\s+" + Pattern.quote(simple) + "\\b");
    }

    /**
     * The line of the annotation among those just above (or on) a declaration, else the declaration's: above it are
     * its annotations, their arguments however many lines they take, and its doc comment.
     */
    private static int annotated(Path file, int declaration, String annotation) {
        if (annotation == null) {
            return declaration;
        }
        List<String> lines = read(file).lines().toList();
        Pattern marker = Pattern.compile(Pattern.quote(annotation) + "\\b");
        // Parentheses closed below and not opened yet: inside an annotation's arguments.
        int unopened = 0;
        for (int i = declaration - 1; i >= 0 && i >= declaration - 12 && i < lines.size(); i--) {
            String line = lines.get(i).strip();
            if (marker.matcher(line).find()) {
                return i + 1;
            }
            if (i < declaration - 1) {
                unopened += count(line, ')') - count(line, '(');
            }
            boolean partOfDeclaration = i == declaration - 1 || unopened > 0 || line.startsWith("@")
                    || line.startsWith("*") || line.startsWith("/");
            if (!partOfDeclaration) {
                break;
            }
        }
        return declaration;
    }

    private static int count(String line, char c) {
        return (int) line.chars().filter(found -> found == c).count();
    }

    /**
     * The enclosing git repository's root, whose relative paths code scanning matches; the project when there is none.
     */
    private static Path repositoryOf(Path project) {
        for (Path dir = project; dir != null; dir = dir.getParent()) {
            if (Files.exists(dir.resolve(".git"))) {
                return dir;
            }
        }
        return project;
    }

    /**
     * A source file that isn't UTF-8 (a Latin-1 comment) is read byte for byte, which keeps its lines; one that can't
     * be read is warned about and found nowhere, so the report places its code at line 1 rather than failing.
     */
    private static String read(Path file) {
        try {
            return Files.readString(file);
        }
        catch (MalformedInputException ex) {
            try {
                return Files.readString(file, StandardCharsets.ISO_8859_1);
            }
            catch (IOException again) {
                log.warn("Couldn't read {}: {}", file, again.toString());
                return "";
            }
        }
        catch (IOException ex) {
            log.warn("Couldn't read {}: {}", file, ex.toString());
            return "";
        }
    }
}
