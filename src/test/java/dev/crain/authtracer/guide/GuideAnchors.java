package dev.crain.authtracer.guide;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalInt;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Points the links of the codebase guide at the lines the classes and members they name are declared on now, as
 * {@code #L123} anchors. Lines move with nearly every edit, so the anchors are refreshed on demand rather than checked
 * on every build: {@code scripts/guide-anchors.sh}, or {@code ./gradlew guideAnchors}. Between runs an anchor may be a
 * few lines off; the link's text still names what it points at, and that is what {@link CodebaseGuideTests} checks.
 * <p>
 * A link is anchored when its text is code ({@code `Linker.link`}) and it leads to a source file: the names in the text
 * are found in turn, each after the one before ({@code SpringSecurityModule.Scan.walk} finds {@code walk} inside
 * {@code Scan}), a declaration first. Links to a whole file ({@code `App.tsx`}), a directory or a page are left alone.
 */
public final class GuideAnchors {

    static final Path GUIDE = Path.of("guide/codebase");
    static final Pattern LINK = Pattern.compile("\\[([^\\]]+)]\\(([^)\\s]+)\\)");
    static final Pattern FENCE = Pattern.compile("(?ms)^```.*?^```");
    static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*");
    static final Pattern LINE_ANCHOR = Pattern.compile("#L\\d+$");

    // Declarations, most telling first: a type, a method, a field or constant, a record component (or a parameter on a
    // line of its own), an enum constant, a Gradle task. Java's members are modifiers, a type, then the name; the type
    // can't be a keyword that starts a statement.
    private static final String TYPE = "\\b(?:class|interface|enum|record|object|trait)\\s+%s\\b";
    private static final String MODIFIERS = "^\\s*(?:@[\\w.]+(?:\\([^)]*\\))?\\s+)*(?:(?:public|protected|private|static"
            + "|final|abstract|synchronized|default|native|transient|volatile)\\s+)*(?:<[^>]+>\\s+)?"
            + "(?!(?:return|new|throw|else|case|yield)\\b)[\\w$][\\w.$<>\\[\\],? ]*?\\s+";
    private static final List<String> JAVA = List.of(TYPE, MODIFIERS + "%s\\s*\\(", MODIFIERS + "%s\\s*[=;]",
            MODIFIERS + "%s\\s*[,)]", "^\\s*%s\\s*(?:\\(|,|;|$)", "\\b(?:register|create)\\(\\s*['\"]%s['\"]");
    // TypeScript: a declaration, then a member of a class or an object.
    private static final List<String> SCRIPT = List.of(
            "\\b(?:function|const|let|var|class|interface|type|enum)\\s+%s\\b",
            "^\\s*(?:(?:readonly|static|private|public|protected|async)\\s+)*%s\\??\\s*[(:=]");

    private GuideAnchors() {
    }

    /**
     * A page with its links re-pointed.
     *
     * @param moved how many links' anchors changed
     * @param unplaced the links whose member AuthTracer couldn't find, which keep no anchor
     */
    record Anchored(String text, int moved, List<String> unplaced) {
    }

    /**
     * Re-points the links of the pages named, or of every page of the guide.
     *
     * @param args Markdown files or directories; none for guide/codebase
     */
    public static void main(String[] args) {
        List<Path> pages = (args.length == 0 ? Stream.of(GUIDE) : Stream.of(args).map(Path::of))
                .flatMap(GuideAnchors::markdown).toList();
        int moved = 0;
        int changed = 0;
        List<String> unplaced = new ArrayList<>();
        for (Path page : pages) {
            String text = read(page);
            Anchored anchored = anchor(page, text);
            if (!anchored.text().equals(text)) {
                write(page, anchored.text());
                changed++;
            }
            moved += anchored.moved();
            anchored.unplaced().forEach(link -> unplaced.add(page + ": " + link));
        }
        System.out.println("Re-pointed " + moved + " links in " + changed + " of " + pages.size() + " pages.");
        if (!unplaced.isEmpty()) {
            System.out.println(unplaced.size() + " links name a member AuthTracer can't find, and keep no anchor:");
            unplaced.forEach(link -> System.out.println("  " + link));
        }
    }

    /**
     * The page with each link to code pointing at the line its class or member is declared on. Links in fenced code
     * blocks are examples, and stay as they are.
     */
    static Anchored anchor(Path page, String text) {
        List<MatchResult> fences = FENCE.matcher(text).results().toList();
        Matcher link = LINK.matcher(text);
        StringBuilder out = new StringBuilder();
        int moved = 0;
        List<String> unplaced = new ArrayList<>();
        while (link.find()) {
            int start = link.start();
            if (fences.stream().anyMatch(fence -> start >= fence.start() && start < fence.end())) {
                continue;
            }
            String target = target(page, link.group(1), link.group(2), unplaced);
            if (!target.equals(link.group(2))) {
                moved++;
            }
            link.appendReplacement(out, Matcher.quoteReplacement("[" + link.group(1) + "](" + target + ")"));
        }
        link.appendTail(out);
        return new Anchored(out.toString(), moved, unplaced);
    }

    /**
     * Where a link should lead: its file at the line of what its text names, or the target as it is.
     */
    private static String target(Path page, String text, String target, List<String> unplaced) {
        String file = LINE_ANCHOR.matcher(target).replaceFirst("");
        if (file.contains("#") || file.matches("[a-z]+:.*")) {
            return target;
        }
        Path resolved = page.toAbsolutePath().getParent().resolve(file).normalize();
        boolean code = text.length() > 2 && text.startsWith("`") && text.endsWith("`");
        if (!code || !Files.isRegularFile(resolved) || resolved.toString().endsWith(".md")) {
            return target;
        }
        String named = text.substring(1, text.length() - 1);
        if (named.endsWith(resolved.getFileName().toString())) {
            return file;
        }
        OptionalInt line = line(resolved, named);
        if (line.isEmpty()) {
            unplaced.add(text + " in " + file);
            return file;
        }
        return file + "#L" + line.getAsInt();
    }

    /**
     * The line (from 1) a file declares what the text names on: each name in turn, after the one before it.
     */
    static OptionalInt line(Path file, String named) {
        List<String> names = new ArrayList<>(IDENTIFIER.matcher(named).results().map(MatchResult::group).toList());
        names.remove("new");
        if (names.isEmpty()) {
            return OptionalInt.empty();
        }
        List<String> lines = read(file).lines().toList();
        List<String> declarations = file.toString().matches(".*\\.(ts|tsx|js|jsx)$") ? SCRIPT : JAVA;
        int found = -1;
        for (int i = 0; i < names.size(); i++) {
            int at = find(lines, Math.max(found, 0), names.get(i), declarations);
            if (at >= 0) {
                found = at;
            } else if (i == names.size() - 1) {
                return OptionalInt.empty();
            }
        }
        return OptionalInt.of(found + 1);
    }

    /**
     * The first line from {@code from} that declares the name, by the most telling kind of declaration that does; else
     * the first that mentions it outside imports and comments.
     */
    private static int find(List<String> lines, int from, String name, List<String> declarations) {
        for (String declaration : declarations) {
            Pattern pattern = Pattern.compile(declaration.formatted(Pattern.quote(name)));
            for (int i = from; i < lines.size(); i++) {
                if (pattern.matcher(lines.get(i)).find()) {
                    return i;
                }
            }
        }
        Pattern mention = Pattern.compile("\\b" + Pattern.quote(name) + "\\b");
        for (int i = from; i < lines.size(); i++) {
            String line = lines.get(i).strip();
            if (!line.startsWith("import ") && !line.startsWith("*") && !line.startsWith("/")
                    && mention.matcher(line).find()) {
                return i;
            }
        }
        return -1;
    }

    private static Stream<Path> markdown(Path path) {
        if (!Files.isDirectory(path)) {
            return Stream.of(path);
        }
        try (Stream<Path> files = Files.walk(path)) {
            return files.filter(file -> file.toString().endsWith(".md")).sorted().toList().stream();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String read(Path file) {
        try {
            return Files.readString(file);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void write(Path file, String text) {
        try {
            Files.writeString(file, text);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
