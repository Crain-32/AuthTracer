package dev.crain.authtracer.guide;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import org.junit.jupiter.api.Test;

/**
 * The codebase guide (guide/codebase) stays true to the code: every class and UI file says which features it supports,
 * the feature index lists what they say, every feature is described on a page, and every link leads to code that is
 * there. {@code ./gradlew test --tests '*CodebaseGuideTests' -PupdateGuide=true} rewrites the index after a change.
 * The links' line anchors are {@link GuideAnchors}', refreshed on demand: a test that wanted them current would fail
 * on nearly every commit.
 */
class CodebaseGuideTests {

    private static final Path GUIDE = Path.of("guide/codebase");
    private static final Path INDEX = GUIDE.resolve("features.md");
    /**
     * The main code of the projects whose classes say which features they support: the server's and the scanner's.
     */
    private static final List<Path> SOURCES = List.of(Path.of("src/main/java"), Path.of("scanner/src/main/java"),
            Path.of("scanner-image/src/main/java"));
    private static final Path UI = Path.of("frontend/src");
    private static final String UPDATE = "./gradlew test --tests '*CodebaseGuideTests' -PupdateGuide=true";

    private static final Pattern UI_TAG = Pattern.compile("// @supports (.+)");
    private static final Pattern LINK = GuideAnchors.LINK;
    private static final Pattern HEADING = Pattern.compile("(#{1,6}) (.+)");
    private static final Pattern FEATURE_LINE = Pattern.compile("\\**Features?:\\**.*");
    private static final Pattern FEATURE_LINK = Pattern.compile("\\[`([A-Z_]+)`]\\(features\\.md#[a-z_]+\\)");
    private static final Pattern FENCE = GuideAnchors.FENCE;
    private static final Pattern IDENTIFIER = GuideAnchors.IDENTIFIER;
    private static final Pattern ANCHORS = Pattern.compile("#L\\d+\\)");

    /**
     * Code that says which features it supports.
     *
     * @param group the package or UI folder it is in, as the index groups it
     * @param name the class, member or file, as people read it
     */
    private record Tagged(String group, String name, Path file, Set<Feature> features) {
    }

    /**
     * Where a page of the guide describes a feature: the heading of the section it is named in.
     */
    private record Section(Path page, String heading, String anchor) {
    }

    @Test
    void everyClassSaysWhichFeaturesItSupports() {
        assertThat(javaSources().stream().map(CodebaseGuideTests::load)
                .filter(type -> !type.isAnnotationPresent(Supports.class)).map(Class::getName))
                .as("Say which features each class is needed for, with @Supports").isEmpty();
    }

    @Test
    void everyUiFileSaysWhichFeaturesItSupports() {
        List<String> untagged = new ArrayList<>();
        for (Path file : uiSources()) {
            Matcher tag = UI_TAG.matcher(read(file).lines().findFirst().orElse(""));
            if (!tag.matches()) {
                untagged.add(file + ": no first line // @supports FEATURE, ...");
                continue;
            }
            for (String name : tag.group(1).split(",\\s*")) {
                if (Arrays.stream(Feature.values()).noneMatch(feature -> feature.name().equals(name.trim()))) {
                    untagged.add(file + ": no feature " + name);
                }
            }
        }
        assertThat(untagged).isEmpty();
    }

    @Test
    void everyFeatureHasCodeThatSupportsIt() {
        EnumSet<Feature> supported = EnumSet.noneOf(Feature.class);
        tagged().forEach(code -> supported.addAll(code.features()));
        assertThat(EnumSet.complementOf(supported))
                .as("Features no code supports: tag the code, or take the feature out of the catalogue").isEmpty();
    }

    @Test
    void everyFeatureIsDescribedOnAPageOfTheGuide() {
        EnumSet<Feature> described = EnumSet.noneOf(Feature.class);
        described.addAll(sections().keySet());
        assertThat(EnumSet.complementOf(described))
                .as("Features no page names in a 'Feature: [`NAME`](features.md#name)' line").isEmpty();
    }

    @Test
    void theFeatureIndexListsWhatTheCodeSays() throws IOException {
        String index = index();
        if (Boolean.getBoolean("authtracer.updateGuide")) {
            Files.writeString(INDEX, GuideAnchors.anchor(INDEX, index).text());
        }
        // The anchors move with the code between refreshes; what the index lists doesn't.
        assertThat(Files.exists(INDEX) && withoutAnchors(Files.readString(INDEX)).equals(index))
                .as(INDEX + " is out of date: rewrite it with " + UPDATE).isTrue();
    }

    @Test
    void everyLinkInTheGuideLeadsToCodeThatIsThere() {
        List<String> broken = new ArrayList<>();
        for (Path page : sources(GUIDE, ".md")) {
            String[] lines = prose(read(page)).split("\n", -1);
            for (int number = 0; number < lines.length; number++) {
                Matcher link = LINK.matcher(lines[number]);
                while (link.find()) {
                    String problem = problem(page, link.group(1), link.group(2));
                    if (problem != null) {
                        broken.add(page + ":" + (number + 1) + ": " + link.group(2) + " " + problem);
                    }
                }
            }
        }
        assertThat(broken).isEmpty();
    }

    private static String withoutAnchors(String page) {
        return ANCHORS.matcher(page).replaceAll(")");
    }

    /**
     * What is wrong with a link, or {@code null}: its file must be there, a page's anchor must be one of its headings,
     * a source file's a line, and the member its text names last must be in the file.
     */
    private static String problem(Path page, String text, String target) {
        if (target.matches("[a-z]+:.*")) {
            return null;
        }
        int hash = target.indexOf('#');
        String file = hash < 0 ? target : target.substring(0, hash);
        Path resolved = file.isEmpty() ? page : page.getParent().resolve(file).normalize();
        if (!Files.exists(resolved)) {
            return "doesn't exist";
        }
        boolean toPage = resolved.toString().endsWith(".md");
        if (hash >= 0 && !toPage && !target.substring(hash).matches("#L\\d+")) {
            return "has an anchor other than a line's (#L12), which scripts/guide-anchors.sh sets";
        }
        if (hash >= 0 && toPage && !anchors(resolved).contains(target.substring(hash + 1))) {
            return "names no heading of " + resolved.getFileName();
        }
        String code = text.startsWith("`") && text.endsWith("`") ? text.substring(1, text.length() - 1) : null;
        if (code == null || !Files.isRegularFile(resolved) || toPage) {
            return null;
        }
        String fileName = resolved.getFileName().toString();
        String baseName = fileName.contains(".") ? fileName.substring(0, fileName.indexOf('.')) : fileName;
        List<String> identifiers = IDENTIFIER.matcher(code).results().map(MatchResult::group).toList();
        if (code.endsWith(fileName) || identifiers.isEmpty() || identifiers.getLast().equals(baseName)) {
            return null;
        }
        String member = identifiers.getLast();
        return Pattern.compile("\\b" + Pattern.quote(member) + "\\b").matcher(read(resolved)).find() ? null
                : "has no " + member;
    }

    /**
     * The feature index, guide/codebase/features.md, as the code's annotations and the guide's pages say it.
     */
    private static String index() {
        List<Tagged> code = tagged();
        Map<Feature, List<Section>> described = sections();
        Map<Feature, List<Feature>> reliedOnBy = new HashMap<>();
        for (Feature feature : Feature.values()) {
            feature.requires().forEach(required -> reliedOnBy.computeIfAbsent(required, key -> new ArrayList<>())
                    .add(feature));
        }
        StringBuilder index = new StringBuilder("""
                # Feature index

                Generated from the `@Supports` annotations in the code and the `// @supports` lines in the UI by
                `CodebaseGuideTests`, so don't edit it by hand: after changing them, rewrite it with
                `%s`. The links' line anchors are refreshed with `scripts/guide-anchors.sh`.

                A feature is anything of value in AuthTracer's response. The catalogue is
                [`Feature`](../../annotations/src/main/java/dev/crain/authtracer/annotations/Feature.java): each
                feature relies on others, and the code it needs is its own and theirs. The [overview](README.md)
                explains how to read and extend it.

                | Area | Features |
                |---|---|
                """.formatted(UPDATE));
        for (Feature.Area area : Feature.Area.values()) {
            index.append("| [").append(area.title()).append("](#").append(slug(area.title())).append(") | ")
                    .append(Arrays.stream(Feature.values()).filter(feature -> feature.area() == area)
                            .map(CodebaseGuideTests::reference).collect(Collectors.joining(", ")))
                    .append(" |\n");
        }
        index.append(dependencies());
        for (Feature.Area area : Feature.Area.values()) {
            index.append("\n## ").append(area.title()).append('\n');
            for (Feature feature : Feature.values()) {
                if (feature.area() != area) {
                    continue;
                }
                index.append("\n### ").append(feature.name()).append("\n\n").append(feature.summary()).append(".\n\n");
                index.append("- **Described in:** ").append(described.getOrDefault(feature, List.of()).stream()
                        .map(section -> "[" + section.page().getFileName() + ": " + section.heading() + "]("
                                + section.page().getFileName() + "#" + section.anchor() + ")")
                        .collect(Collectors.joining(", "))).append('\n');
                index.append("- **Relies on:** ").append(references(feature.requires())).append('\n');
                index.append("- **Relied on by:** ").append(references(reliedOnBy.getOrDefault(feature, List.of())))
                        .append('\n');
                index.append("- **Code:**\n");
                Map<String, List<Tagged>> groups = new TreeMap<>();
                code.stream().filter(tagged -> tagged.features().contains(feature))
                        .forEach(tagged -> groups.computeIfAbsent(tagged.group(), key -> new ArrayList<>())
                                .add(tagged));
                groups.forEach((group, members) -> index.append("  - ").append(group).append(": ")
                        .append(members.stream().map(tagged -> "[`" + tagged.name() + "`](../../"
                                + tagged.file().toString().replace('\\', '/') + ")").sorted().distinct()
                                .collect(Collectors.joining(", "))).append('\n'));
            }
        }
        return index.toString();
    }

    /**
     * How the features depend on each other, as a Mermaid diagram: each arrow runs from a feature to one that relies on
     * it. Findings and delivery are left out to keep it readable; their sections say what they rely on.
     */
    private static String dependencies() {
        Set<Feature.Area> shown = EnumSet.complementOf(EnumSet.of(Feature.Area.FINDINGS, Feature.Area.DELIVERY));
        StringBuilder diagram = new StringBuilder("""

                ## How the features depend on each other

                Each arrow runs from a feature to one that relies on it. Findings and delivery are left out to keep it
                readable: their sections below say what each relies on.

                ```mermaid
                flowchart LR
                """);
        for (Feature.Area area : shown) {
            diagram.append("  subgraph area_").append(area.name()).append("[\"").append(area.title()).append("\"]\n");
            Arrays.stream(Feature.values()).filter(feature -> feature.area() == area)
                    .forEach(feature -> diagram.append("    ").append(feature.name()).append('\n'));
            diagram.append("  end\n");
        }
        for (Feature feature : Feature.values()) {
            if (shown.contains(feature.area())) {
                feature.requires().forEach(required -> diagram.append("  ").append(required.name()).append(" --> ")
                        .append(feature.name()).append('\n'));
            }
        }
        return diagram.append("```\n").toString();
    }

    private static String reference(Feature feature) {
        return "[" + feature.name() + "](#" + slug(feature.name()) + ")";
    }

    private static String references(List<Feature> features) {
        return features.isEmpty() ? "nothing else" : features.stream().map(CodebaseGuideTests::reference)
                .collect(Collectors.joining(", "));
    }

    /**
     * Every class, nested class, method and UI file that says which features it supports.
     */
    private static List<Tagged> tagged() {
        List<Tagged> tagged = new ArrayList<>();
        for (Path file : javaSources()) {
            Path folder = root(file).relativize(file).getParent();
            String group = "`" + folder.toString().replace('\\', '/')
                    .replaceFirst("^dev/crain/authtracer/?", "") + "/`";
            collect(load(file), group.equals("`/`") ? "`dev.crain.authtracer`" : group, file, tagged);
        }
        for (Path file : uiSources()) {
            Matcher tag = UI_TAG.matcher(read(file).lines().findFirst().orElse(""));
            if (tag.matches()) {
                Path folder = UI.relativize(file).getParent();
                tagged.add(new Tagged("UI `" + (folder == null ? "" : folder.toString().replace('\\', '/') + "/") + "`",
                        file.getFileName().toString(), file, Arrays.stream(tag.group(1).split(",\\s*"))
                                .map(String::trim).map(Feature::valueOf).collect(Collectors.toSet())));
            }
        }
        return tagged;
    }

    private static void collect(Class<?> type, String group, Path file, List<Tagged> tagged) {
        String name = type.getName().substring(type.getPackageName().length() + 1).replace('$', '.');
        Supports own = type.getAnnotation(Supports.class);
        if (own != null) {
            tagged.add(new Tagged(group, name, file, Set.of(own.value())));
        }
        for (Executable member : Stream.concat(Arrays.stream(type.getDeclaredConstructors()),
                Arrays.stream(type.getDeclaredMethods())).toList()) {
            Supports supports = member.getAnnotation(Supports.class);
            if (supports != null && !member.isSynthetic()) {
                String shown = member instanceof Constructor<?> ? "new " + name : name + "." + member.getName();
                tagged.add(new Tagged(group, shown, file, Set.of(supports.value())));
            }
        }
        for (Class<?> nested : type.getDeclaredClasses()) {
            collect(nested, group, file, tagged);
        }
    }

    /**
     * Each feature the pages name in a {@code Feature:} line, with the section it is named in.
     */
    private static Map<Feature, List<Section>> sections() {
        Map<Feature, List<Section>> sections = new LinkedHashMap<>();
        for (Path page : sources(GUIDE, ".md")) {
            if (page.equals(INDEX)) {
                continue;
            }
            String heading = null;
            String anchor = null;
            Map<String, Integer> seen = new HashMap<>();
            for (String line : prose(read(page)).split("\n")) {
                Matcher title = HEADING.matcher(line);
                if (title.matches()) {
                    heading = title.group(2).replace("`", "");
                    anchor = unique(slug(title.group(2)), seen);
                } else if (heading != null && FEATURE_LINE.matcher(line).matches()) {
                    Matcher link = FEATURE_LINK.matcher(line);
                    while (link.find()) {
                        sections.computeIfAbsent(Feature.valueOf(link.group(1)), key -> new ArrayList<>())
                                .add(new Section(page, heading, anchor));
                    }
                }
            }
        }
        return sections;
    }

    /**
     * The anchors of a page's headings, as GitHub makes them.
     */
    private static Set<String> anchors(Path page) {
        Set<String> anchors = new LinkedHashSet<>();
        Map<String, Integer> seen = new HashMap<>();
        for (String line : prose(read(page)).split("\n")) {
            Matcher title = HEADING.matcher(line);
            if (title.matches()) {
                anchors.add(unique(slug(title.group(2)), seen));
            }
        }
        return anchors;
    }

    private static String slug(String heading) {
        return heading.toLowerCase(Locale.ROOT).replaceAll("[^\\p{L}\\p{N} _-]", "").replace(' ', '-');
    }

    /**
     * A heading's anchor among the page's others: GitHub numbers the repeats.
     */
    private static String unique(String slug, Map<String, Integer> seen) {
        int count = seen.merge(slug, 1, Integer::sum);
        return count == 1 ? slug : slug + "-" + (count - 1);
    }

    /**
     * A page without its fenced code blocks, which hold examples rather than links and headings; their lines stay, so
     * line numbers still match.
     */
    private static String prose(String page) {
        return FENCE.matcher(page).replaceAll(block -> Matcher.quoteReplacement(block.group().replaceAll("[^\n]", "")));
    }

    private static Class<?> load(Path source) {
        String name = root(source).relativize(source).toString().replace('\\', '/').replace('/', '.')
                .replaceFirst("\\.java$", "");
        try {
            return Class.forName(name, false, CodebaseGuideTests.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(name + " isn't compiled", e);
        }
    }

    private static List<Path> javaSources() {
        return SOURCES.stream().flatMap(root -> sources(root, ".java").stream()).toList();
    }

    /**
     * The source root a file is under, which its package is relative to.
     */
    private static Path root(Path source) {
        return SOURCES.stream().filter(source::startsWith).findFirst().orElseThrow();
    }

    private static List<Path> uiSources() {
        return Stream.concat(sources(UI, ".ts").stream(), sources(UI, ".tsx").stream())
                .filter(file -> !file.startsWith(UI.resolve("test"))
                        && !file.getFileName().toString().contains(".test."))
                .sorted().toList();
    }

    private static List<Path> sources(Path root, String extension) {
        try (Stream<Path> files = Files.walk(root)) {
            return files.filter(file -> file.toString().endsWith(extension)).sorted().toList();
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
}
