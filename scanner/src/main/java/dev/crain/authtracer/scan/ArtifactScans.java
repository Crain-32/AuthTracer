package dev.crain.authtracer.scan;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

import dev.crain.authtracer.UsageException;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.provided.ProvidedFacts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds {@link ScanInput}s for built artifacts: a Spring Boot jar ({@code BOOT-INF/classes}, {@code BOOT-INF/lib})
 * or a war ({@code WEB-INF/classes}, {@code WEB-INF/lib} and {@code lib-provided}, its root the web app's resources),
 * unpacked into a work directory the way a project scan finds them in a build's outputs. Nothing in the artifact is run
 * or loaded: it is only read, and unpacked no further than the work directory and the {@link Limits}.
 */
@Supports(Feature.BUILT_ARTIFACTS)
public final class ArtifactScans {

    private static final Logger log = LoggerFactory.getLogger(ArtifactScans.class);

    public static final String UNVERSIONED = "unversioned";

    /** The version a build tool appends to the artifact's name: {@code -0.0.1-SNAPSHOT}, {@code -2.3}. */
    private static final Pattern VERSION_SUFFIX = Pattern.compile("-\\d[\\w.+-]*$");
    /** A line of a Boot jar's {@code classpath.idx}: {@code - "BOOT-INF/lib/a.jar"}. */
    private static final Pattern INDEXED = Pattern.compile("^- \"(.+)\"$");
    /** An executable war's launcher, at its root: Spring Boot's, not the application's. */
    private static final String BOOT_LOADER = "org/springframework/boot/loader/";

    /**
     * How much of an archive is unpacked before it is refused: a zip's entries can claim far more than it holds.
     */
    public record Limits(long entries, long bytes) {

        public static final Limits DEFAULT = new Limits(200_000, 4L * 1024 * 1024 * 1024);
    }

    /**
     * Where an archive keeps the application's classes and its libraries.
     */
    enum Layout {

        BOOT_JAR("BOOT-INF/classes/", List.of("BOOT-INF/lib/")),
        WAR("WEB-INF/classes/", List.of("WEB-INF/lib/", "WEB-INF/lib-provided/"));

        private final String classes;
        private final List<String> libraries;

        Layout(String classes, List<String> libraries) {
            this.classes = classes;
            this.libraries = libraries;
        }

        /**
         * The directory a library entry is directly in, or empty when it isn't a library: nested deeper, or not a jar.
         */
        Optional<String> library(String entry) {
            return libraries.stream().filter(dir -> entry.startsWith(dir) && entry.endsWith(".jar")
                    && entry.indexOf('/', dir.length()) < 0).findFirst();
        }
    }

    private ArtifactScans() {
    }

    /**
     * Whether the file is an archive {@link #artifact} can scan: a Boot jar or a war, not a plain jar (a Gradle build's
     * {@code -plain.jar} next to its Boot jar) that has no libraries in it to resolve the framework's types with.
     */
    public static boolean scannable(Path archive) {
        try (ZipFile zip = new ZipFile(archive.toFile())) {
            return layout(zip).isPresent();
        }
        catch (IOException ex) {
            return false;
        }
    }

    public static ScanInput artifact(Path archive, Path workDir, String service, String revision,
            List<String> packagePrefixes, Optional<Path> localFacts, Optional<Path> orgFacts) {
        return artifact(archive, workDir, service, revision, packagePrefixes, localFacts, orgFacts, Limits.DEFAULT);
    }

    /**
     * Unpacks the artifact into the work directory (which the caller deletes once the scan is done) and describes it.
     *
     * @param service the service name, or {@code null} to use {@code spring.application.name}, else the manifest's
     *        {@code Implementation-Title}, else the artifact's name without its version
     * @param revision the revision label, or {@code null} to use the commit {@code git.properties} records, else the
     *        version {@code build-info.properties} or the manifest records, else {@link #UNVERSIONED}
     * @param localFacts the service's own Provided facts file, which isn't in the artifact
     */
    public static ScanInput artifact(Path archive, Path workDir, String service, String revision,
            List<String> packagePrefixes, Optional<Path> localFacts, Optional<Path> orgFacts, Limits limits) {
        try (ZipFile zip = open(archive)) {
            Layout layout = layout(zip).orElseThrow(() -> new UsageException(archive.getFileName()
                    + " is neither a Spring Boot jar (BOOT-INF/classes) nor a war (WEB-INF/classes): scan the jar"
                    + " Spring Boot's bootJar task or repackage goal builds, not the plain one."));
            Path classes = Files.createDirectories(workDir.resolve("classes"));
            Path webapp = workDir.resolve("webapp");
            List<Path> jars = unpack(zip, layout, workDir, classes, webapp, limits);
            Manifest manifest = manifest(zip);
            List<Path> resources = Files.isDirectory(webapp) ? List.of(classes, webapp) : List.of(classes);
            String name = service != null ? service
                    : ConfigurationProperties.load(resources).get("spring.application.name")
                            .or(() -> attribute(manifest, Attributes.Name.IMPLEMENTATION_TITLE))
                            .orElseGet(() -> named(archive));
            String recorded = revision != null ? revision : revision(classes, manifest);
            ProvidedFacts facts = ProvidedFacts.load(localFacts, orgFacts, name);
            return new ScanInput(name, recorded, List.of(classes), ordered(zip, jars, workDir), resources,
                    packagePrefixes, facts);
        }
        catch (IOException ex) {
            throw new UncheckedIOException("Can't unpack " + archive + ": " + ex.getMessage(), ex);
        }
    }

    private static ZipFile open(Path archive) throws IOException {
        try {
            return new ZipFile(archive.toFile());
        }
        catch (ZipException ex) {
            throw new UsageException(archive.getFileName() + " isn't a jar or war: " + ex.getMessage());
        }
    }

    private static Optional<Layout> layout(ZipFile zip) {
        for (Layout layout : Layout.values()) {
            String root = layout.classes.substring(0, layout.classes.indexOf('/') + 1);
            if (zip.stream().anyMatch(entry -> entry.getName().startsWith(root))) {
                return Optional.of(layout);
            }
        }
        return Optional.empty();
    }

    /**
     * Writes the classes (with the resources beside them), the libraries (at their path in the archive, so a war's
     * {@code lib} and {@code lib-provided} can hold jars of the same name) and, for a war, the web app's own files,
     * leaving out the Boot loader and everything else at a Boot jar's root.
     *
     * @return the libraries unpacked, in the archive's order
     */
    private static List<Path> unpack(ZipFile zip, Layout layout, Path workDir, Path classes, Path webapp,
            Limits limits) throws IOException {
        if (zip.size() > limits.entries()) {
            throw new IllegalArgumentException(Path.of(zip.getName()).getFileName() + " has " + zip.size()
                    + " entries, more than the " + limits.entries() + " the scan unpacks.");
        }
        List<Path> jars = new ArrayList<>();
        long[] written = {0};
        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String name = entry.getName();
            if (entry.isDirectory()) {
                continue;
            }
            Optional<String> library = layout.library(name);
            Path target;
            if (name.startsWith(layout.classes)) {
                target = inside(classes, name.substring(layout.classes.length()), name);
            }
            else if (library.isPresent()) {
                target = inside(workDir, name, name);
                jars.add(target);
            }
            else if (layout == Layout.WAR && !name.startsWith("WEB-INF/lib") && !name.startsWith(BOOT_LOADER)) {
                target = inside(webapp, name, name);
            }
            else {
                continue;
            }
            Files.createDirectories(target.getParent());
            try (InputStream in = zip.getInputStream(entry); OutputStream out = Files.newOutputStream(target)) {
                copy(in, out, written, limits, zip);
            }
        }
        return jars;
    }

    /**
     * The entry's file under the directory, refusing a name that would land outside it ({@code ../}, an absolute
     * path): a crafted archive must not write anywhere else.
     */
    private static Path inside(Path dir, String relative, String entry) {
        // Both normalized: a work directory given as a/./b or a/../b compares as itself.
        Path base = dir.normalize();
        Path target = base.resolve(relative).normalize();
        if (relative.isEmpty() || relative.startsWith("/") || relative.contains("\\") || !target.startsWith(base)
                || target.equals(base)) {
            throw new IllegalArgumentException("The archive's entry " + entry + " would be unpacked outside "
                    + dir.getFileName() + "/, so the archive isn't scanned.");
        }
        return target;
    }

    private static void copy(InputStream in, OutputStream out, long[] written, Limits limits, ZipFile zip)
            throws IOException {
        byte[] buffer = new byte[64 * 1024];
        for (int read = in.read(buffer); read >= 0; read = in.read(buffer)) {
            written[0] += read;
            if (written[0] > limits.bytes()) {
                long megabytes = limits.bytes() / (1024 * 1024);
                throw new IllegalArgumentException(Path.of(zip.getName()).getFileName() + " unpacks to more than "
                        + (megabytes > 0 ? megabytes + " MB" : limits.bytes() + " bytes") + ", the most the scan"
                        + " unpacks.");
            }
            out.write(buffer, 0, read);
        }
    }

    /**
     * The libraries in the order a Boot jar's {@code classpath.idx} runs them with (the archive's order without one,
     * or for a library it doesn't list), so a class two of them have resolves to the same one as at runtime.
     */
    private static List<Path> ordered(ZipFile zip, List<Path> jars, Path workDir) throws IOException {
        ZipEntry index = zip.getEntry("BOOT-INF/classpath.idx");
        if (index == null) {
            return jars;
        }
        Set<Path> ordered = new LinkedHashSet<>();
        try (InputStream in = zip.getInputStream(index)) {
            for (String line : new String(in.readNBytes(1024 * 1024), StandardCharsets.UTF_8).lines().toList()) {
                Matcher indexed = INDEXED.matcher(line.strip());
                if (indexed.matches()) {
                    Path jar = workDir.resolve(indexed.group(1)).normalize();
                    if (jars.contains(jar)) {
                        ordered.add(jar);
                    }
                }
            }
        }
        List<Path> unindexed = jars.stream().filter(jar -> !ordered.contains(jar)).toList();
        if (!unindexed.isEmpty()) {
            // Where the index doesn't place a jar, which of two classes of one name wins may differ from the app's.
            log.warn("{} of the jars in BOOT-INF/lib aren't in classpath.idx ({}); they are read after the others",
                    unindexed.size(), unindexed.stream().map(Path::getFileName).toList());
        }
        ordered.addAll(jars);
        return List.copyOf(ordered);
    }

    private static Manifest manifest(ZipFile zip) throws IOException {
        ZipEntry entry = zip.getEntry("META-INF/MANIFEST.MF");
        if (entry == null) {
            return new Manifest();
        }
        try (InputStream in = zip.getInputStream(entry)) {
            return new Manifest(in);
        }
    }

    private static Optional<String> attribute(Manifest manifest, Attributes.Name name) {
        return Optional.ofNullable(manifest.getMainAttributes().getValue(name)).map(String::strip)
                .filter(value -> !value.isEmpty());
    }

    /**
     * The artifact's name without its extension, version or classifier: {@code employee-service-0.0.1-SNAPSHOT.jar}
     * is {@code employee-service}.
     */
    static String named(Path archive) {
        String file = archive.getFileName().toString();
        String base = file.contains(".") ? file.substring(0, file.lastIndexOf('.')) : file;
        String name = VERSION_SUFFIX.matcher(base).replaceFirst("");
        return (name.isEmpty() ? base : name).toLowerCase(Locale.ROOT);
    }

    /**
     * The commit the build recorded (the git-commit-id plugins' {@code git.properties}), else its version.
     */
    private static String revision(Path classes, Manifest manifest) {
        return property(classes.resolve("git.properties"), "git.commit.id.abbrev")
                .or(() -> property(classes.resolve("META-INF/build-info.properties"), "build.version"))
                .or(() -> attribute(manifest, Attributes.Name.IMPLEMENTATION_VERSION))
                .orElse(UNVERSIONED);
    }

    private static Optional<String> property(Path file, String key) {
        if (!Files.isRegularFile(file)) {
            return Optional.empty();
        }
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(file)) {
            properties.load(in);
        }
        catch (IOException | IllegalArgumentException ex) {
            log.warn("Couldn't read {}, so its {} isn't known: {}", file.getFileName(), key, ex.toString());
            return Optional.empty();
        }
        return Optional.ofNullable(properties.getProperty(key)).map(String::strip).filter(value -> !value.isEmpty());
    }
}
