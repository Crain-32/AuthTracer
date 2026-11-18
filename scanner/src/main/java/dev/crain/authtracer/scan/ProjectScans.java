package dev.crain.authtracer.scan;

import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.provided.ProvidedFacts;
import dev.crain.authtracer.scan.build.BuildClasspath;
import dev.crain.authtracer.scan.build.Builds;
import dev.crain.authtracer.scan.spring.SpringSecurityModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds {@link ScanInput}s for projects on disk and the default scanner.
 */
@Supports(Feature.PROJECT_BUILDS)
public final class ProjectScans {

    private static final Logger log = LoggerFactory.getLogger(ProjectScans.class);

    public static final String WORKING_TREE = "working-tree";

    private ProjectScans() {
    }

    @Supports(Feature.APPLICATION_GRAPH)
    public static ApplicationScanner defaultScanner() {
        return new ApplicationScanner(List.of(new SpringSecurityModule()));
    }

    /**
     * @param service the service name, or {@code null} to use {@code spring.application.name} (else the directory)
     * @param revision the revision label, or {@code null} to use the git commit
     */
    public static ScanInput project(Path projectDir, String service, String revision,
            List<String> packagePrefixes) {
        return project(projectDir, service, revision, packagePrefixes, Optional.empty());
    }

    /**
     * @param orgFacts the organization's Provided facts file; the project's own {@code authtracer.yaml} is read too
     */
    public static ScanInput project(Path projectDir, String service, String revision,
            List<String> packagePrefixes, Optional<Path> orgFacts) {
        return project(projectDir, service, revision, packagePrefixes, orgFacts, null);
    }

    /**
     * @param directoryName the name to fall back on when neither {@code service} nor {@code spring.application.name}
     *        names the service, {@code null} for the directory's: a temporary checkout is named after its project
     */
    public static ScanInput project(Path projectDir, String service, String revision,
            List<String> packagePrefixes, Optional<Path> orgFacts, String directoryName) {
        Path dir = projectDir.toAbsolutePath().normalize();
        // Before the build, whose outputs would make the tree look changed.
        String recorded = revision != null ? revision : gitRevision(dir);
        BuildClasspath classpath = Builds.resolve(dir);
        String name = service != null ? service
                : ConfigurationProperties.load(classpath.resourceDirs()).get("spring.application.name")
                        .orElse((directoryName != null ? directoryName : dir.getFileName().toString())
                                .toLowerCase(Locale.ROOT));
        ProvidedFacts facts = ProvidedFacts.load(Optional.of(dir.resolve(ProvidedFacts.LOCAL_FILE)), orgFacts, name);
        return new ScanInput(name, recorded, classpath.classDirs(), classpath.libraries(), classpath.resourceDirs(),
                packagePrefixes, facts);
    }

    /**
     * The short commit hash, with {@code -dirty} when the directory has uncommitted changes (changes elsewhere in the
     * repository, another service of a monorepo, don't count) or git can't tell; {@link #WORKING_TREE} when the
     * directory has no commits, or is among another repository's ignored files (a copy under its {@code build/}): that
     * repository's commit says nothing about the copy.
     */
    @Supports(Feature.DIFF)
    public static String gitRevision(Path dir) {
        if (git(dir, "check-ignore", "-q", ".") != null) {
            log.info("{} is among its repository's ignored files: its revision is {}", dir, WORKING_TREE);
            return WORKING_TREE;
        }
        String head = git(dir, "rev-parse", "--short", "HEAD");
        if (head == null) {
            log.info("git finds no commit for {} (no repository, no commits, or no git): its revision is {}", dir,
                    WORKING_TREE);
            return WORKING_TREE;
        }
        String status = git(dir, "status", "--porcelain", "--", ".");
        if (status == null) {
            log.warn("git status failed in {}: its revision is {}-dirty, as it can't tell", dir, head);
        }
        return status == null || !status.isBlank() ? head + "-dirty" : head;
    }

    /**
     * Git's output, or {@code null} when it fails or isn't installed.
     */
    private static String git(Path dir, String... args) {
        List<String> command = new ArrayList<>(List.of("git", "-C", dir.toString()));
        command.addAll(List.of(args));
        try {
            Processes.Result result = Processes.run(null, Duration.ofSeconds(30), command);
            return result.succeeded() ? result.output().trim() : null;
        }
        catch (UncheckedIOException ex) {
            log.debug("git couldn't run in {}: {}", dir, ex.getMessage());
            return null;
        }
    }
}
