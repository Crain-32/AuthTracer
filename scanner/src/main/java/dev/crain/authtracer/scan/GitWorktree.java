package dev.crain.authtracer.scan;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A temporary checkout of another revision of a repository, for scanning it next to the working tree.
 */
@Supports({Feature.DIFF, Feature.PROJECT_BUILDS})
public final class GitWorktree implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(GitWorktree.class);

    private final Path repository;
    private final Path directory;
    private final String prefix;

    private GitWorktree(Path repository, Path directory, String prefix) {
        this.repository = repository;
        this.directory = directory;
        this.prefix = prefix;
    }

    /**
     * Checks {@code ref} out (detached) into a new temporary directory.
     *
     * @param project a directory in the repository, its root or a project under it
     */
    public static GitWorktree checkout(Path project, String ref) {
        if (ref.isBlank() || ref.startsWith("-")) {
            // git would read it as an option.
            throw new IllegalArgumentException("Not a git ref: '" + ref + "'");
        }
        Path directory;
        try {
            directory = Files.createTempDirectory("authtracer-" + ref.replaceAll("[^A-Za-z0-9]", "_") + "-");
            Files.delete(directory);
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        // A project in a monorepo is a subdirectory of the checkout, as of the working tree.
        String prefix = git(project, Duration.ofSeconds(30), "rev-parse", "--show-prefix");
        try {
            git(project, Duration.ofMinutes(2), "worktree", "add", "--detach", directory.toString(), ref);
        }
        catch (RuntimeException ex) {
            // A checkout killed partway leaves a locked worktree entry that prune won't remove.
            discard(project, directory);
            throw ex;
        }
        return new GitWorktree(project, directory, prefix);
    }

    /**
     * The checkout's root.
     */
    public Path directory() {
        return directory;
    }

    /**
     * The checkout's copy of the directory it was made from.
     */
    public Path project() {
        return prefix.isEmpty() ? directory : directory.resolve(prefix);
    }

    @Override
    public void close() {
        git(repository, Duration.ofMinutes(2), "worktree", "remove", "--force", directory.toString());
    }

    private static void discard(Path repository, Path directory) {
        try {
            git(repository, Duration.ofSeconds(30), "worktree", "remove", "--force", "--force", directory.toString());
        }
        catch (RuntimeException ignored) {
            // Nothing was registered, or it is gone already.
        }
        try {
            git(repository, Duration.ofSeconds(30), "worktree", "prune");
        }
        catch (RuntimeException ignored) {
            // Best effort: the checkout failed, which is what gets reported.
        }
        if (Files.exists(directory)) {
            try (Stream<Path> files = Files.walk(directory)) {
                files.sorted(Comparator.reverseOrder()).forEach(file -> file.toFile().delete());
            }
            catch (IOException ignored) {
                // Said below.
            }
        }
        if (Files.exists(directory)) {
            log.warn("The failed checkout at {} couldn't be removed; it is left in the temporary directory", directory);
        }
    }

    private static String git(Path repository, Duration timeout, String... args) {
        List<String> command = new ArrayList<>(List.of("git", "-C", repository.toString()));
        command.addAll(List.of(args));
        Processes.Result result = Processes.run(null, timeout, command);
        if (!result.succeeded()) {
            throw new IllegalStateException(String.join(" ", command) + (result.timedOut() ? " timed out:\n"
                    : " failed:\n") + result.output());
        }
        return result.output().trim();
    }
}
