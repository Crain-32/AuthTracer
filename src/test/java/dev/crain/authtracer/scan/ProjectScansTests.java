package dev.crain.authtracer.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

/**
 * The revision and name a scan records for a project directory, and checkouts of other revisions.
 * <p>
 * Stand-in build wrappers and git hooks here are POSIX shell scripts.
 */
@DisabledOnOs(OS.WINDOWS)
class ProjectScansTests {

    @TempDir
    Path repo;

    @Test
    void aProjectIsAtItsRepositorysCommit() throws IOException {
        commit();
        Files.createDirectories(repo.resolve("service/src"));
        Files.writeString(repo.resolve("service/src/App.java"), "class App {}");
        git("add", "-A");
        git("commit", "-qm", "service");
        String head = git("rev-parse", "--short", "HEAD");

        assertThat(ProjectScans.gitRevision(repo)).isEqualTo(head);
        assertThat(ProjectScans.gitRevision(repo.resolve("service"))).isEqualTo(head);
        // A change elsewhere in the repository, another service of a monorepo, isn't this one's.
        Files.writeString(repo.resolve("README.md"), "changed");
        assertThat(ProjectScans.gitRevision(repo.resolve("service"))).isEqualTo(head);
        assertThat(ProjectScans.gitRevision(repo)).isEqualTo(head + "-dirty");
        Files.writeString(repo.resolve("service/src/App.java"), "class App { int changed; }");
        assertThat(ProjectScans.gitRevision(repo.resolve("service"))).isEqualTo(head + "-dirty");
    }

    @Test
    void aCheckoutOfAProjectInASubdirectoryIsThatSubdirectory() throws IOException {
        commit();
        Files.createDirectories(repo.resolve("services/orders"));
        Files.writeString(repo.resolve("services/orders/build.gradle"), "// orders");
        git("add", "-A");
        git("commit", "-qm", "orders");
        String base = git("rev-parse", "HEAD");
        Files.writeString(repo.resolve("services/orders/build.gradle"), "// orders, changed");

        try (GitWorktree worktree = GitWorktree.checkout(repo.resolve("services/orders"), base)) {
            assertThat(worktree.project()).isEqualTo(worktree.directory().resolve("services/orders"));
            assertThat(Files.readString(worktree.project().resolve("build.gradle"))).isEqualTo("// orders");
        }
    }

    @Test
    void aCheckoutOfTheRepositoryIsItsRootAndIsRemovedWhenClosed() throws IOException {
        commit();
        String base = git("rev-parse", "HEAD");
        Files.writeString(repo.resolve(".gitignore"), "build/\nout/\n");

        Path checkout;
        try (GitWorktree worktree = GitWorktree.checkout(repo, base)) {
            checkout = worktree.directory();
            assertThat(worktree.project()).isEqualTo(checkout);
            assertThat(Files.readString(checkout.resolve(".gitignore"))).isEqualTo("build/\n");
        }
        assertThat(checkout).doesNotExist();
        assertThat(git("worktree", "list", "--porcelain").lines().filter(line -> line.startsWith("worktree ")))
                .hasSize(1);
    }

    @Test
    void aCheckoutThatFailsPartwayIsRemoved() throws IOException {
        commit();
        // The checkout is made, then its post-checkout hook fails: git leaves the worktree registered.
        Path checkedOut = repo.resolve(".git/checked-out");
        Path hook = repo.resolve(".git/hooks/post-checkout");
        Files.createDirectories(hook.getParent());
        Files.writeString(hook, "#!/bin/sh\npwd > '" + checkedOut + "'\nexit 1\n");
        assertThat(hook.toFile().setExecutable(true)).isTrue();
        String head = git("rev-parse", "HEAD");

        assertThatThrownBy(() -> GitWorktree.checkout(repo, head)).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("worktree add").hasMessageContaining(" failed:");
        // git would read it as an option.
        assertThatThrownBy(() -> GitWorktree.checkout(repo, "--orphan=x")).isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Not a git ref: '--orphan=x'");
        assertThat(Path.of(Files.readString(checkedOut).trim())).doesNotExist();
        assertThat(git("worktree", "list", "--porcelain").lines().filter(line -> line.startsWith("worktree ")))
                .hasSize(1);
    }

    @Test
    void aRefThatIsntThereIsGitsError() throws IOException {
        commit();

        assertThatThrownBy(() -> GitWorktree.checkout(repo, "no-such-ref")).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("worktree add").hasMessageContaining("no-such-ref");
        assertThat(git("worktree", "list", "--porcelain").lines().filter(line -> line.startsWith("worktree ")))
                .hasSize(1);
    }

    @Test
    void aStatusGitCantReadIsDirty() throws IOException {
        commit();
        String head = git("rev-parse", "--short", "HEAD");
        // Whether the tree changed is unknown: the revision mustn't claim the commit.
        Files.writeString(repo.resolve(".git/index"), "not an index");

        assertThat(ProjectScans.gitRevision(repo)).isEqualTo(head + "-dirty");
    }

    @Test
    void theRevisionIsTakenBeforeTheBuildWritesItsOutputs() throws IOException {
        commit();
        Path service = Files.createDirectories(repo.resolve("orders"));
        // A build whose outputs git sees, as they aren't ignored.
        executable(service.resolve("gradlew"), """
                #!/bin/sh
                mkdir -p out/classes out/resources
                echo compiled > out/classes/App.class
                echo "AUTHTRACER_CLASSES=$(pwd -P)/out/classes"
                echo "AUTHTRACER_RESOURCES=$(pwd -P)/out/resources"
                """);
        git("add", "-A");
        git("commit", "-qm", "orders");
        String head = git("rev-parse", "--short", "HEAD");

        ScanInput input = ProjectScans.project(service, null, null, List.of());

        assertThat(input.revision()).isEqualTo(head);
        assertThat(ProjectScans.gitRevision(service)).isEqualTo(head + "-dirty");
    }

    @Test
    void aServiceIsNamedByTheOptionElseSpringElseItsDirectory() throws IOException {
        Path service = Files.createDirectories(repo.resolve("Orders"));
        executable(service.resolve("gradlew"), """
                #!/bin/sh
                mkdir -p out/classes out/resources
                [ -f name ] && cp name out/resources/application.properties
                echo "AUTHTRACER_CLASSES=$(pwd -P)/out/classes"
                echo "AUTHTRACER_RESOURCES=$(pwd -P)/out/resources"
                """);

        ScanInput unnamed = ProjectScans.project(service, null, "1.0", List.of("com.example"));
        assertThat(unnamed.service()).isEqualTo("orders");
        assertThat(unnamed.revision()).isEqualTo("1.0");
        assertThat(unnamed.packagePrefixes()).containsExactly("com.example");
        assertThat(unnamed.classDirs()).containsExactly(service.toRealPath().resolve("out/classes"));
        // A temporary checkout is named after the project it was made from.
        assertThat(ProjectScans.project(service, null, "1.0", List.of(), Optional.empty(), "OrderService").service())
                .isEqualTo("orderservice");
        Files.writeString(service.resolve("name"), "spring.application.name=order-service\n");
        assertThat(ProjectScans.project(service, null, "1.0", List.of(), Optional.empty(), "checkout").service())
                .isEqualTo("order-service");
        assertThat(ProjectScans.project(service, "orders-api", "1.0", List.of()).service()).isEqualTo("orders-api");
    }

    @Test
    void aCopyInsideAnotherRepositorysIgnoredFilesIsJustAWorkingTree() throws IOException {
        commit();
        Path copy = Files.createDirectories(repo.resolve("build/experiments/employee-service-copy"));
        Files.writeString(copy.resolve("App.java"), "class App {}");

        assertThat(ProjectScans.gitRevision(copy)).isEqualTo(ProjectScans.WORKING_TREE);
    }

    @Test
    void aDirectoryOutsideAnyRepositoryIsAWorkingTree() {
        assertThat(ProjectScans.gitRevision(repo)).isEqualTo(ProjectScans.WORKING_TREE);
    }

    private void commit() throws IOException {
        git("init", "-q");
        Files.writeString(repo.resolve(".gitignore"), "build/\n");
        git("add", "-A");
        git("commit", "-qm", "base");
    }

    private static void executable(Path file, String script) throws IOException {
        Files.writeString(file, script);
        assertThat(file.toFile().setExecutable(true)).isTrue();
    }

    private String git(String... args) {
        List<String> command = new ArrayList<>(List.of("git", "-C", repo.toString(), "-c", "user.name=test",
                "-c", "user.email=test@localhost", "-c", "commit.gpgsign=false"));
        command.addAll(List.of(args));
        Processes.Result result = Processes.run(null, Duration.ofSeconds(30), command);
        assertThat(result.succeeded()).as("git %s: %s", String.join(" ", args), result.output()).isTrue();
        return result.output().trim();
    }
}
