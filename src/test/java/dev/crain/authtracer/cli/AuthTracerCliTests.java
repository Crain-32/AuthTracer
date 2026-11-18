package dev.crain.authtracer.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

/**
 * The command line as a build runs it: the whole application, started and stopped for each command, and the exit code
 * it ends with (0 ok, 1 failed, 2 usage, 3 error).
 */
@ExtendWith(OutputCaptureExtension.class)
class AuthTracerCliTests {

    @TempDir
    Path dir;

    @Test
    void theExitCodeIsTheCommandsVerdict(CapturedOutput output) {
        Path admin = graph("admin.json", Requirement.anyAuthority(List.of("ROLE_ADMIN")));
        Path open = graph("open.json", Requirement.authenticated());

        assertThat(AuthTracerCli.run("diff", "--base", admin.toString(), "--head", admin.toString()))
                .isEqualTo(CliRunner.OK);
        assertThat(output.getOut()).contains("Result: **Pass**");
        assertThat(AuthTracerCli.run("diff", "--base", admin.toString(), "--head", open.toString()))
                .isEqualTo(CliRunner.FAILED);
        assertThat(output.getOut()).contains("Result: **FAIL** (1 weakened)");
    }

    @Test
    void aCommandItCannotRunIsAUsageErrorOrAnError(CapturedOutput output) {
        assertThat(AuthTracerCli.run("verify")).isEqualTo(CliRunner.USAGE);
        assertThat(output.getOut()).contains("Unknown command 'verify'.").contains("Usage:");
        // A file it reads that isn't there: the command couldn't finish, which says nothing about authorization.
        assertThat(AuthTracerCli.run("exposures", "--graph", dir.resolve("missing.json").toString()))
                .isEqualTo(CliRunner.ERROR);
        assertThat(output.getOut()).contains("Failed: ");
    }

    @Test
    void anApplicationThatCannotStartIsAnErrorNotAVerdict(CapturedOutput output) {
        Path admin = graph("admin.json", Requirement.anyAuthority(List.of("ROLE_ADMIN")));

        assertThat(AuthTracerCli.run("diff", "--base", admin.toString(), "--head", admin.toString(),
                "--authtracer.zipkin.lookback=an-hour")).isEqualTo(CliRunner.ERROR);
        assertThat(output.getErr()).contains("AuthTracer failed to start: ");
        assertThat(output.getOut()).doesNotContain("# AuthTracer diff");
    }

    /**
     * {@code GET /accounts/{id}} behind one method check.
     */
    private Path graph(String name, Requirement requirement) {
        Ingress ingress = Ingress.of("GET", "/accounts/{id}", CodeRef.ofMethod("app.Accounts", "get(long)"));
        AuthorizationLocation check = new AuthorizationLocation("location:METHOD:app.Accounts#get", "@PreAuthorize",
                AuthorizationLocation.Scope.METHOD, AuthorizationLocation.Phase.PRE, requirement,
                CodeRef.ofMethod("app.Accounts", "get(long)"), null, null, AuthorizationLocation.Denial.THROW, true);
        Path file = dir.resolve(name);
        GraphJson.write(new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "bank", name, 8080,
                AuthoritySource.UNKNOWN, List.of(ingress, check),
                List.of(Edge.local(ingress.id(), ingress.id(), check.id(), 1, List.of())), List.of(), List.of(),
                List.of()), file);
        return file;
    }
}
