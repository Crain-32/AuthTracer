package dev.crain.authtracer.cli;

import java.util.Map;

import dev.crain.authtracer.AuthTracerApplication;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import org.springframework.boot.Banner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;

/**
 * Command-line entry point: {@code scan}, {@code link}, {@code diff}, {@code exposures}, {@code policies} and
 * {@code identities}. Exits with the command's code (see {@code CliRunner}'s usage text).
 */
@Supports(Feature.COMMAND_LINE)
public final class AuthTracerCli {

    private AuthTracerCli() {
    }

    public static void main(String[] args) {
        System.exit(run(args));
    }

    /**
     * Runs one command in an application context of its own, closed again before it returns.
     *
     * @return the exit code
     */
    static int run(String... args) {
        SpringApplication application = new SpringApplication(AuthTracerApplication.class);
        application.setWebApplicationType(WebApplicationType.NONE);
        application.setBannerMode(Banner.Mode.OFF);
        application.setAdditionalProfiles(CliRunner.PROFILE);
        application.setDefaultProperties(Map.of(
                "spring.devtools.restart.enabled", "false",
                "spring.batch.job.enabled", "false",
                "logging.level.root", "WARN",
                "logging.level.dev.crain.authtracer", "INFO",
                "logging.pattern.console", "%d{HH:mm:ss.SSS} %-5level %logger{0} - %msg%n"));
        try {
            return SpringApplication.exit(application.run(args));
        }
        catch (RuntimeException ex) {
            // Not 1, which reads as a failed check.
            System.err.println("AuthTracer failed to start: " + ex.getMessage());
            return CliRunner.ERROR;
        }
    }
}
