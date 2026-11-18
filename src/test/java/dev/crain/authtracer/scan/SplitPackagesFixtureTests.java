package dev.crain.authtracer.scan;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.provided.ProvidedFacts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

/**
 * Scanned with only some of its packages, a service's other classes are read as libraries: a path that calls into
 * one says so.
 */
@ExtendWith(OutputCaptureExtension.class)
class SplitPackagesFixtureTests {

    @Test
    void aPathIntoTheServicesOwnClassOutsideThePackagesScannedIsWarned(CapturedOutput output) {
        ProjectScans.defaultScanner().scan(new ScanInput("splitpackages", "test",
                FixtureScans.paths("authtracer.fixtures.classes"), FixtureScans.paths("authtracer.fixtures.libraries"),
                List.of(), List.of("fixtures.splitpackages.web."), ProvidedFacts.NONE));

        assertThat(output).contains("a path calls fixtures.splitpackages.service.Accounts#balance(), in a class of the"
                + " service outside the packages scanned ([fixtures.splitpackages.web.])")
                .contains("called 1 of its classes outside the packages scanned");
        // The whole service, scanned: its check is on the path, and nothing is said.
        assertThat(FixtureScans.path(FixtureScans.scan("splitpackages"), "ingress:GET /balance"))
                .contains("location:METHOD:fixtures.splitpackages.service.Accounts#balance():@PreAuthorize");
    }
}
