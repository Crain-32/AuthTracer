package dev.crain.authtracer.scan;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.provided.ProvidedFacts;
import org.junit.jupiter.api.Test;

/**
 * Which classes a scan's {@code --packages} take in.
 */
class ScanInputTests {

    @Test
    void aPackageTakesInItsSubpackagesButNotItsNamesakes() {
        ScanInput input = input(List.of("dev.a", "com.example."));

        assertThat(input.includes("dev.a.X")).isTrue();
        assertThat(input.includes("dev.a.b.Y")).isTrue();
        assertThat(input.includes("dev.ab.Z")).isFalse();
        assertThat(input.includes("com.example.App")).isTrue();
        assertThat(input.includes("com.examples.App")).isFalse();
    }

    @Test
    void noPackagesTakeInEveryClass() {
        assertThat(input(List.of()).includes("anything.At.All")).isTrue();
    }

    private static ScanInput input(List<String> packages) {
        return new ScanInput("orders", "1", List.of(), List.of(), List.of(), packages, ProvidedFacts.NONE);
    }
}
