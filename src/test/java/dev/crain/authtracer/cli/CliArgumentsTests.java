package dev.crain.authtracer.cli;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.entry;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CliArgumentsTests {

    @Test
    void parsesSpaceAndEqualsSeparatedOptions() {
        CliArguments args = CliArguments.parse(
                new String[] { "scan", "--project", "../employee-service", "--out=build/b.json", "--packages", "a.b, c" });
        assertThat(args.command()).isEqualTo("scan");
        assertThat(args.required("project")).isEqualTo("../employee-service");
        assertThat(args.required("out")).isEqualTo("build/b.json");
        assertThat(args.list("packages")).containsExactly("a.b", "c");
        assertThat(args.option("service")).isEmpty();
    }

    @Test
    void reportsMissingAndUnexpectedArguments() {
        assertThatIllegalArgumentException().isThrownBy(() -> CliArguments.parse(new String[] { "scan" })
                .required("out")).withMessage("Missing --out");
        assertThatIllegalArgumentException().isThrownBy(() -> CliArguments.parse(new String[] { "scan", "stray" }))
                .withMessage("Unexpected argument: stray");
    }

    @Test
    void aFlagWithoutAValueIsTrue() {
        CliArguments args = CliArguments.parse(new String[] { "diff", "--fail-on-review", "--base", "a.json",
                "--fail-on-unneeded" });

        assertThat(args.options()).containsExactly(entry("fail-on-review", "true"), entry("base", "a.json"),
                entry("fail-on-unneeded", "true"));
    }

    @Test
    void withoutACommandEveryArgumentIsAnOption() {
        CliArguments args = CliArguments.parse(new String[] { "--base", "a.json" });

        assertThat(args.command()).isEmpty();
        assertThat(args.required("base")).isEqualTo("a.json");
        assertThat(CliArguments.parse(new String[0]).command()).isEmpty();
    }

    @Test
    void aNumberOptionTakesAWholeNumber() {
        CliArguments args = CliArguments.parse(new String[] { "link", "--lookback", "5", "--limit", "an-hour" });

        assertThat(args.number("lookback")).contains(5L);
        assertThat(args.number("timeout")).isEmpty();
        assertThatIllegalArgumentException().isThrownBy(() -> args.number("limit"))
                .withMessage("--limit takes a whole number, got: an-hour");
    }

    @Test
    void aListLeavesOutEmptyEntries() {
        assertThat(CliArguments.parse(new String[] { "scan", "--packages", "a.b,, c ,," }).list("packages"))
                .containsExactly("a.b", "c");
        assertThat(CliArguments.parse(new String[] { "scan" }).list("packages")).isEmpty();
    }

    @Test
    void aFileOptionMustNameAFile(@TempDir Path dir) throws IOException {
        Path facts = Files.writeString(dir.resolve("org.yaml"), "version: 1\n");
        CliArguments args = CliArguments.parse(new String[] { "scan", "--org-facts", facts.toString(), "--facts",
                dir.resolve("typo.yaml").toString() });

        assertThat(args.file("org-facts")).contains(facts);
        assertThat(args.file("project")).isEmpty();
        assertThatIllegalArgumentException().isThrownBy(() -> args.file("facts"))
                .withMessageStartingWith("--facts: no such file: ");
    }
}
