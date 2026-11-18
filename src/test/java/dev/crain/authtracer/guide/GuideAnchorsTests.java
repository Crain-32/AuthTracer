package dev.crain.authtracer.guide;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * Where {@link GuideAnchors} points a link: at the line the class or member its text names is declared on.
 */
class GuideAnchorsTests {

    private static final Path PAGE = Path.of("guide/codebase/page.md");
    private static final String GRAPH = "../../scanner/src/main/java/dev/crain/authtracer/graph/";
    private static final String SPRING = "../../scanner/src/main/java/dev/crain/authtracer/scan/spring/";
    private static final Pattern ANCHOR = Pattern.compile("\\(([^)#]+)#L(\\d+)\\)");

    @Test
    void aLinkPointsAtTheLineItsMemberIsDeclaredOn() throws IOException {
        assertThat(declared("[`Edge.local`](" + GRAPH + "Edge.java)")).contains("static Edge local(");
        assertThat(declared("[`Egress.UNKNOWN_TARGET`](" + GRAPH + "Egress.java)"))
                .contains("String UNKNOWN_TARGET =");
        assertThat(declared("[`Finding.Kind`](" + GRAPH + "Finding.java)")).contains("enum Kind");
    }

    @Test
    void aRecordComponentIsFoundInTheRecordsHeader() throws IOException {
        assertThat(declared("[`AuthorizationLocation.proxied`](" + GRAPH + "AuthorizationLocation.java)"))
                .contains("boolean proxied,");
    }

    @Test
    void aGradleTaskIsFoundWhereItIsRegistered() throws IOException {
        assertThat(declared("[`authtracer`](../../build.gradle)")).contains("tasks.register('authtracer',");
    }

    @Test
    void aLinkToAClassPointsAtItsDeclarationPastTheImports() throws IOException {
        assertThat(declared("[`Edge`](" + GRAPH + "Edge.java)")).contains("record Edge(");
    }

    @Test
    void eachNameIsFoundInsideTheOneBeforeIt() throws IOException {
        // Scan's walk, not another class's method of that name.
        assertThat(declared("[`SpringSecurityModule.Scan.walk`](" + SPRING + "SpringSecurityModule.java)"))
                .contains("void walk(");
        assertThat(declared("[`EntryRules.checks`](" + SPRING + "SpringSecurityModule.java)"))
                .contains("checks(");
    }

    @Test
    void aUiLinkPointsAtItsFunction() throws IOException {
        assertThat(declared("[`findingGroups`](../../frontend/src/features/findings/findingGroups.ts)"))
                .contains("export function findingGroups(");
    }

    @Test
    void aStaleAnchorIsMovedAndAFreshOneKept() {
        String stale = "[`Edge.local`](" + GRAPH + "Edge.java#L1)";
        GuideAnchors.Anchored once = GuideAnchors.anchor(PAGE, stale);
        GuideAnchors.Anchored twice = GuideAnchors.anchor(PAGE, once.text());

        assertThat(once.moved()).isEqualTo(1);
        assertThat(twice.moved()).isZero();
        assertThat(twice.text()).isEqualTo(once.text());
    }

    @Test
    void linksThatNameNoMemberAreLeftAsTheyAre() {
        String page = """
                [`App.tsx`](../../frontend/src/App.tsx), [`scan/spring/`](%s), [the overview](README.md#the-pipeline),
                [plain words](%sEdge.java)

                ```
                [`Edge.local`](%sEdge.java)
                ```
                """.formatted(SPRING, GRAPH, GRAPH);

        assertThat(GuideAnchors.anchor(PAGE, page).text()).isEqualTo(page);
    }

    @Test
    void aLinkToAFileNamedByItsTextLosesItsAnchor() {
        assertThat(GuideAnchors.anchor(PAGE, "[`App.tsx`](../../frontend/src/App.tsx#L9)").text())
                .isEqualTo("[`App.tsx`](../../frontend/src/App.tsx)");
    }

    @Test
    void aMemberTheFileDoesNotHaveIsReportedAndKeepsNoAnchor() {
        GuideAnchors.Anchored anchored = GuideAnchors.anchor(PAGE, "[`Edge.nowhere`](" + GRAPH + "Edge.java#L3)");

        assertThat(anchored.text()).isEqualTo("[`Edge.nowhere`](" + GRAPH + "Edge.java)");
        assertThat(anchored.unplaced()).containsExactly("`Edge.nowhere` in " + GRAPH + "Edge.java");
    }

    /**
     * The line a link is anchored at.
     */
    private static String declared(String link) throws IOException {
        Matcher anchor = ANCHOR.matcher(GuideAnchors.anchor(PAGE, link).text());
        assertThat(anchor.find()).as("anchored: " + link).isTrue();
        List<String> lines = Files.readAllLines(PAGE.getParent().resolve(anchor.group(1)).normalize());
        return lines.get(Integer.parseInt(anchor.group(2)) - 1);
    }
}
