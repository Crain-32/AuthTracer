package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A field's JSON name under each of Jackson's naming strategies, as Jackson 3 names it (checked against its
 * PropertyNamingStrategies).
 */
class JsonNamingFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("jsonnaming");

    @Test
    void snakeCaseSeparatesRunsOfCapitalsAndDropsALeadingUnderscore() {
        assertThat(json("SnakeView.myHTTPServer")).isEqualTo("my_httpserver");
        assertThat(json("SnakeView._id")).isEqualTo("id");
        assertThat(json("SnakeView.a_B")).isEqualTo("a_b");
        assertThat(json("UpperSnakeView.myHTTPServer")).isEqualTo("MY_HTTPSERVER");
        assertThat(json("UpperSnakeView.homeURL")).isEqualTo("HOME_URL");
    }

    @Test
    void kebabAndDotCaseStartAWordAtARunsLastCapital() {
        assertThat(json("KebabView.myHTTPServer")).isEqualTo("my-http-server");
        assertThat(json("KebabView.homeURL")).isEqualTo("home-url");
        assertThat(json("KebabView.a1B")).isEqualTo("a1-b");
        assertThat(json("KebabView.URL")).isEqualTo("url");
        assertThat(json("DotView.myHTTPServer")).isEqualTo("my.http.server");
        assertThat(json("DotView.firstName")).isEqualTo("first.name");
    }

    @Test
    void theOtherStrategiesChangeOnlyTheCase() {
        assertThat(json("LowerView.myHTTPServer")).isEqualTo("myhttpserver");
        assertThat(json("UpperCamelView.myHTTPServer")).isEqualTo("MyHTTPServer");
        assertThat(json("UpperCamelView.x")).isEqualTo("X");
        assertThat(json("LowerCamelView.myHTTPServer")).isEqualTo("myHTTPServer");
    }

    private String json(String field) {
        return ((Field) graph.node("field:fixtures.jsonnaming." + field).orElseThrow()).jsonName();
    }
}
