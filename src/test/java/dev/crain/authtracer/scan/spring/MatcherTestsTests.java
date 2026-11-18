package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.scan.spring.HttpSecurityRules.Matcher;
import dev.crain.authtracer.scan.spring.HttpSecurityRules.Matcher.Test.Kind;
import dev.crain.authtracer.scan.spring.HttpSecurityRules.Matcher.Truth;
import org.junit.jupiter.api.Test;

/**
 * HTTP-06: what a RequestMatcher lambda's tests say about a route's requests, and how they read.
 */
class MatcherTestsTests {

    @Test
    void aNegatedTestTurnsTrueAndFalseAroundAndLeavesTheCallersChoice() {
        assertThat(test(Kind.PATH_PREFIX, "/api", true).truth("GET", "/api/orders")).isEqualTo(Truth.FALSE);
        assertThat(test(Kind.PATH_PREFIX, "/api", true).truth("GET", "/web")).isEqualTo(Truth.TRUE);
        assertThat(test(Kind.URI, "/api/orders", true).truth("GET", "/api/orders")).isEqualTo(Truth.MAYBE);
        assertThat(test(Kind.URI, "/api/orders", false).truth("GET", "/web")).isEqualTo(Truth.FALSE);
    }

    @Test
    void anExactPathOnARouteWithVariablesIsThePathsToDecide() {
        assertThat(test(Kind.PATH, "/orders/7", false).truth("GET", "/orders/{id}")).isEqualTo(Truth.MAYBE);
        // A route that isn't a valid pattern can't be ruled out.
        assertThat(test(Kind.PATH, "/orders/7", false).truth("GET", "/orders/{id")).isEqualTo(Truth.MAYBE);
    }

    @Test
    void eachTestReadsAsWhatItAsks() {
        assertThat(List.of(test(Kind.METHOD, "GET", true), test(Kind.PATH, "/a", true), test(Kind.URI, "/a", false),
                test(Kind.URI_PREFIX, "/a", true), test(Kind.HEADER, "X", true), test(Kind.PARAMETER, "p", false))
                .stream().map(Matcher.Test::describe).toList())
                .containsExactly("not GET", "path not /a", "URI /a", "URI not under /a", "no header X", "parameter p");
        assertThat(test(Kind.PARAMETER, "p", false).choice()).isEqualTo("the parameter p");
        assertThat(test(Kind.METHOD, "GET", false).choice()).isNull();
    }

    @Test
    void aLambdaThatNeverReturnsTrueMatchesNothing() {
        Matcher nothing = Matcher.tests(List.of());
        assertThat(nothing.matches("GET", "/orders")).isFalse();
        assertThat(nothing.mayMatch("GET", "/orders")).isFalse();
        assertThat(Matcher.tests(List.of(List.of())).describe()).isEqualTo("when every request");
    }

    private static Matcher.Test test(Kind kind, String value, boolean negated) {
        return new Matcher.Test(kind, value, negated);
    }
}
