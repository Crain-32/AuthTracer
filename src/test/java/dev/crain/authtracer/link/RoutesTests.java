package dev.crain.authtracer.link;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class RoutesTests {

    @Test
    void aWildcardTemplateReachesTheRoutesUnderIt() {
        assertThat(Routes.reaches("/employees/**", "/employees/{id}")).isTrue();
        assertThat(Routes.reaches("/employees/**", "/employees")).isTrue();
        assertThat(Routes.reaches("/employees/**", "/teams/{id}")).isFalse();
        assertThat(Routes.reaches("/employees/{id}", "/employees/{employeeId}")).isTrue();
        // A literal segment lands on a variable; a variable may be anything, so not only on that literal.
        assertThat(Routes.reaches("/employees/me", "/employees/{id}")).isTrue();
        assertThat(Routes.reaches("/employees/me/", "/employees/{id}")).isTrue();
        assertThat(Routes.reaches("/employees/{id}", "/employees/me")).isFalse();
        assertThat(Routes.reaches("/employees/me", "/teams/{id}")).isFalse();
        assertThat(Routes.matchesPath("/employees/**", "/employees/7/salary")).isTrue();
    }

    @Test
    void aQueryPicksTheEndpointByItsParams() {
        assertThat(Routes.paramsMatch("use_case=delegation", "use_case=delegation")).isTrue();
        assertThat(Routes.paramsMatch("use_case=delegation", "use_case=impersonation")).isFalse();
        assertThat(Routes.paramsMatch(null, "use_case=impersonation")).isTrue();
        // Headers, media types and API versions aren't in the query.
        assertThat(Routes.paramsMatch("use_case=delegation", "use_case=delegation&header:X-API-VERSION=2")).isTrue();
        assertThat(Routes.paramsMatch("a=b", "version:2.0")).isTrue();
        assertThat(Routes.paramsMatch("a=1", null)).isTrue();
        assertThat(Routes.paramsMatch("a=1", "!b")).isTrue();
        assertThat(Routes.paramsMatch("a=1&b=2", "!b")).isFalse();
        assertThat(Routes.paramsMatch("a={p1}", "a=x")).isTrue();
        // The handler AuthTracer adds to tell two Ingress with one id apart is no request parameter.
        assertThat(Routes.paramsMatch("", "handler=app.Endpoint#get")).isTrue();
    }

    @Test
    void aParamConditionIsMetAsSpringMeetsIt() {
        // a!=b: any other value, or none; a: present, with any value.
        assertThat(Routes.paramsMatch("mode=full", "mode!=full")).isFalse();
        assertThat(Routes.paramsMatch("mode=brief", "mode!=full")).isTrue();
        assertThat(Routes.paramsMatch("", "mode!=full")).isTrue();
        assertThat(Routes.paramsMatch("debug&mode=full", "debug")).isTrue();
        assertThat(Routes.paramsMatch("mode=full", "debug")).isFalse();
        assertThat(Routes.paramsMatch("view=full", "mode=full")).isFalse();
    }

    @Test
    void onlyRequestParametersAreParamsAQueryCanMeet() {
        assertThat(Routes.namesParameters("use_case=delegation")).isTrue();
        assertThat(Routes.namesParameters("version:2.0&!debug")).isTrue();
        assertThat(Routes.namesParameters("header:X-API-VERSION=2&handler=app.Reports#v2")).isFalse();
        assertThat(Routes.namesParameters(null)).isFalse();
    }

    @Test
    void methodsMatchWhenEitherIsAnyOrUnknown() {
        assertThat(Routes.sameMethod(null, "GET")).isTrue();
        assertThat(Routes.sameMethod("GET", null)).isTrue();
        assertThat(Routes.sameMethod("GET", "*")).isTrue();
        assertThat(Routes.sameMethod("get", "GET")).isTrue();
        assertThat(Routes.sameMethod("GET", "POST")).isFalse();
    }

    @Test
    void aUrlIsReadAsFarAsItIsOne() {
        assertThat(Routes.path("http://localhost:9001")).isEqualTo("/");
        assertThat(Routes.path("http://localhost:9001/items/7?view=full")).isEqualTo("/items/7");
        // A target with characters a URI doesn't allow, as some tracers record it.
        assertThat(Routes.path("/search?q=a b")).isEqualTo("/search");
        assertThat(Routes.path("/items/{id}")).isEqualTo("/items/{id}");
        assertThat(Routes.host("http://back:8080/items")).hasValue("back");
        assertThat(Routes.host("http://bad host/items")).isEmpty();
        assertThat(Routes.host(null)).isEmpty();
        assertThat(Routes.port("https://api.example.com/items")).hasValue(443);
        assertThat(Routes.port("http://example.com")).hasValue(80);
        assertThat(Routes.port("/items")).isEmpty();
        assertThat(Routes.port("http://bad host:80")).isEmpty();
    }

    @Test
    void aTemplateIsAPathFromTheRoot() {
        assertThat(Routes.reaches("items/{id}", "/items/**")).isTrue();
        assertThat(Routes.reaches("items/**", "/items/{id}")).isTrue();
        assertThat(Routes.matchesPath("/items/{id}", "/items/7/price")).isFalse();
        // Not a pattern Spring parses, so nothing is under it.
        assertThat(Routes.reaches("/admin/**/users", "/admin/{id}/users")).isFalse();
    }

    @Test
    void aMessageReachesTheListenersOfItsDestination() {
        assertThat(Routes.sameDestination("RABBIT", "orders", "orders")).isTrue();
        assertThat(Routes.sameDestination("RABBIT", "orders.created", "orders.*")).isFalse();
        // A Kafka listener's topicPattern is a regular expression.
        assertThat(Routes.sameDestination("KAFKA", "orders.created", "orders\\..*")).isTrue();
        assertThat(Routes.sameDestination("KAFKA", "orders.created", "invoices")).isFalse();
        assertThat(Routes.sameDestination("KAFKA", "orders.created", "orders\\.(created")).isFalse();
    }

    @Test
    void aConcreteCallReachesAWildcardRoute() {
        assertThat(Routes.reaches("/eureka/apps/{app}", "/eureka/**")).isTrue();
        assertThat(Routes.reaches("/actuator/health/liveness", "/actuator/health/{*path}")).isTrue();
        assertThat(Routes.reaches("/legacy/report", "/legacy/**")).isTrue();
        assertThat(Routes.reaches("/employees/{id}", "/admin/**")).isFalse();
    }
}
