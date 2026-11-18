package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AbsoluteUrlTests {

    @Test
    void aUrlIsSplitIntoItsBaseAndPath() {
        assertThat(AbsoluteUrl.parse("http://idp:9000/realms/x")).contains(new AbsoluteUrl("http://idp:9000",
                "/realms/x"));
        assertThat(AbsoluteUrl.parse("${issuer}/realms")).isEmpty();
    }

    @Test
    void aRelativeOrOpaqueUrlOrOneWithoutAHostIsNone() {
        assertThat(AbsoluteUrl.parse("/oauth2/jwks")).isEmpty();
        assertThat(AbsoluteUrl.parse("mailto:security@example.com")).isEmpty();
        assertThat(AbsoluteUrl.parse("file:/etc/jwks.json")).isEmpty();
        assertThat(AbsoluteUrl.parse("http://:9000/oauth2")).isEmpty();
    }

    @Test
    void aHostNameWithAnUnderscoreIsStillAHost() {
        assertThat(AbsoluteUrl.parse("http://config_server:8888")).contains(new AbsoluteUrl(
                "http://config_server:8888", ""));
        assertThat(AbsoluteUrl.parse("http://user@auth_server/oauth2")).contains(new AbsoluteUrl(
                "http://auth_server", "/oauth2"));
    }
}
