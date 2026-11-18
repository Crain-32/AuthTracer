package dev.crain.authtracer.scan;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigurationPropertiesTests {

    @TempDir
    Path dir;

    @Test
    void placeholdersResolveAsSpringResolvesThem() throws IOException {
        ConfigurationProperties properties = load("""
                server.port=${PORT:${FALLBACK_PORT:8080}}
                issuer=http://${idp.host}:${idp.port:9000}
                idp.host=keycloak
                realm=${issuer}/realms/${REALM}
                topic=${orders.topic}
                """);

        assertThat(properties.get("server.port")).contains("8080");
        // A value's own placeholders resolve in turn.
        assertThat(properties.get("issuer")).contains("http://keycloak:9000");
        // The environment sets REALM: no value AuthTracer can know.
        assertThat(properties.get("realm")).isEmpty();
        assertThat(properties.getResolvingKnown("realm")).contains("http://keycloak:9000/realms/${REALM}");
        assertThat(properties.get("topic")).isEmpty();
        assertThat(properties.getResolvingKnown("topic")).contains("${orders.topic}");
        assertThat(properties.resolve("${idp.host:other}")).contains("keycloak");
        assertThat(properties.resolveKnown("/${missing}/${idp.host}")).isEqualTo("/${missing}/keycloak");
    }

    @Test
    void aCircularReferenceResolvesToNothing() throws IOException {
        ConfigurationProperties properties = load("a=${b}\nb=${a}\n");

        assertThat(properties.get("a")).isEmpty();
        assertThat(properties.resolveKnown("${a}")).isEqualTo("${a}");
    }

    @Test
    void aProfilesDocumentIsLeftOutAndALaterDocumentOverrides() throws IOException {
        Files.writeString(dir.resolve("application.yaml"), """
                server:
                  port: 8080
                ---
                spring:
                  config:
                    activate:
                      on-profile: local
                  h2:
                    console:
                      enabled: true
                server:
                  port: 9999
                ---
                server:
                  port: 8443
                """);
        ConfigurationProperties properties = ConfigurationProperties.load(List.of(dir));

        assertThat(properties.get("server.port")).contains("8443");
        assertThat(properties.flag("spring.h2.console.enabled")).isEmpty();
    }

    @Test
    void aCloudPlatformsOrALegacyProfilesDocumentIsLeftOutToo() throws IOException {
        Files.writeString(dir.resolve("application.yml"), """
                management:
                  server:
                    port: 9000
                ---
                spring:
                  config:
                    activate:
                      on-cloud-platform: kubernetes
                management:
                  server:
                    port: 9001
                    address: 10.0.0.1
                ---
                spring:
                  profiles: dev
                  h2:
                    console:
                      enabled: true
                """);
        ConfigurationProperties properties = ConfigurationProperties.load(List.of(dir));

        assertThat(properties.get("management.server.port")).contains("9000");
        assertThat(properties.get("management.server.address")).isEmpty();
        assertThat(properties.flag("spring.h2.console.enabled")).isEmpty();
    }

    @Test
    void aPropertiesFilesDocumentsAreReadAsYamlDocumentsAre() throws IOException {
        ConfigurationProperties properties = load("""
                server.port=8080
                #---
                spring.config.activate.on-profile=local
                server.port=9999
                spring.h2.console.enabled=true
                #---
                server.servlet.context-path=/api
                """);

        assertThat(properties.get("server.port")).contains("8080");
        assertThat(properties.get("server.servlet.context-path")).contains("/api");
        assertThat(properties.flag("spring.h2.console.enabled")).isEmpty();
    }

    @Test
    void theFirstResourceDirectoryAndFileThatSetAPropertyWin(@TempDir Path other) throws IOException {
        Files.writeString(dir.resolve("application.properties"), "server.port=8080\n");
        Files.writeString(dir.resolve("application.yaml"), "server:\n  port: 8081\n  address: 0.0.0.0\n");
        Files.writeString(other.resolve("application.properties"), "server.port=8082\nspring.application.name=x\n");
        ConfigurationProperties properties = ConfigurationProperties.load(List.of(dir, other));

        assertThat(properties.get("server.port")).contains("8080");
        assertThat(properties.get("server.address")).contains("0.0.0.0");
        assertThat(properties.get("spring.application.name")).contains("x");
    }

    @Test
    void namesBindRelaxedlyAsSpringBindsThem() throws IOException {
        ConfigurationProperties properties = load("""
                eureka.client.serviceUrl.defaultZone=http://eureka:8761/eureka/
                spring.h2.console.settings.webAllowOthers=true
                management.endpoint.env.showValues=ALWAYS
                spring.security.oauth2.client.registration.myIdp.clientId=app
                """);

        assertThat(properties.list("eureka.client.service-url.defaultZone")).containsExactly(
                "http://eureka:8761/eureka/");
        assertThat(properties.flag("spring.h2.console.settings.web-allow-others")).contains(true);
        assertThat(properties.get("management.endpoint.env.show-values")).contains("ALWAYS");
        assertThat(properties.namesUnder("spring.security.oauth2.client.registration."))
                .containsExactly("myIdp.clientId");
        assertThat(properties.hasPrefix("spring.security.oauth2.client.")).isTrue();
        assertThat(properties.get("server.port")).isEmpty();
    }

    @Test
    void namesUnderARelaxedPrefixAreTheNamesAsWritten() throws IOException {
        ConfigurationProperties properties = load("""
                spring.security.oauth2.client.Registration.my-idp.client-id=app
                eureka.client.service-url[Default-Zone]=http://eureka:8761/eureka/
                """);

        assertThat(properties.hasPrefix("spring.security.oauth2.client.registration.")).isTrue();
        assertThat(properties.namesUnder("spring.security.oauth2.client.registration."))
                .containsExactly("my-idp.client-id");
        assertThat(properties.hasPrefix("spring.security.oauth2.resourceserver.")).isFalse();
        // An index is a map key, kept as written.
        assertThat(properties.get("eureka.client.serviceUrl[Default-Zone]")).contains("http://eureka:8761/eureka/");
        assertThat(properties.get("eureka.client.serviceUrl[defaultzone]")).isEmpty();
    }

    @Test
    void listsAreCommaSeparatedOrYamlLists() throws IOException {
        Files.writeString(dir.resolve("application.yaml"), """
                exposure:
                  include: [health, "${extra:env}", " "]
                  exclude: beans, , info
                """);
        ConfigurationProperties properties = ConfigurationProperties.load(List.of(dir));

        assertThat(properties.list("exposure.include")).containsExactly("health", "env");
        assertThat(properties.list("exposure.exclude")).containsExactly("beans", "info");
        assertThat(properties.list("exposure.missing")).isEmpty();
    }

    @Test
    void flagsAreReadAsSpringsBinderReadsThem() throws IOException {
        ConfigurationProperties properties = load("a=TRUE\nb=off\nc=Yes \nd=0\ne=maybe\n");

        assertThat(properties.flag("a")).contains(true);
        assertThat(properties.flag("b")).contains(false);
        assertThat(properties.flag("c")).contains(true);
        assertThat(properties.flag("d")).contains(false);
        assertThat(properties.flag("e")).isEmpty();
        assertThat(properties.flag("f")).isEmpty();
    }

    /**
     * Boot 4.1.1's default locations: classpath:/config/ after classpath:/, so the config/ directory's file wins.
     */
    @Test
    void theConfigDirectorysFileWinsOverTheRoots() throws IOException {
        Files.writeString(dir.resolve("application.properties"), "management.endpoints.web.exposure.include=health\n"
                + "server.port=8080\n");
        Files.createDirectories(dir.resolve("config"));
        Files.writeString(dir.resolve("config/application.yml"), """
                management:
                  endpoints:
                    web:
                      exposure:
                        include: "*"
                """);
        ConfigurationProperties properties = ConfigurationProperties.load(List.of(dir));

        assertThat(properties.get("management.endpoints.web.exposure.include")).contains("*");
        assertThat(properties.get("server.port")).contains("8080");
    }

    /**
     * A profile the configuration activates itself is applied: its file and its documents over the rest, a later
     * profile over an earlier one. One only the deployment can activate is left out.
     */
    @Test
    void theProfilesTheConfigurationActivatesAreApplied() throws IOException {
        Files.writeString(dir.resolve("application.yaml"), """
                spring:
                  profiles:
                    active: prod,eu
                server:
                  port: 8080
                app:
                  region: none
                ---
                spring:
                  config:
                    activate:
                      on-profile: eu
                app:
                  region: eu
                ---
                spring:
                  config:
                    activate:
                      on-profile: local
                spring.h2.console.enabled: true
                """);
        Files.writeString(dir.resolve("application-prod.properties"), "server.port=443\napp.region=prod\n");
        Files.writeString(dir.resolve("application-dev.properties"), "management.endpoints.web.exposure.include=*\n");
        ConfigurationProperties properties = ConfigurationProperties.load(List.of(dir));

        assertThat(properties.get("server.port")).contains("443");
        assertThat(properties.get("app.region")).contains("eu");
        assertThat(properties.flag("spring.h2.console.enabled")).isEmpty();
        assertThat(properties.get("management.endpoints.web.exposure.include")).isEmpty();
    }

    private ConfigurationProperties load(String content) throws IOException {
        Files.writeString(dir.resolve("application.properties"), content);
        return ConfigurationProperties.load(List.of(dir));
    }
}
