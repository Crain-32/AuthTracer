package fixtures.bootintrospectorbean;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.server.resource.introspection.RestClientOpaqueTokenIntrospector;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * No SecurityFilterChain bean and no introspection properties, but an introspector bean of the RestClient kind (new
 * in Spring Security 7.1): Boot's opaque-token chain takes the default's place, since its condition matches any
 * OpaqueTokenIntrospector.
 */
@SpringBootApplication
@RestController
class BootIntrospectorBeanApplication {

    @Bean
    RestClientOpaqueTokenIntrospector introspector() {
        return RestClientOpaqueTokenIntrospector.withIntrospectionUri("https://idp.example.com/introspect")
                .clientId("reports").clientSecret("secret").build();
    }

    @GetMapping("/reports")
    String reports() {
        return "reports";
    }
}
