package fixtures.librarydsl;

import fixtures.securitylib.TenantSecurityDsl;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP-16: DSLs from a shared security library, applied with http.with(..) (created here, or by the library's
 * factory method) and through META-INF/spring.factories. AuthTracer doesn't read a library's configurers.
 */
@Configuration
@EnableWebSecurity
class LibraryDslConfig {

    @Bean
    @Order(1)
    SecurityFilterChain tenants(HttpSecurity http) throws Exception {
        http.securityMatcher("/tenants/**")
                .with(new TenantSecurityDsl(), Customizer.withDefaults())
                .authorizeHttpRequests(requests -> requests.anyRequest().authenticated());
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.with(TenantSecurityDsl.tenantSecurity(), Customizer.withDefaults())
                .authorizeHttpRequests(requests -> requests.anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class LibraryDslController {

    @GetMapping("/tenants/acme")
    String tenant() {
        return "acme";
    }
}
