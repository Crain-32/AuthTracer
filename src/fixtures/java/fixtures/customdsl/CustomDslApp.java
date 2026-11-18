package fixtures.customdsl;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The organization's rules come in a custom DSL; one more in spring.factories applies to every chain.
 */
@Configuration
@EnableWebSecurity
class CustomDslConfig {

    @Bean
    SecurityFilterChain web(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/public/**").permitAll())
                .with(new CompanyDsl(), Customizer.withDefaults());
        return http.build();
    }
}

/**
 * Its init runs when the chain is built: after the chain's own rules.
 */
class CompanyDsl extends AbstractHttpConfigurer<CompanyDsl, HttpSecurity> {

    @Override
    public void init(HttpSecurity http) {
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/ops/**").hasRole("OPS")
                .anyRequest().authenticated());
    }
}

/**
 * Registered in META-INF/spring.factories: Spring applies it to every HttpSecurity.
 */
class InternalDsl extends AbstractHttpConfigurer<InternalDsl, HttpSecurity> {

    @Override
    public void init(HttpSecurity http) {
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/internal/**").denyAll());
    }
}

@RestController
class Endpoints {

    @GetMapping("/public/info")
    String info() {
        return "info";
    }

    @GetMapping("/ops/health")
    String health() {
        return "ok";
    }

    @GetMapping("/internal/debug")
    String debug() {
        return "debug";
    }

    @GetMapping("/orders")
    String orders() {
        return "orders";
    }
}
