package fixtures.anonymousauthorities;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Callers who haven't signed in get ROLE_GUEST as well as ROLE_ANONYMOUS, so the guest role's checks admit anyone.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class AnonymousAuthoritiesConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/catalog/**").hasAnyRole("GUEST", "CUSTOMER")
                        .requestMatchers("/orders/**").hasRole("CUSTOMER")
                        .anyRequest().authenticated())
                .anonymous(anonymous -> anonymous.authorities("ROLE_ANONYMOUS", "ROLE_GUEST"));
        return http.build();
    }
}

@Service
class Catalog {

    @PreAuthorize("hasRole('GUEST')")
    String prices() {
        return "prices";
    }
}

@RestController
class StoreController {

    private final Catalog catalog;

    StoreController(Catalog catalog) {
        this.catalog = catalog;
    }

    @GetMapping("/catalog/prices")
    String prices() {
        return catalog.prices();
    }

    @GetMapping("/orders/mine")
    String orders() {
        return "orders";
    }
}
