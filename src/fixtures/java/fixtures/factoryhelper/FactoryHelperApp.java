package fixtures.factoryhelper;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The factory bean's role prefix is set in a helper the bean method hands it to: hasRole("STAFF") asks for AUTH_STAFF.
 */
@Configuration
@EnableWebSecurity
class FactoryHelperApp {

    @Bean
    static <T> AuthorizationManagerFactory<T> authorizationManagerFactory() {
        DefaultAuthorizationManagerFactory<T> factory = new DefaultAuthorizationManagerFactory<>();
        prefixed(factory);
        return factory;
    }

    private static void prefixed(DefaultAuthorizationManagerFactory<?> factory) {
        factory.setRolePrefix("AUTH_");
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/staff/**").hasRole("STAFF")
                        .anyRequest().authenticated())
                .httpBasic(basic -> { });
        return http.build();
    }
}

@RestController
class StaffController {

    @GetMapping("/staff/list")
    String list() {
        return "staff";
    }
}
