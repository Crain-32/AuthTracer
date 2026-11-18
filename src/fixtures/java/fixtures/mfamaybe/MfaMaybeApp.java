package fixtures.mfamaybe;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.RequiredFactor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0111: a factory that adds a factor only under a profile the configuration doesn't activate may not be
 * made, so the rules may not ask for the factor.
 */
@SpringBootApplication
public class MfaMaybeApp {

    public static void main(String[] args) {
        SpringApplication.run(MfaMaybeApp.class, args);
    }
}

@Configuration
class ChainConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.anyRequest().hasRole("STAFF")).build();
    }
}

@Configuration
@Profile("strict")
class StrictFactors {

    @Bean
    AuthorizationManagerFactory<Object> authorizationManagerFactory() {
        return AuthorizationManagerFactories.multiFactor()
                .requireFactor(RequiredFactor.Builder::passwordAuthority)
                .build();
    }
}

@RestController
class HomeController {

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
