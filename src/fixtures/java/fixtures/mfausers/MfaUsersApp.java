package fixtures.mfausers;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.authorization.MapRequiredAuthoritiesRepository;
import org.springframework.security.authorization.RequiredAuthoritiesAuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * AUTHZ-10 with the factors listed by Arrays.asList: the admin needs a one-time token and a passkey.
 */
@Configuration
@EnableWebSecurity
class MfaUsersConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return http.build();
    }

    @Bean
    AuthorizationManagerFactory<Object> authorizationManagerFactory(RequiredAuthoritiesAuthorizationManager<Object> users) {
        DefaultAuthorizationManagerFactory<Object> defaults = new DefaultAuthorizationManagerFactory<>();
        defaults.setAdditionalAuthorization(users);
        return defaults;
    }

    @Bean
    RequiredAuthoritiesAuthorizationManager<Object> users() {
        MapRequiredAuthoritiesRepository repository = new MapRequiredAuthoritiesRepository();
        repository.saveRequiredAuthorities("admin", Arrays.asList(FactorGrantedAuthority.OTT_AUTHORITY,
                FactorGrantedAuthority.WEBAUTHN_AUTHORITY));
        return new RequiredAuthoritiesAuthorizationManager<>(repository);
    }
}

/**
 * Where sign-ins are recorded; its implementation is the application's.
 */
interface SignInLog {

    void record(String user);
}

@Component
class MemorySignInLog implements SignInLog {

    @Override
    public void record(String user) {
    }
}

@RestController
class MfaUsersController {

    private final SignInLog log;

    MfaUsersController(SignInLog log) {
        this.log = log;
    }

    @GetMapping("/home")
    String home() {
        log.record("home");
        return "home";
    }
}
