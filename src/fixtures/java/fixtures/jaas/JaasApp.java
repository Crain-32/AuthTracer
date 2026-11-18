package fixtures.jaas;

import static org.springframework.security.config.Customizer.withDefaults;

import java.security.Principal;
import java.util.Map;
import java.util.Set;

import javax.security.auth.login.AppConfigurationEntry;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.jaas.AuthorityGranter;
import org.springframework.security.authentication.jaas.DefaultJaasAuthenticationProvider;
import org.springframework.security.authentication.jaas.memory.InMemoryConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP Basic, checked by a JAAS login module; what the caller may do is what the authority granters grant its
 * principals.
 */
@Configuration
@EnableWebSecurity
class JaasSecurityConfig {

    private final AuthorityGranter auditors = new AuditorGranter();

    @Bean
    DefaultJaasAuthenticationProvider jaasProvider() {
        DefaultJaasAuthenticationProvider provider = new DefaultJaasAuthenticationProvider();
        provider.setConfiguration(new InMemoryConfiguration(Map.of("SPRINGSECURITY", new AppConfigurationEntry[] {
                new AppConfigurationEntry("com.example.LoginModule",
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, Map.of()) })));
        provider.setAuthorityGranters(new AuthorityGranter[] { new RoleGranter(),
                principal -> Set.of("ROLE_USER"), auditors });
        return provider;
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("USER"))
                .httpBasic(withDefaults());
        return http.build();
    }
}

class RoleGranter implements AuthorityGranter {

    @Override
    public Set<String> grant(Principal principal) {
        return principal.getName().startsWith("admin") ? Set.of("ROLE_ADMIN") : Set.of();
    }
}

class AuditorGranter implements AuthorityGranter {

    @Override
    public Set<String> grant(Principal principal) {
        return Set.of("ROLE_AUDITOR");
    }
}

@RestController
class JaasController {

    @GetMapping("/reports")
    String reports() {
        return "reports";
    }
}
