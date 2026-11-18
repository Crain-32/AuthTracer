package fixtures.ldapbuilder;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP Basic against a directory the global builder configures, and an admin chain against Active Directory.
 */
@Configuration
@EnableWebSecurity
class LdapBuilderSecurityConfig {

    @Autowired
    void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.ldapAuthentication()
                .userDnPatterns("uid={0},ou=people")
                .groupSearchBase("ou=groups")
                .contextSource().url("ldap://ldap.example.com:389/dc=example,dc=com");
    }

    @Bean
    @Order(1)
    SecurityFilterChain admin(HttpSecurity http) throws Exception {
        http.securityMatcher("/admin/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("ADMINS"))
                .httpBasic(withDefaults())
                .authenticationProvider(new ActiveDirectoryLdapAuthenticationProvider("example.com",
                        "ldap://ad.example.com"));
        return http.build();
    }

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .httpBasic(withDefaults());
        return http.build();
    }
}

@RestController
class LdapBuilderController {

    @GetMapping("/people")
    String people() {
        return "people";
    }
}
