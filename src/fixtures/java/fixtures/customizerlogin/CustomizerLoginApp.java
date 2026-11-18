package fixtures.customizerlogin;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A Customizer<HttpSecurity> bean sets up the login page for every chain, permitting it.
 */
@Configuration
class CustomizerLoginConfig {

    @Bean
    Customizer<HttpSecurity> login() {
        return http -> {
            try {
                http.formLogin(form -> form.loginPage("/signin").permitAll());
            }
            catch (Exception ex) {
                throw new IllegalStateException(ex);
            }
        };
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class SigninController {

    @GetMapping("/signin")
    String signin() {
        return "sign in";
    }

    @GetMapping("/account")
    String account() {
        return "account";
    }
}
