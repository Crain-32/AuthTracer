package fixtures.loginurls;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Login and logout on URLs of the application's own: permitAll() lets everyone reach each of them, the failure page
 * included. A partner chain with the default login page permits only its logout URL.
 */
@Configuration
@EnableWebSecurity
class LoginUrlsConfig {

    @Bean
    @Order(1)
    SecurityFilterChain partners(HttpSecurity http) throws Exception {
        http.securityMatcher("/partner/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("PARTNER"))
                .formLogin(Customizer.withDefaults())
                .logout(logout -> logout.logoutUrl("/partner/logout").permitAll());
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain web(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .formLogin(form -> form.loginPage("/account/login")
                        .loginProcessingUrl("/account/authenticate")
                        .failureUrl("/account/login-failed")
                        .permitAll())
                .logout(logout -> logout.logoutUrl("/account/logout")
                        .logoutSuccessUrl("/account/goodbye")
                        .permitAll());
        return http.build();
    }
}

@Controller
class AccountController {

    @GetMapping("/account/login")
    String login() {
        return "login";
    }

    @GetMapping("/account/login-failed")
    String failed() {
        return "login-failed";
    }

    @GetMapping("/account/goodbye")
    String goodbye() {
        return "goodbye";
    }

    @GetMapping("/account/settings")
    @ResponseBody
    String settings() {
        return "settings";
    }

    /**
     * The logout confirmation page, at the logout URL.
     */
    @GetMapping("/partner/logout")
    String partnerLogout() {
        return "logout";
    }

    @GetMapping("/partner/home")
    @ResponseBody
    String partnerHome() {
        return "home";
    }
}
