package fixtures.loginpage;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * A custom login page: formLogin(..).permitAll() lets everyone reach it, ahead of anyRequest().
 */
@Configuration
@EnableWebSecurity
class LoginPageConfig {

    @Bean
    SecurityFilterChain web(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .formLogin(form -> form.loginPage("/signin").permitAll())
                .logout(logout -> logout.logoutSuccessUrl("/bye").permitAll());
        return http.build();
    }
}

@Controller
class LoginController {

    @GetMapping("/signin")
    String signin() {
        return "signin";
    }

    @GetMapping("/bye")
    String bye() {
        return "bye";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
