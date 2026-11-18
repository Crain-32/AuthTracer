package fixtures.customizerforms;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * No SecurityFilterChain bean: Boot's default chain gets the customizers' rules first, and one of them opens paths the
 * environment names, which may be any.
 */
@SpringBootApplication
class CustomizerFormsApp {

    @Bean
    Customizer<HttpSecurity> publicPaths(@Value("${security.public-paths}") String[] paths) {
        return http -> http.authorizeHttpRequests(authorize -> authorize.requestMatchers(paths).permitAll());
    }

    @Bean
    Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry> admin() {
        return authorize -> authorize.requestMatchers("/admin/**").hasRole("ADMIN");
    }
}

@RestController
class CustomizerFormsController {

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
