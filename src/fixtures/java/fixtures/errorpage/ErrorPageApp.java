package fixtures.errorpage;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP-05: an error page on spring.web.error.path whose error dispatch gets the same rule as its own requests.
 */
@SpringBootApplication
class ErrorPageApp {

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class ProblemController implements ErrorController {

    @GetMapping("/problem")
    String problem() {
        return "Something went wrong";
    }
}
