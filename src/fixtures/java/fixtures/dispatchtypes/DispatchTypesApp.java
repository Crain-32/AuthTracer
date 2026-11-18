package fixtures.dispatchtypes;

import jakarta.servlet.DispatcherType;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.DispatcherTypeRequestMatcher;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP-05: rules matched by dispatcher type. A legacy chain lets every request's own dispatch through before its
 * admin rule; the application's chain lets forwards, async re-dispatches and errors through, asks GET requests for a
 * reader and DELETEs for an admin. Its own error page answers the error dispatch of any request that fails.
 */
@SpringBootApplication
class DispatchTypesApp {

    @Bean
    @Order(1)
    SecurityFilterChain legacy(HttpSecurity http) throws Exception {
        http.securityMatcher("/legacy/**")
                .authorizeHttpRequests(authorize -> authorize
                        .dispatcherTypeMatchers(DispatcherType.REQUEST).permitAll()
                        .requestMatchers("/legacy/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                // Forwards to views and async re-dispatches come after a request that was authorized.
                .dispatcherTypeMatchers(DispatcherType.FORWARD, DispatcherType.ASYNC).permitAll()
                .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                .requestMatchers(new DispatcherTypeRequestMatcher(DispatcherType.INCLUDE)).permitAll()
                .dispatcherTypeMatchers(HttpMethod.GET, DispatcherType.REQUEST).hasRole("READER")
                .requestMatchers(new DispatcherTypeRequestMatcher(DispatcherType.REQUEST, HttpMethod.DELETE))
                .hasRole("ADMIN")
                .anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class ReportsController {

    @GetMapping("/reports")
    String reports() {
        return "reports";
    }

    @PostMapping("/reports")
    String create() {
        return "created";
    }

    @DeleteMapping("/reports/{id}")
    void delete(@PathVariable long id) {
    }

    @GetMapping("/legacy/admin/users")
    String users() {
        return "users";
    }
}

@Controller
class ErrorPageController implements ErrorController {

    @GetMapping("/error")
    @ResponseBody
    String error() {
        return "Something went wrong";
    }
}
