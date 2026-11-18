package fixtures.classmappings;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * Spring MVC combines a class's @RequestMapping with each handler's: their methods together, their params together.
 */
@Configuration
@EnableWebSecurity
class ClassMappingsConfig {

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable()).authorizeHttpRequests(authorize -> authorize
                .requestMatchers(HttpMethod.POST, "/accounts/**").hasRole("TELLER")
                .anyRequest().authenticated());
        return http.build();
    }
}

@RestController
@RequestMapping(path = "/accounts", method = RequestMethod.POST)
class AccountsController {

    /**
     * POST only: the class's method.
     */
    @RequestMapping("/close")
    String close() {
        return "closed";
    }

    /**
     * GET and POST.
     */
    @GetMapping("/summary")
    String summary() {
        return "summary";
    }
}

@RestController
@RequestMapping(path = "/v2", params = "tenant")
class TenantController {

    @GetMapping(path = "/items", params = "page")
    String items() {
        return "items";
    }
}
