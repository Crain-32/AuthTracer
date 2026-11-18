package fixtures.anymethod;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A mapping for any method under rules for one method: reading the reports needs a reader, anything else to them is
 * open, and the mapping takes both.
 */
@Configuration
@EnableWebSecurity
class AnyMethodConfig {

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(HttpMethod.GET, "/reports/**").hasRole("READER")
                .requestMatchers("/reports/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class AnyMethodController {

    @RequestMapping("/reports/summary")
    String summary() {
        return "summary";
    }

    @GetMapping("/reports/detail")
    String detail() {
        return "detail";
    }
}
