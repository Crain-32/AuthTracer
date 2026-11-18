package fixtures.dynamicpatterns;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0051 with each RequestMatcher factory: patterns built from properties, a case-insensitive regex, and a
 * rule whose matchers are a path pattern and a matcher written as a lambda.
 */
@Configuration
@EnableWebSecurity
class DynamicPatternsConfig {

    @Bean
    PathPatternRequestMatcher.Builder paths() {
        return PathPatternRequestMatcher.withDefaults();
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http, PathPatternRequestMatcher.Builder paths,
            @Value("${partners.path}") String partners, @Value("${reports.path}") String reports,
            @Value("${feeds.path}") String feeds, @Value("${sessions.path}") String sessions,
            @Value("${api.path}") String api) throws Exception {
        RequestMatcher internal = request -> request.getRemoteAddr().startsWith("10.");
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/health").permitAll()
                .requestMatchers(PathPatternRequestMatcher.pathPattern("/exports/**"), internal).hasRole("EXPORTER")
                .requestMatchers(paths.matcher(partners + "/**")).hasRole("PARTNER")
                .requestMatchers(PathPatternRequestMatcher.pathPattern(reports + "/**")).hasRole("REPORTER")
                .requestMatchers(RegexRequestMatcher.regexMatcher(HttpMethod.GET, feeds + "/v[0-9]+/.*")).hasRole("FEEDS")
                .requestMatchers(new RegexRequestMatcher("/legacy/.*", null, true)).hasRole("LEGACY")
                .requestMatchers(paths.matcher(sessions + "/**")).rememberMe()
                .requestMatchers(PathPatternRequestMatcher.pathPattern(api + "/**"))
                .hasAllAuthorities("SCOPE_api.read", "SCOPE_api.write")
                .anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class DynamicPatternsController {

    @GetMapping("/health")
    String health() {
        return "up";
    }

    @GetMapping("/exports/daily")
    String export() {
        return "export";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
