package fixtures.matcherlambdaforms;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP-06: RequestMatcher lambdas in more of the forms configurations write them: one that logs before it decides, a
 * constant compared with the raw URI, a helper that takes the request first, a method-override header, a parameter,
 * and ones AuthTracer can't read: a prefix of the method's name, the content length, a switch on the method, and a
 * prefix from the environment.
 */
@Configuration
@EnableWebSecurity
class MatcherLambdaFormsConfig {

    private static final Log log = LogFactory.getLog(MatcherLambdaFormsConfig.class);

    @Bean
    SecurityFilterChain forms(HttpSecurity http, Environment environment) throws Exception {
        String prefix = environment.getProperty("forms.prefix", "/forms/configured");
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(request -> {
                    log.debug("Matching " + request.getServletPath());
                    return request.getServletPath().equals("/forms/exact");
                }).hasRole("EXACT")
                .requestMatchers(request -> "/forms/legacy".equals(request.getRequestURI())).denyAll()
                .requestMatchers(request -> Paths.under(request, "/forms/admin")).hasRole("ADMIN")
                .requestMatchers(request -> HttpMethod.DELETE.matches(request.getHeader("X-HTTP-Method-Override")))
                .hasRole("DELETER")
                .requestMatchers(request -> request.getParameter("debug") != null).hasRole("DEBUG")
                .requestMatchers(request -> request.getMethod().startsWith("P")).hasRole("WRITER")
                .requestMatchers(request -> request.getContentLength() > 1024).hasRole("UPLOADER")
                .requestMatchers(request -> switch (request.getMethod()) {
                    case "GET", "HEAD" -> true;
                    default -> false;
                }).hasRole("READER")
                .requestMatchers(request -> request.getServletPath().startsWith(prefix)).hasRole("CONFIGURED")
                .anyRequest().authenticated());
        return http.build();
    }
}

final class Paths {

    private Paths() {
    }

    static boolean under(HttpServletRequest request, String prefix) {
        return request.getServletPath().startsWith(prefix);
    }
}

@RestController
class MatcherLambdaFormsController {

    @GetMapping("/forms/exact")
    String exact() {
        return "exact";
    }

    @GetMapping("/forms/legacy")
    String legacy() {
        return "legacy";
    }

    @GetMapping("/forms/admin/users")
    String users() {
        return "users";
    }

    @PostMapping("/forms/items")
    String items() {
        return "items";
    }
}
