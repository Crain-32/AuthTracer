package fixtures.sessionunread;

import static org.springframework.security.config.Customizer.withDefaults;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The context is kept in a signed cookie, by a repository of the application's own, and by one a library gives the
 * admin chain.
 */
@Configuration
@EnableWebSecurity
class SessionUnreadSecurityConfig {

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .formLogin(withDefaults())
                .securityContext(context -> context.securityContextRepository(new CookieContextRepository()));
        return http.build();
    }

    @Bean
    @Order(1)
    SecurityFilterChain admin(HttpSecurity http, SecurityContextRepository libraryRepository) throws Exception {
        http.securityMatcher("/admin/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("ADMIN"))
                .formLogin(withDefaults())
                .securityContext(context -> context.securityContextRepository(libraryRepository));
        return http.build();
    }
}

class CookieContextRepository implements SecurityContextRepository {

    @Override
    @SuppressWarnings("deprecation")
    public SecurityContext loadContext(HttpRequestResponseHolder holder) {
        return SecurityContextHolder.createEmptyContext();
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        response.addHeader("Set-Cookie", "context=" + context.hashCode());
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return request.getCookies() != null;
    }
}

@RestController
class SessionUnreadController {

    @GetMapping("/inbox")
    String inbox() {
        return "inbox";
    }
}
