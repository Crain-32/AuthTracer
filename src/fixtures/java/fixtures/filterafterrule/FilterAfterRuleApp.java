package fixtures.filterafterrule;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Filters that authenticate after the request rules decided: one added after the AuthorizationFilter, one Boot
 * registers after the whole chain. The rules see a caller who hasn't signed in; only the checks after them, method
 * security here, see what they set. HTTP Basic is the way in the rules see.
 */
@SpringBootApplication
@EnableMethodSecurity
class FilterAfterRuleApp {
}

@Configuration
@EnableWebSecurity
class AfterRuleChain {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.requestMatchers("/reports/**").permitAll()
                        .anyRequest().authenticated())
                .httpBasic(basic -> { })
                .addFilterAfter(new ServiceKeyFilter(), AuthorizationFilter.class)
                .build();
    }
}

class ServiceKeyFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.getHeader("X-Service-Key") != null) {
            SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                    "service", null, AuthorityUtils.createAuthorityList("ROLE_SERVICE")));
        }
        chain.doFilter(request, response);
    }
}

/**
 * A filter bean Boot registers at the lowest precedence, after Spring Security's.
 */
@Component
class AuditorFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.getHeader("X-Auditor") != null) {
            SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                    "auditor", null, AuthorityUtils.createAuthorityList("ROLE_AUDITOR")));
        }
        chain.doFilter(request, response);
    }
}

@RestController
class ReportsController {

    @GetMapping("/reports/daily")
    @PreAuthorize("hasRole('SERVICE')")
    String daily() {
        return "daily";
    }
}
