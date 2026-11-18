package fixtures.filtercustomizerboot;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ThrowingCustomizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Decision 0070 (amended): with no chain of the application's, a {@code Customizer<HttpSecurity>} bean's filter is in
 * Spring Boot's default chain, here one after its AuthorizationFilter and one before HTTP Basic.
 */
@SpringBootApplication
class FilterCustomizerBootApp {

    @Bean
    Customizer<HttpSecurity> audit() {
        return http -> http.addFilterAfter(new AuditFilter(), AuthorizationFilter.class);
    }

    @Bean
    ThrowingCustomizer<HttpSecurity> trace() {
        return http -> http.addFilterBefore(new TraceFilter(), BasicAuthenticationFilter.class);
    }
}

class TraceFilter extends OncePerRequestFilter {

    private final RestClient traces = RestClient.builder().baseUrl("http://traces:8080").build();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        traces.post().uri("/spans").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class AuditFilter extends OncePerRequestFilter {

    private final RestClient audit = RestClient.builder().baseUrl("http://audit:8080").build();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        audit.post().uri("/events").body(request.getRequestURI()).retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

@RestController
class ReportController {

    @GetMapping("/reports")
    String reports() {
        return "reports";
    }
}
