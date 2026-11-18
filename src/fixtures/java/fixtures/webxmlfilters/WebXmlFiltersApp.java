package fixtures.webxmlfilters;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

/**
 * Decision 0070 (amended): a war's web.xml maps a filter before Spring Security's, one after it, a
 * {@code DelegatingFilterProxy} to a filter bean, and one to a bean nobody defines.
 */
@Configuration
@EnableWebSecurity
@EnableWebMvc
class WebXmlFiltersApp {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults()).build();
    }

    @Bean
    AuditFilter auditFilter() {
        return new AuditFilter();
    }
}

class XmlEarlyFilter implements Filter {

    private final RestClient client = RestClient.builder().baseUrl("http://early:8080").build();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/early").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class XmlFilter implements Filter {

    private final RestClient client = RestClient.builder().baseUrl("http://xml:8080").build();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/xml").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class AuditFilter extends OncePerRequestFilter {

    private final RestClient client = RestClient.builder().baseUrl("http://audit:8080").build();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        client.post().uri("/audit").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

/**
 * A component a DelegatingFilterProxy runs by its bean name.
 */
@Component
class StampFilter extends OncePerRequestFilter {

    private final RestClient client = RestClient.builder().baseUrl("http://stamps:8080").build();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        client.post().uri("/stamps").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

@RestController
class OrderController {

    @GetMapping("/api/orders")
    String orders() {
        return "orders";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
