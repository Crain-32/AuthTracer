package fixtures.filterforms;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.server.servlet.context.ServletComponentScan;
import org.springframework.boot.web.servlet.FilterRegistration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * HTTP-17: the other ways filters are added and ordered. In the chain: {@code addFilterAt}, {@code addFilter} of a
 * subclass of a built-in filter, a position relative to a filter added before, a lambda, a filter added in a helper,
 * and one AuthTracer can't resolve. For every request: an {@code Ordered} component that skips some requests, a
 * {@code @WebFilter}, a bean with {@code @FilterRegistration}, and a bean method's {@code @Order}, which Boot ignores.
 */
@SpringBootApplication
@ServletComponentScan
class FilterFormsApp {
}

interface FilterFactory {

    Filter create();
}

@Configuration
@EnableWebSecurity
class FormsChain {

    private static final RestClient CALLS = RestClient.create("http://calls:8080");

    @Bean
    SecurityFilterChain chain(HttpSecurity http, FilterFactory factory) throws Exception {
        http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .addFilterAt(new TokenFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new TokenAuditFilter(), TokenFilter.class)
                .addFilter(new LoginFilter())
                .addFilterBefore((request, response, next) -> {
                    CALLS.get().uri("/lambda").retrieve().toBodilessEntity();
                    next.doFilter(request, response);
                }, AuthorizationFilter.class)
                .addFilterBefore(factory.create(), AnonymousAuthenticationFilter.class)
                .addFilterAfter(new TranslatedFilter(), ExceptionTranslationFilter.class);
        afterAuthorization(http);
        return http.build();
    }

    private static void afterAuthorization(HttpSecurity http) {
        http.addFilterAfter(new HelperFilter(), AuthorizationFilter.class);
    }

    @Bean
    @FilterRegistration(urlPatterns = "/admin/*", order = -200)
    Filter admin() {
        return new AdminFilter();
    }

    /**
     * Boot orders a filter bean by its class, not by its bean method: this runs at the lowest precedence.
     */
    @Bean
    @Order(-200)
    Filter late() {
        return new LateFilter();
    }
}

class TokenFilter extends OncePerRequestFilter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        client.get().uri("/token").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class TokenAuditFilter extends OncePerRequestFilter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        client.get().uri("/token-audit").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

/**
 * Spring's UsernamePasswordAuthenticationFilter calls it for its login requests only.
 */
class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        client.get().uri("/login").retrieve().toBodilessEntity();
        return super.attemptAuthentication(request, response);
    }
}

class TranslatedFilter extends OncePerRequestFilter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        client.get().uri("/translated").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class HelperFilter extends OncePerRequestFilter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        client.get().uri("/helper").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

/**
 * First for every request but the health checks.
 */
@Component
class FirstFilter extends OncePerRequestFilter implements Ordered {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/health");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        client.get().uri("/first").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

@WebFilter("/reports/*")
class ReportsFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/reports-access").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class AdminFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/admin-access").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class LateFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/late").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

@RestController
class FormsController {

    @GetMapping("/things")
    String things() {
        return "things";
    }

    @GetMapping("/reports/daily")
    String daily() {
        return "daily";
    }

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }
}
