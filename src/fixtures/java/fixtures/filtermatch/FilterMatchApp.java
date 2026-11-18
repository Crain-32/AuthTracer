package fixtures.filtermatch;

import java.io.IOException;
import java.util.List;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * HTTP-17: which requests a filter runs for, when AuthTracer can only say it may. A chain whose
 * {@code securityMatcher} it can't evaluate may take a request first, so its filters may run, and so may the next
 * chain's. URL patterns that a route's template variable may match, servlet names, and patterns that aren't
 * constants may cover a request too. And the forms a filter value takes: a field, an interface with one bean, a
 * factory method, and a registration's {@code setFilter(..)}.
 */
@SpringBootApplication
class FilterMatchApp {
}

interface TokenCheck extends Filter {
}

@Configuration
@EnableWebSecurity
class MatchChains {

    private final AuditFilter audit;

    MatchChains(AuditFilter audit) {
        this.audit = audit;
    }

    @Bean
    @Order(1)
    SecurityFilterChain partners(HttpSecurity http) throws Exception {
        return http.securityMatcher(request -> request.getHeader("X-Partner") != null)
                .authorizeHttpRequests(requests -> requests.anyRequest().hasRole("PARTNER"))
                .addFilterBefore(new PartnerFilter(), AuthorizationFilter.class)
                .build();
    }

    @Bean
    SecurityFilterChain main(HttpSecurity http, TokenCheck check) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .addFilterBefore(audit, AuthorizationFilter.class)
                .addFilterBefore(check, AuthorizationFilter.class)
                .addFilterAfter(gate(), AuthorizationFilter.class)
                .build();
    }

    private static Filter gate() {
        return new GateFilter();
    }

    @Bean
    FilterRegistrationBean<TenantFilter> tenant() {
        FilterRegistrationBean<TenantFilter> registration = new FilterRegistrationBean<>(new TenantFilter());
        registration.addUrlPatterns("/accounts/acme/*");
        return registration;
    }

    @Bean
    FilterRegistrationBean<JsonFilter> json() {
        FilterRegistrationBean<JsonFilter> registration = new FilterRegistrationBean<>(new JsonFilter());
        registration.setUrlPatterns(List.of("*.json"));
        return registration;
    }

    @Bean
    FilterRegistrationBean<NamedFilter> named() {
        FilterRegistrationBean<NamedFilter> registration = new FilterRegistrationBean<>(new NamedFilter());
        registration.addServletNames("dispatcherServlet");
        return registration;
    }

    @Bean
    FilterRegistrationBean<DynamicFilter> dynamic(Environment environment) {
        FilterRegistrationBean<DynamicFilter> registration = new FilterRegistrationBean<>(new DynamicFilter());
        registration.addUrlPatterns(environment.getProperty("dynamic.path"));
        return registration;
    }

    @Bean
    FilterRegistrationBean<ExactFilter> exact() {
        FilterRegistrationBean<ExactFilter> registration = new FilterRegistrationBean<>(new ExactFilter());
        registration.addUrlPatterns("/home");
        return registration;
    }

    @Bean
    FilterRegistrationBean<Filter> early() {
        FilterRegistrationBean<Filter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new EarlyFilter());
        registration.setOrder(-300);
        return registration;
    }
}

class PartnerFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/partner").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

@Component
class AuditFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/audit").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

@Component
class TokenCheckFilter implements TokenCheck {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/token-check").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class GateFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/gate").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class TenantFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/tenant").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class JsonFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/json").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class NamedFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/named").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class DynamicFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/dynamic").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class ExactFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/exact").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class EarlyFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/early").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

@RestController
class MatchController {

    @GetMapping("/accounts/{tenant}/orders")
    String orders() {
        return "orders";
    }

    @GetMapping("/data/{file}")
    String data() {
        return "data";
    }

    @GetMapping("/data/report.json")
    String report() {
        return "report";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
