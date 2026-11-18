package fixtures.filterregistrations;

import java.io.IOException;
import java.util.List;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.server.servlet.context.ServletComponentScan;
import org.springframework.boot.web.servlet.FilterRegistration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.ForwardedHeaderFilter;

/**
 * HTTP-17: the ways Spring Boot 4.1.1 registers a servlet filter, or doesn't. A {@code @WebFilter} for servlet names
 * may run for any request, one with nothing for every request. A filter bean's {@code @FilterRegistration} may name
 * servlets or disable it. A lambda bean, a library filter bean (which runs library code only), a bean a registration
 * of its own takes over, a disabled registration and one turned on or off by settings, the default servlet's
 * {@code /}, servlet names (alone or beside URL patterns), an order read from settings, URL patterns longer or shorter than a route, a route ending in {@code **}, and bean methods whose filter
 * depends on the environment.
 */
@SpringBootApplication
@ServletComponentScan
class FilterRegistrationsApp {
}

/**
 * Where a filter's calls go.
 */
abstract class CallingFilter implements Filter {

    private static final RestClient CALLS = RestClient.create("http://calls:8080");

    abstract String uri();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        CALLS.get().uri(uri()).retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

@WebFilter(servletNames = "dispatcherServlet")
class NamedWebFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/named-web").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

@WebFilter
class BareWebFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/bare-web").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

@Configuration
class Registrations {

    private static final RestClient CALLS = RestClient.create("http://calls:8080");

    @Bean
    @FilterRegistration(servletNames = "dispatcherServlet")
    Filter namedBean() {
        return new NamedBeanFilter();
    }

    @Bean
    @FilterRegistration(enabled = false)
    Filter disabledBean() {
        return new DisabledBeanFilter();
    }

    @Bean
    Filter lambdaBean() {
        return (request, response, chain) -> {
            CALLS.get().uri("/lambda-bean").retrieve().toBodilessEntity();
            chain.doFilter(request, response);
        };
    }

    @Bean
    ForwardedHeaderFilter forwarded() {
        return new ForwardedHeaderFilter();
    }

    @Bean
    AuditFilter audit() {
        return new AuditFilter();
    }

    @Bean
    FilterRegistrationBean<AuditFilter> auditRegistration(AuditFilter audit) {
        FilterRegistrationBean<AuditFilter> registration = new FilterRegistrationBean<>(audit);
        registration.addUrlPatterns("/reports/*");
        return registration;
    }

    @Bean
    FilterRegistrationBean<TraceFilter> trace() {
        FilterRegistrationBean<TraceFilter> registration = new FilterRegistrationBean<>(new TraceFilter());
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    FilterRegistrationBean<RootFilter> root(Environment environment) {
        FilterRegistrationBean<RootFilter> registration = new FilterRegistrationBean<>(new RootFilter());
        registration.addUrlPatterns("/");
        registration.setOrder(environment.getProperty("root.order", Integer.class, 0));
        registration.setEnabled(true);
        return registration;
    }

    @Bean
    FilterRegistrationBean<ServletNamesFilter> servletNames() {
        FilterRegistrationBean<ServletNamesFilter> registration = new FilterRegistrationBean<>(new ServletNamesFilter());
        registration.setServletNames(List.of("dispatcherServlet"));
        return registration;
    }

    @Bean
    FilterRegistrationBean<SummaryFilter> summary() {
        FilterRegistrationBean<SummaryFilter> registration = new FilterRegistrationBean<>(new SummaryFilter());
        registration.addUrlPatterns("/reports/daily/summary", "/reports");
        return registration;
    }

    @Bean
    FilterRegistrationBean<ArchiveFilter> archive() {
        FilterRegistrationBean<ArchiveFilter> registration = new FilterRegistrationBean<>(new ArchiveFilter());
        registration.addUrlPatterns("/files/archive");
        return registration;
    }

    @Bean
    Filter choice(Environment environment) {
        if (environment.containsProperty("strict")) {
            return new StrictFilter();
        }
        return new RelaxedFilter();
    }

    @Bean
    FilterRegistrationBean<BothFilter> both() {
        FilterRegistrationBean<BothFilter> registration = new FilterRegistrationBean<>(new BothFilter());
        registration.addUrlPatterns("/reports/*");
        registration.addServletNames("dispatcherServlet");
        return registration;
    }

    @Bean
    FilterRegistrationBean<ToggledFilter> toggled(Environment environment) {
        FilterRegistrationBean<ToggledFilter> registration = new FilterRegistrationBean<>(new ToggledFilter());
        registration.setEnabled(environment.getProperty("toggled.enabled", Boolean.class, true));
        return registration;
    }

    @Bean
    FilterRegistrationBean<ForwardedHeaderFilter> forwardedRegistration() {
        return new FilterRegistrationBean<>(new ForwardedHeaderFilter());
    }

    @Bean
    @FilterRegistration(order = 10)
    Filter ordered() {
        return new OrderedFilter();
    }

    @Bean
    String[] allowedOrigins() {
        return new String[] {"https://example.com"};
    }

    @Bean
    Filter picked(Environment environment) {
        return environment.containsProperty("strict") ? new StrictFilter() : new ForwardedHeaderFilter();
    }
}

class NamedBeanFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/named-bean").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class DisabledBeanFilter extends CallingFilter {

    @Override
    String uri() {
        return "/disabled-bean";
    }
}

class AuditFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/audit").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class TraceFilter extends CallingFilter {

    @Override
    String uri() {
        return "/trace";
    }
}

class RootFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/root").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class ServletNamesFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/servlet-names").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class SummaryFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/summary").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class ArchiveFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/archive").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class BothFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/both").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class ToggledFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/toggled").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class OrderedFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/ordered").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class StrictFilter extends CallingFilter {

    @Override
    String uri() {
        return "/strict";
    }
}

class RelaxedFilter extends CallingFilter {

    @Override
    String uri() {
        return "/relaxed";
    }
}

/**
 * A component filter whose base class is abstract: only the concrete class is a bean.
 */
@Component
class StampFilter extends CallingFilter {

    @Override
    String uri() {
        return "/stamp";
    }
}

@RestController
class RegistrationsController {

    @GetMapping("/reports/{id}")
    String report(@PathVariable String id) {
        return id;
    }

    @GetMapping("/files/**")
    String files() {
        return "files";
    }

    @GetMapping("/status")
    String status() {
        return "up";
    }
}
