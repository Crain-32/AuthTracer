package fixtures.filterunwinding;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Decision 0070 (amended): what a filter does after {@code chain.doFilter(..)} returns runs after the handler, as the
 * request unwinds through the filters, the inner one's first; what it does instead of calling it runs before.
 */
@SpringBootApplication
class FilterUnwindingApp {

    /**
     * Mapped to the dispatcher by name: some requests pass it.
     */
    @Bean
    FilterRegistrationBean<AfterFilter> after() {
        FilterRegistrationBean<AfterFilter> registration = new FilterRegistrationBean<>(new AfterFilter());
        registration.addServletNames("dispatcherServlet");
        return registration;
    }
}

class AfterFilter extends OncePerRequestFilter {

    private final RestClient client = RestClient.builder().baseUrl("http://after:8080").build();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        chain.doFilter(request, response);
        client.post().uri("/after").retrieve().toBodilessEntity();
    }
}

@Component
@Order(-200)
class TimingFilter extends OncePerRequestFilter {

    private final RestClient client = RestClient.builder().baseUrl("http://timings:8080").build();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        client.post().uri("/start").retrieve().toBodilessEntity();
        try {
            chain.doFilter(request, response);
        }
        finally {
            client.post().uri("/stop").retrieve().toBodilessEntity();
        }
    }
}

@Component
@Order(-150)
class GateFilter extends OncePerRequestFilter {

    private final RestClient client = RestClient.builder().baseUrl("http://gate:8080").build();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.getHeader("X-Closed") == null) {
            chain.doFilter(request, response);
            client.post().uri("/served").retrieve().toBodilessEntity();
            return;
        }
        client.post().uri("/turned-away").retrieve().toBodilessEntity();
    }
}

@RestController
class OrderController {

    private final RestClient orders = RestClient.builder().baseUrl("http://orders:8080").build();

    @GetMapping("/orders")
    String orders() {
        return orders.get().uri("/orders").retrieve().body(String.class);
    }
}
