package fixtures.filters;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Runs first, for every request: Boot registers the component itself, before Spring Security's filter chain.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class TenantFilter extends OncePerRequestFilter {

    private final RestClient tenants = RestClient.builder().baseUrl("http://tenants:8080").build();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        tenants.get().uri("/tenants/{host}", request.getServerName()).retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

/**
 * Added to the API chain before its AuthorizationFilter.
 */
class ApiKeyFilter extends OncePerRequestFilter {

    private final RestClient keys = RestClient.builder().baseUrl("http://keys:8080").build();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        keys.post().uri("/keys/verify").body(String.valueOf(request.getHeader("X-Api-Key"))).retrieve()
                .toBodilessEntity();
        chain.doFilter(request, response);
    }
}

/**
 * Added to the API chain after its AuthorizationFilter: it denies by hand.
 */
@Component
class AuditFilter extends OncePerRequestFilter {

    private final RestClient audit = RestClient.builder().baseUrl("http://audit:8080").build();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (request.getMethod().equals("DELETE") && authentication.getAuthorities().isEmpty()) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        audit.post().uri("/events").body(authentication.getName()).retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

/**
 * Registered for {@code /legacy/*} only, at order 5: after Spring Security's chain.
 */
class LegacyFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!((HttpServletRequest) request).isUserInRole("LEGACY")) {
            ((HttpServletResponse) response).sendError(403);
            return;
        }
        chain.doFilter(request, response);
    }
}

class MaintenanceFilter implements Filter {

    private final RestClient status = RestClient.builder().baseUrl("http://status:8080").build();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        status.get().uri("/maintenance").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}
