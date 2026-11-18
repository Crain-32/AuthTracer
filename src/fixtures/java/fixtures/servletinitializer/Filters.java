package fixtures.servletinitializer;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.springframework.web.client.RestClient;

class TenantFilter implements Filter {

    private final RestClient client = RestClient.builder().baseUrl("http://tenants:8080").build();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/tenants").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class LateFilter implements Filter {

    private final RestClient client = RestClient.builder().baseUrl("http://late:8080").build();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/late").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class UnmappedFilter implements Filter {

    private final RestClient client = RestClient.builder().baseUrl("http://unmapped:8080").build();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/unmapped").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class WarFilter implements Filter {

    private final RestClient client = RestClient.builder().baseUrl("http://war:8080").build();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/war").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}
