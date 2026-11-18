package fixtures.servletinitializerearly;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * Decision 0070 (amended): an initializer ordered before Spring Security's registration puts every plain initializer
 * first, the lambda one too, so both their filters run before the chain, in the initializers' order.
 */
@SpringBootApplication
class ServletInitializerEarlyApp {

    @Bean
    ServletContextInitializer later() {
        return servletContext -> servletContext.addFilter("later", new LaterFilter())
                .addMappingForUrlPatterns(null, false, "/*");
    }
}

@Component
@Order(-200)
class EarlyInitializer implements ServletContextInitializer {

    @Override
    public void onStartup(ServletContext servletContext) {
        servletContext.addFilter("early", EarlyFilter.class).addMappingForUrlPatterns(null, false, "/*");
    }
}

class EarlyFilter implements Filter {

    private final RestClient client = RestClient.builder().baseUrl("http://early:8080").build();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/early").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class LaterFilter implements Filter {

    private final RestClient client = RestClient.builder().baseUrl("http://later:8080").build();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/later").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

@RestController
class HomeController {

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
