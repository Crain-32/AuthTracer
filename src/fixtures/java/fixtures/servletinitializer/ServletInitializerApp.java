package fixtures.servletinitializer;

import jakarta.servlet.FilterRegistration;
import jakarta.servlet.ServletContext;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.web.WebApplicationInitializer;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CharacterEncodingFilter;

/**
 * Decision 0070 (amended): filters added to the servlet context in code. A lambda initializer comes after Spring
 * Security's registration, so its filters run after the chain; a {@code WebApplicationInitializer}'s place isn't
 * known, so its filter is read as ahead of the chain.
 */
@SpringBootApplication
class ServletInitializerApp {

    @Bean
    ServletContextInitializer tenants() {
        return servletContext -> {
            servletContext.addFilter("tenant", new TenantFilter()).addMappingForUrlPatterns(null, false, "/api/*");
            FilterRegistration.Dynamic late = servletContext.addFilter("late", "fixtures.servletinitializer.LateFilter");
            late.addMappingForUrlPatterns(null, true, "/*");
            // Never mapped: it runs for no request.
            FilterRegistration.Dynamic unmapped = servletContext.addFilter("unmapped", new UnmappedFilter());
            unmapped.setAsyncSupported(true);
        };
    }
}

class WarInitializer implements WebApplicationInitializer {

    @Override
    public void onStartup(ServletContext servletContext) {
        servletContext.addFilter("war", WarFilter.class).addMappingForServletNames(null, false, "dispatcherServlet");
        servletContext.addFilter("encoding", new CharacterEncodingFilter()).addMappingForUrlPatterns(null, false, "/*");
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
