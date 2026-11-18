package fixtures.filterignoring;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * HTTP-17: a request that {@code ignoring()} may take out of the filter chain may skip the chain's filters too, the
 * one a factory makes as well.
 */
@SpringBootApplication
class FilterIgnoringApp {
}

interface FilterFactory {

    Filter create();
}

@Configuration
@EnableWebSecurity
class ProbeChains {

    @Bean
    WebSecurityCustomizer probes() {
        return web -> web.ignoring().requestMatchers(request -> request.getHeader("X-Probe") != null);
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http, FilterFactory factory) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .addFilterBefore(new ScreenFilter(), AuthorizationFilter.class)
                .addFilterAfter(factory.create(), AuthorizationFilter.class)
                .build();
    }
}

class ScreenFilter implements Filter {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        client.get().uri("/screen").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

class StampFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        chain.doFilter(request, response);
    }
}

@RestController
class StatusController {

    @GetMapping("/status")
    String status() {
        return "up";
    }
}
