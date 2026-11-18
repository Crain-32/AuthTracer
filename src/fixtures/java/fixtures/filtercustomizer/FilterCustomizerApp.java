package fixtures.filtercustomizer;

import java.io.IOException;
import java.util.List;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Decision 0070 (amended): a {@code Customizer<HttpSecurity>} bean adds an API-key filter to every chain, before the
 * chain's own filters at the same place.
 */
@Configuration
@EnableWebSecurity
class FilterCustomizerApp {

    @Bean
    Customizer<HttpSecurity> apiKeys() {
        return http -> http.addFilterBefore(new ApiKeyFilter(), BasicAuthenticationFilter.class);
    }

    /**
     * A customizer of the headers, which Spring Security applies to http.headers(..): no filter of its own.
     */
    @Bean
    Customizer<HeadersConfigurer<HttpSecurity>> headers() {
        return headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin);
    }

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.anyRequest().hasRole("CLIENT")).build();
    }
}

class ApiKeyFilter extends OncePerRequestFilter {

    private final RestClient keys = RestClient.builder().baseUrl("http://keys:8080").build();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String owner = keys.get().uri("/keys/{key}", request.getHeader("X-Api-Key")).retrieve().body(String.class);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(owner, null,
                List.of(new SimpleGrantedAuthority("ROLE_CLIENT"))));
        chain.doFilter(request, response);
    }
}

@RestController
class OrderController {

    @GetMapping("/orders")
    String orders() {
        return "orders";
    }
}
