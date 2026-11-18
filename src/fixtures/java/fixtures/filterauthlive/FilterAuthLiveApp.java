package fixtures.filterauthlive;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.repository.CrudRepository;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Decision 0071: an API-key filter that looks the key up on every request, so a revoked key stops working at once.
 */
@SpringBootApplication
class FilterAuthLiveApp {
}

@Configuration
@EnableWebSecurity
class KeysChain {

    @Bean
    SecurityFilterChain chain(HttpSecurity http, ApiKeyFilter keys) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .addFilterBefore(keys, AnonymousAuthenticationFilter.class)
                .build();
    }
}

record ApiKey(String key, String owner, String role) {
}

interface ApiKeys extends CrudRepository<ApiKey, String> {
}

@Component
class ApiKeyFilter extends OncePerRequestFilter {

    private final ApiKeys keys;

    ApiKeyFilter(ApiKeys keys) {
        this.keys = keys;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Optional<ApiKey> key = keys.findById(String.valueOf(request.getHeader("X-Api-Key")));
        key.ifPresent(found -> SecurityContextHolder.setContext(new SecurityContextImpl(
                new PreAuthenticatedAuthenticationToken(found.owner(), null,
                        List.of(new SimpleGrantedAuthority("ROLE_" + found.role()))))));
        chain.doFilter(request, response);
    }
}

@RestController
class KeysController {

    @GetMapping("/keyed")
    String keyed() {
        return "keyed";
    }
}
