package fixtures.filterotherstack;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * HTTP-17 (#48): a WebFlux application that also declares a Servlet chain, left over from a migration. That chain never
 * runs, so the key filter it adds is no way in.
 */
@SpringBootApplication
class FilterOtherStackApp {
}

@Configuration
class Chains {

    @Bean
    SecurityWebFilterChain reactive(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.anyExchange().authenticated())
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    @Bean
    SecurityFilterChain legacy(HttpSecurity http) throws Exception {
        return http.addFilterBefore(new KeyFilter(), UsernamePasswordAuthenticationFilter.class).build();
    }
}

class KeyFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("key", null,
                AuthorityUtils.createAuthorityList("ROLE_KEY")));
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
