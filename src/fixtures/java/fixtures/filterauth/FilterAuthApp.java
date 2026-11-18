package fixtures.filterauth;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Decision 0071: the hand-written JWT filter. It decodes the bearer token itself and sets the SecurityContext's
 * Authentication, with authorities of its own, before the chain's rules decide.
 */
@SpringBootApplication
class FilterAuthApp {
}

@Configuration
@EnableWebSecurity
class FilterAuthChain {

    @Bean
    SecurityFilterChain chain(HttpSecurity http, JwtFilter jwt, AuthenticationManager manager) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.anyRequest().hasRole("USER"))
                .addFilterBefore(jwt, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new PasswordHeaderFilter(manager), JwtFilter.class)
                .build();
    }
}

@Component
class JwtFilter extends OncePerRequestFilter {

    private final JwtDecoder decoder;

    JwtFilter(JwtDecoder decoder) {
        this.decoder = decoder;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            authenticate(decoder.decode(header.substring(7)));
        }
        chain.doFilter(request, response);
    }

    private void authenticate(Jwt jwt) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(jwt.getSubject(),
                null, AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_READER")));
    }
}

/**
 * Hands the credentials to the AuthenticationManager: its providers, which AuthTracer doesn't read, decide.
 */
class PasswordHeaderFilter extends OncePerRequestFilter {

    private final AuthenticationManager manager;

    PasswordHeaderFilter(AuthenticationManager manager) {
        this.manager = manager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String user = request.getHeader("X-User");
        if (user != null) {
            SecurityContextHolder.getContext().setAuthentication(manager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(user, request.getHeader("X-Password"))));
        }
        chain.doFilter(request, response);
    }
}

@RestController
class FilterAuthController {

    @GetMapping("/profile")
    String profile() {
        return "profile";
    }
}
