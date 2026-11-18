package fixtures.filterauthboot;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Decision 0071: no chain is declared, so Boot's default one (form login and HTTP Basic) is a way in, and so is the
 * filter component, which Boot registers for every request.
 */
@SpringBootApplication
class FilterAuthBootApp {
}

/**
 * Trusts a header a proxy in front of the service sets.
 */
@Component
class ProxyHeaderFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String user = request.getHeader("X-Forwarded-User");
        if (user != null) {
            SecurityContextHolder.getContext().setAuthentication(new PreAuthenticatedAuthenticationToken(user, null,
                    AuthorityUtils.createAuthorityList("ROLE_STAFF")));
        }
        chain.doFilter(request, response);
    }
}

@RestController
class StaffController {

    @GetMapping("/staff")
    String staff() {
        return "staff";
    }
}
