package fixtures.filterauthpreauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0071: a gateway puts the user in a header, and a pre-authentication filter of the application's own
 * trusts it; Spring keeps what it sets in the session. A login filter of its own signs in a kiosk from a header on
 * its login requests.
 */
@SpringBootApplication
class FilterAuthPreauthApp {
}

@Configuration
@EnableWebSecurity
class GatewayChain {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        GatewayHeaderFilter gateway = new GatewayHeaderFilter();
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .addFilterAt(gateway, AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterBefore(new KioskLoginFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}

class GatewayHeaderFilter extends AbstractPreAuthenticatedProcessingFilter {

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        return request.getHeader("X-Gateway-User");
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return "N/A";
    }
}

class KioskLoginFilter extends AbstractAuthenticationProcessingFilter {

    KioskLoginFilter() {
        super("/kiosk/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        return UsernamePasswordAuthenticationToken.authenticated(request.getHeader("X-Kiosk"), null,
                AuthorityUtils.createAuthorityList("ROLE_KIOSK"));
    }
}

@RestController
class InboxController {

    @GetMapping("/inbox")
    String inbox() {
        return "inbox";
    }
}
