package fixtures.authoritiesincode;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * SRC-10: code that sets the Authentication itself outside a filter. The refund endpoint elevates whoever calls it
 * before the billing check, which then sees what it set; a step-up adds a factor authority with toBuilder(); a task
 * runs as the system.
 */
@SpringBootApplication
@EnableMethodSecurity
@EnableScheduling
class AuthoritiesInCodeApp {
}

@Service
class Billing {

    @PreAuthorize("hasRole('BILLING')")
    public String refund(long id) {
        return "refunded " + id;
    }
}

@RestController
class SupportController {

    private final Billing billing;

    SupportController(Billing billing) {
        this.billing = billing;
    }

    @PostMapping("/support/refunds/{id}")
    String refund(@PathVariable long id) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("support", null,
                AuthorityUtils.createAuthorityList("ROLE_BILLING")));
        return billing.refund(id);
    }

    @PostMapping("/step-up")
    void stepUp(Authentication authentication) {
        Authentication elevated = authentication.toBuilder()
                .authorities(authorities -> authorities.add(new SimpleGrantedAuthority("FACTOR_OTT"))).build();
        SecurityContextHolder.getContext().setAuthentication(elevated);
    }
}

@Component
class NightlyClose {

    private final Billing billing;

    NightlyClose(Billing billing) {
        this.billing = billing;
    }

    @Scheduled(cron = "0 0 2 * * *")
    void close() {
        SecurityContextHolder.setContext(new SecurityContextImpl(new UsernamePasswordAuthenticationToken("system",
                null, AuthorityUtils.createAuthorityList("ROLE_BILLING"))));
        billing.refund(0);
    }
}
