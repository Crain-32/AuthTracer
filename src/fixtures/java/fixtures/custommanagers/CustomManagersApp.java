package fixtures.custommanagers;

import java.time.LocalTime;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Advisor;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Custom AuthorizationManagers: created in the chain, written as a lambda, handed in by type, held in a field,
 * composed with a built-in one, and given to a method-security advisor that is also its own denied handler.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class CustomManagersConfig {

    private final AuthorizationManager<RequestAuthorizationContext> partners;

    CustomManagersConfig(AuthorizationManager<RequestAuthorizationContext> partners) {
        this.partners = partners;
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http, OfficeHours officeHours) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/opa/**").access(new OpaAuthorizationManager("http://opa:8181"))
                .requestMatchers("/weekdays/**").access((authentication, context) ->
                        new AuthorizationDecision(context.getRequest().getParameter("weekday") != null))
                .requestMatchers("/office/**").access(officeHours)
                .requestMatchers("/partners/**").access(partners)
                .requestMatchers("/either/**").access(AuthorizationManagers.anyOf(
                        AuthorityAuthorizationManager.hasRole("ADMIN"), officeHours))
                .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor preAuthorize(AuditManager audit) {
        return AuthorizationManagerBeforeMethodInterceptor.preAuthorize(audit);
    }
}

class OpaAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final String url;

    OpaAuthorizationManager(String url) {
        this.url = url;
    }

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            RequestAuthorizationContext context) {
        return new AuthorizationDecision(url.startsWith("http") && context.getRequest().getRemoteUser() != null);
    }
}

@Component
class OfficeHours implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            RequestAuthorizationContext context) {
        return new AuthorizationDecision(LocalTime.now().getHour() >= 9);
    }
}

@Component
class Partners implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            RequestAuthorizationContext context) {
        return new AuthorizationDecision(context.getRequest().getHeader("X-Partner") != null);
    }
}

/**
 * Decides the pre-authorized methods and handles their denials itself (DENY-04).
 */
@Component
class AuditManager implements AuthorizationManager<MethodInvocation>, MethodAuthorizationDeniedHandler {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            MethodInvocation invocation) {
        return new AuthorizationDecision(invocation.getArguments().length > 0);
    }

    @Override
    public Object handleDeniedInvocation(MethodInvocation invocation, AuthorizationResult result) {
        return "audited";
    }
}

@Service
class Ledger {

    @PreAuthorize("hasRole('AUDITOR')")
    String entries(String year) {
        return year;
    }
}

@RestController
class CustomManagersController {

    private final Ledger ledger;

    CustomManagersController(Ledger ledger) {
        this.ledger = ledger;
    }

    @GetMapping("/opa/check")
    String opa() {
        return "opa";
    }

    @GetMapping("/weekdays/plan")
    String weekdays() {
        return "plan";
    }

    @GetMapping("/office/printers")
    String office() {
        return "printers";
    }

    @GetMapping("/partners/catalog")
    String partners() {
        return "catalog";
    }

    @GetMapping("/either/report")
    String either() {
        return "report";
    }

    @GetMapping("/ledger")
    String ledger() {
        return ledger.entries("2026");
    }
}
