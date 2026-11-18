package fixtures.decisionforms;

import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * Decision code in more of the forms applications write it: managers that combine built-in ones, a manager bean
 * written as a lambda, a policy interface's method reference, an AuthorizationManagerFactory bean called from SpEL,
 * a feature-flag bean behind an interface, a bean defined once per profile, checks that read a table or ask a quota
 * service, and a bean nothing defines next to a check AuthTracer reads.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class DecisionFormsConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http, AuthorizationManager<RequestAuthorizationContext> internalOnly,
            Policy policy) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/composite/**").access(new Composite())
                .requestMatchers("/negated/**").access(new Negated())
                .requestMatchers("/internal/**").access(internalOnly)
                .requestMatchers("/policy/**").access(policy::decide)
                .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    AuthorizationManager<RequestAuthorizationContext> internalOnly() {
        return (authentication, context) -> new AuthorizationDecision(authentication.get().getAuthorities()
                .contains(new SimpleGrantedAuthority("ROLE_INTERNAL")));
    }

    @Bean
    AuthorizationManager<RequestAuthorizationContext> partnersOnly() {
        return AuthorityAuthorizationManager.hasRole("PARTNER");
    }

    @Bean
    Policy policy() {
        return new OpenPolicy();
    }

    @Bean
    AuthorizationManagerFactory<MethodInvocation> groups(Environment environment) {
        DefaultAuthorizationManagerFactory<MethodInvocation> factory = new DefaultAuthorizationManagerFactory<>();
        factory.setRolePrefix("GROUP_");
        return factory;
    }

    @Bean
    AuthorizationManagerFactory<MethodInvocation> tenants(Environment environment) {
        DefaultAuthorizationManagerFactory<MethodInvocation> factory = new DefaultAuthorizationManagerFactory<>();
        factory.setRolePrefix(environment.getProperty("tenant.role-prefix", "TENANT_"));
        return factory;
    }

    @Bean
    FeatureFlags featureFlags(Environment environment) {
        return name -> environment.getProperty("features." + name, Boolean.class, false);
    }
}

@Configuration
@Profile("dev")
class DevGateConfig {

    @Bean
    Gate gate() {
        return new Gate(true);
    }
}

@Configuration
@Profile("!dev")
class GateConfig {

    @Bean
    Gate gate() {
        return new Gate(false);
    }
}

class Gate {

    private final boolean open;

    Gate(boolean open) {
        this.open = open;
    }

    public boolean allows(Authentication authentication) {
        return open;
    }
}

/**
 * A policy the application looks up; which implementation decides isn't known at the call.
 */
interface Policy {

    AuthorizationResult decide(Supplier<? extends Authentication> authentication, RequestAuthorizationContext context);
}

class OpenPolicy implements Policy {

    @Override
    public AuthorizationResult decide(Supplier<? extends Authentication> authentication,
            RequestAuthorizationContext context) {
        return new AuthorizationDecision(true);
    }
}

interface FeatureFlags {

    boolean isEnabled(String name);
}

/**
 * Either of two built-in managers.
 */
class Composite implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            RequestAuthorizationContext context) {
        return AuthorizationManagers.anyOf(AuthorityAuthorizationManager.<RequestAuthorizationContext>hasRole("ADMIN"),
                AuthorityAuthorizationManager.<RequestAuthorizationContext>hasRole("OPS"))
                .authorize(authentication, context);
    }
}

/**
 * Anyone a built-in manager doesn't grant.
 */
class Negated implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            RequestAuthorizationContext context) {
        return AuthorizationManagers.not(AuthorityAuthorizationManager.<RequestAuthorizationContext>hasRole("BANNED"))
                .authorize(authentication, context);
    }
}

@Component("seats")
class Seats {

    private final JdbcTemplate jdbc;

    Seats(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public boolean available(Authentication authentication) {
        Integer taken = jdbc.queryForObject("select count(*) from seats where owner = ?", Integer.class,
                authentication.getName());
        return taken != null && taken < 3;
    }
}

@Component("quota")
class Quota {

    private final RestClient quotas = RestClient.create("http://quota:8080");

    public boolean remaining(Authentication authentication) {
        Integer left = quotas.get().uri("/quotas/{user}", authentication.getName()).retrieve().body(Integer.class);
        return left != null && left > 0;
    }
}

@Component("self")
class Self {

    public boolean isSelf(MethodSecurityExpressionOperations operations) {
        return operations.getAuthentication().getAuthorities().contains(new SimpleGrantedAuthority("ROLE_SELF"));
    }
}

@RestController
class DecisionFormsController {

    @GetMapping("/composite/check")
    String composite() {
        return "composite";
    }

    @GetMapping("/negated/check")
    String negated() {
        return "negated";
    }

    @GetMapping("/internal/check")
    String internal() {
        return "internal";
    }

    @GetMapping("/policy/check")
    String policy() {
        return "policy";
    }

    @GetMapping("/groups")
    @PreAuthorize("@groups.hasRole('ADMIN')")
    String groups() {
        return "groups";
    }

    @GetMapping("/groups/all")
    @PreAuthorize("@groups.hasAllRoles('ADMIN', 'AUDITOR')")
    String allGroups() {
        return "all groups";
    }

    @GetMapping("/tenants")
    @PreAuthorize("@tenants.hasRole('ADMIN')")
    String tenants() {
        return "tenants";
    }

    @GetMapping("/beta")
    @PreAuthorize("@featureFlags.isEnabled('beta')")
    String beta() {
        return "beta";
    }

    @GetMapping("/gate")
    @PreAuthorize("@gate.allows(authentication)")
    String gate() {
        return "gate";
    }

    @GetMapping("/seats")
    @PreAuthorize("@seats.available(authentication)")
    String seats() {
        return "seats";
    }

    @GetMapping("/quota")
    @PreAuthorize("@quota.remaining(authentication)")
    String quota() {
        return "quota";
    }

    @GetMapping("/self")
    @PreAuthorize("@self.isSelf(#root)")
    String self() {
        return "self";
    }

    @GetMapping("/fallback")
    @PreAuthorize("hasAuthority('ops') or @fallback.allows()")
    String fallback() {
        return "fallback";
    }
}
