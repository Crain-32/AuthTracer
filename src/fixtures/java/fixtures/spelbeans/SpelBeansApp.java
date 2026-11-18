package fixtures.spelbeans;

import java.util.Map;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.oauth2.core.authorization.DefaultOAuth2AuthorizationManagerFactory;
import org.springframework.security.oauth2.core.authorization.OAuth2AuthorizationManagerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * SpEL bean references in pre/post annotations: an application bean's method, the OAuth2 manager factory's scopes
 * (one wrapping the multi-factor factory, one with its own prefix), and a bean nothing defines.
 */
@Configuration
@EnableMethodSecurity
class SpelBeansConfig {

    @Bean
    OAuth2AuthorizationManagerFactory<MethodInvocation> oauth2() {
        return new DefaultOAuth2AuthorizationManagerFactory<>();
    }

    @Bean
    OAuth2AuthorizationManagerFactory<MethodInvocation> stepUp() {
        AuthorizationManagerFactory<MethodInvocation> mfa = AuthorizationManagerFactories.<MethodInvocation>multiFactor()
                .requireFactors(FactorGrantedAuthority.PASSWORD_AUTHORITY, FactorGrantedAuthority.OTT_AUTHORITY)
                .build();
        return new DefaultOAuth2AuthorizationManagerFactory<>(mfa);
    }

    @Bean("legacyScopes")
    OAuth2AuthorizationManagerFactory<MethodInvocation> legacy() {
        DefaultOAuth2AuthorizationManagerFactory<MethodInvocation> factory = new DefaultOAuth2AuthorizationManagerFactory<>();
        factory.setScopePrefix("PERM_");
        return factory;
    }
}

/**
 * Decides per document, which AuthTracer can't reduce.
 */
@Component("authz")
class AuthorizationLogic {

    private final Map<Long, String> owners = Map.of(1L, "ada");

    public boolean canRead(Long id, MethodSecurityExpressionOperations operations) {
        return operations.getAuthentication().getName().equals(owners.get(id));
    }
}

@RestController
class DocumentController {

    @GetMapping("/documents/{id}")
    @PreAuthorize("@authz.canRead(#id, #root) and hasRole('USER')")
    String document(@PathVariable Long id) {
        return "document";
    }

    @GetMapping("/messages")
    @PreAuthorize("@oauth2.hasScope('message:read')")
    String messages() {
        return "messages";
    }

    @GetMapping("/admin/messages")
    @PreAuthorize("@stepUp.hasAnyScope('message:admin', 'admin')")
    String adminMessages() {
        return "admin messages";
    }

    @GetMapping("/legacy/messages")
    @PreAuthorize("@legacyScopes.hasScope('messages')")
    String legacyMessages() {
        return "legacy messages";
    }

    @GetMapping("/archive")
    @PreAuthorize("@archivist.mayRead()")
    String archive() {
        return "archive";
    }
}
