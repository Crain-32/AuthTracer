package fixtures.securitylib;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

/**
 * A shared security library's DSL: to an application that depends on it, a configurer from a library.
 */
public class TenantSecurityDsl extends AbstractHttpConfigurer<TenantSecurityDsl, HttpSecurity> {

    public static TenantSecurityDsl tenantSecurity() {
        return new TenantSecurityDsl();
    }

    @Override
    public void init(HttpSecurity http) {
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/tenants/**").permitAll());
    }
}
