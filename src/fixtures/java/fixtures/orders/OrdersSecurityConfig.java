package fixtures.orders;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Secured is on, JSR-250 is off: {@code @RolesAllowed} in this package must not count.
 */
@Configuration
@EnableMethodSecurity(securedEnabled = true)
class OrdersSecurityConfig {
}
