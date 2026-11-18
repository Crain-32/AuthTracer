package fixtures.securitylib;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

/**
 * A shared security library's DSL an application registers in its META-INF/spring.factories.
 */
public class AuditSecurityDsl extends AbstractHttpConfigurer<AuditSecurityDsl, HttpSecurity> {
}
