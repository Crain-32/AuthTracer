package fixtures.fields;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.method.NullReturningMethodAuthorizationDeniedHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@Configuration
@EnableMethodSecurity
class FieldsSecurityConfig {

    @Bean
    NullReturningMethodAuthorizationDeniedHandler nullReturningHandler() {
        return new NullReturningMethodAuthorizationDeniedHandler();
    }
}
