package fixtures.bootdecoderbean;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * No SecurityFilterChain bean and no JWT properties, but a decoder bean of the application's own class: Boot's JWT
 * chain takes the default's place.
 */
@SpringBootApplication
@RestController
class BootDecoderBeanApplication {

    @Bean
    TenantJwtDecoder jwtDecoder() {
        return new TenantJwtDecoder(NimbusJwtDecoder.withJwkSetUri("https://idp.example.com/jwks").build());
    }

    @GetMapping("/reports")
    String reports() {
        return "reports";
    }
}

/**
 * Decodes with one tenant's keys.
 */
class TenantJwtDecoder implements JwtDecoder {

    private final JwtDecoder delegate;

    TenantJwtDecoder(JwtDecoder delegate) {
        this.delegate = delegate;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        return delegate.decode(token);
    }
}
