package fixtures.jwtbootaudiences;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Boot's decoder, with the audiences its properties name and a validator bean it adds to the issuer's.
 */
@SpringBootApplication
@RestController
class JwtBootAudiencesApplication {

    @Bean
    OAuth2TokenValidator<Jwt> tenantValidator() {
        return new JwtClaimValidator<String>("tenant", "acme"::equals);
    }

    @GetMapping("/orders")
    String orders() {
        return "orders";
    }
}
