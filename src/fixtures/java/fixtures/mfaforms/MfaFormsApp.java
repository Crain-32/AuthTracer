package fixtures.mfaforms;

import java.time.Duration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.RequiredFactor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * AUTHZ-08 and AUTHZ-09 as Spring Security's reference writes them: an AuthorizationManagerFactory bean built by
 * multiFactor() asks every rule for a recent password and an SMS code; an admin factory asks some users for a
 * one-time token; and managers built from RequiredFactor ask for a passkey or a certificate, or a recent SMS code.
 */
@Configuration
@EnableWebSecurity
class MfaFormsConfig {

    @Bean
    AuthorizationManagerFactory<Object> authorizationManagerFactory() {
        return AuthorizationManagerFactories.multiFactor()
                .requireFactor(factor -> factor.passwordAuthority().validDuration(Duration.ofHours(1)))
                .requireFactor(factor -> factor.authority("FACTOR_SMS"))
                .build();
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        AuthorizationManagerFactory<RequestAuthorizationContext> admins = AuthorizationManagerFactories
                .<RequestAuthorizationContext>multiFactor()
                .when(authentication -> authentication.getName().startsWith("admin"))
                .requireFactors(FactorGrantedAuthority.OTT_AUTHORITY)
                .build();
        AllRequiredFactorsAuthorizationManager<RequestAuthorizationContext> passkey = AllRequiredFactorsAuthorizationManager
                .<RequestAuthorizationContext>builder()
                .requireFactor(RequiredFactor.withAuthority(FactorGrantedAuthority.WEBAUTHN_AUTHORITY).build())
                .build();
        AllRequiredFactorsAuthorizationManager<RequestAuthorizationContext> certificate = AllRequiredFactorsAuthorizationManager
                .<RequestAuthorizationContext>builder()
                .requireFactor(RequiredFactor.builder().x509Authority().build())
                .build();
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/public").permitAll()
                .requestMatchers("/admin/**").access(admins.hasRole("ADMIN"))
                .requestMatchers("/keys/**").access(AllRequiredFactorsAuthorizationManager.anyOf(passkey, certificate))
                .requestMatchers("/payments/**").access(AllRequiredFactorsAuthorizationManager
                        .<RequestAuthorizationContext>builder()
                        .requireFactor(RequiredFactor.builder().authority("FACTOR_SMS")
                                .validDuration(Duration.ofMinutes(5)).build())
                        .build())
                .anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class MfaFormsController {

    @GetMapping("/public")
    String open() {
        return "open";
    }

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/keys/rotate")
    String rotate() {
        return "rotated";
    }

    @GetMapping("/payments/send")
    String send() {
        return "sent";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
