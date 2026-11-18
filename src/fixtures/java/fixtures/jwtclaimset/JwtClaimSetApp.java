package fixtures.jwtclaimset;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * SRC-03: the decoder rewrites the scope claim before authorities are read, from the identity provider's groups.
 */
@Configuration
@EnableWebSecurity
class JwtClaimSetConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().hasAuthority("SCOPE_orders"))
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withIssuerLocation("https://idp.example.com").build();
        decoder.setClaimSetConverter(MappedJwtClaimSetConverter.withDefaults(Map.of("scope", new GroupsToScope())));
        return decoder;
    }
}

/**
 * The groups, as the scopes they stand for.
 */
class GroupsToScope implements Converter<Object, Object> {

    @Override
    public Object convert(Object scope) {
        return scope == null ? Collections.emptyList() : List.of(scope.toString().split(","));
    }
}

@RestController
class JwtClaimSetController {

    @GetMapping("/orders")
    String orders() {
        return "orders";
    }
}
