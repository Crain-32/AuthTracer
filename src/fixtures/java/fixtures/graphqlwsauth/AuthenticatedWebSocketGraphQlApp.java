package fixtures.graphqlwsauth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.graphql.server.WebSocketGraphQlInterceptor;
import org.springframework.graphql.server.support.BearerTokenAuthenticationExtractor;
import org.springframework.graphql.server.webmvc.AuthenticationWebSocketInterceptor;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;

/**
 * As spring-graphql-examples' websocket-authentication: the handshake is open, and the connection authenticates
 * through connection_init.
 */
@Configuration
class AuthenticatedWebSocketGraphQlConfig {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests
                .requestMatchers(HttpMethod.POST, "/graphql").hasAuthority("SCOPE_graphql")
                .anyRequest().permitAll());
        return http.build();
    }

    @Bean
    WebSocketGraphQlInterceptor authenticationInterceptor(AuthenticationManager manager) {
        return new AuthenticationWebSocketInterceptor(new BearerTokenAuthenticationExtractor(), manager);
    }
}

@Controller
class GreetingController {

    @QueryMapping
    String greeting() {
        return "hello";
    }
}
