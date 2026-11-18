package fixtures.graphqlws;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;

/**
 * POST /graphql needs a scope, but the WebSocket handshake is open: the operation is as open as the WebSocket.
 */
@Configuration
class WebSocketGraphQlConfig {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests
                .requestMatchers(HttpMethod.POST, "/graphql").hasAuthority("SCOPE_graphql")
                .requestMatchers("/graphql-ws").permitAll()
                .anyRequest().denyAll());
        return http.build();
    }
}

@Controller
class GreetingController {

    @QueryMapping
    String greeting() {
        return "hello";
    }
}
