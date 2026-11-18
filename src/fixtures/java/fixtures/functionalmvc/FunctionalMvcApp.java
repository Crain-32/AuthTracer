package fixtures.functionalmvc;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

/**
 * Spring MVC's functional endpoints read the same way.
 */
@Configuration
class FunctionalMvcApp {

    @Bean
    RouterFunction<ServerResponse> routes() {
        return RouterFunctions.route()
                .path("/api", builder -> builder.GET("/status", FunctionalMvcApp::status))
                .build();
    }

    static ServerResponse status(ServerRequest request) {
        return ServerResponse.ok().body("up");
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/api/**").hasRole("API")
                .anyRequest().denyAll());
        return http.build();
    }
}
