package fixtures.gatewaymvc;

import static org.springframework.cloud.gateway.server.mvc.filter.BeforeFilterFunctions.stripPrefix;
import static org.springframework.cloud.gateway.server.mvc.filter.LoadBalancerFilterFunctions.lb;
import static org.springframework.cloud.gateway.server.mvc.filter.BeforeFilterFunctions.uri;
import static org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions.route;
import static org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions.http;

import org.springframework.cloud.gateway.server.mvc.filter.TokenRelayFilterFunctions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

/**
 * Spring Cloud Gateway Server MVC: routes in properties and in a RouterFunction bean, behind the servlet chain.
 */
@Configuration
@EnableWebSecurity
class GatewayMvcConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/api/orders/**").hasRole("SALES")
                .requestMatchers("/api/invoices/**", "/api/users/**").authenticated()
                .anyRequest().denyAll());
        return http.build();
    }

    @Bean
    RouterFunction<ServerResponse> invoices() {
        return route("invoices").GET("/api/invoices/**", http())
                .before(uri("http://localhost:8085"))
                .before(stripPrefix(1))
                .filter(TokenRelayFilterFunctions.tokenRelay())
                .build();
    }

    @Bean
    RouterFunction<ServerResponse> users() {
        return route("users").GET("/api/users/**", http()).filter(lb("users-service")).build();
    }
}
