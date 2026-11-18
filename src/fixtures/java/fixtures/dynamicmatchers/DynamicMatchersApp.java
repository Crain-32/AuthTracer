package fixtures.dynamicmatchers;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Patterns built at run time: a chain's securityMatcher and two rules AuthTracer can't evaluate, which may match
 * any request first.
 */
@SpringBootApplication
class DynamicMatchersApp {

    @Bean
    @Order(1)
    SecurityFilterChain internal(HttpSecurity http) throws Exception {
        http.securityMatcher(internalPath() + "/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("INTERNAL"));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/public", openPath()).permitAll()
                .requestMatchers(HttpMethod.POST, openPath() + "/orders").hasRole("WRITER")
                .anyRequest().authenticated());
        return http.build();
    }

    static String internalPath() {
        return System.getProperty("internal.path", "/internal");
    }

    static String openPath() {
        return System.getProperty("open.path", "/open");
    }
}

@RestController
class OrdersController {

    @GetMapping("/orders")
    String orders() {
        return "orders";
    }
}
