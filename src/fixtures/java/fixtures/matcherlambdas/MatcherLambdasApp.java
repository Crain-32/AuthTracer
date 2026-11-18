package fixtures.matcherlambdas;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.cors.CorsUtils;

/**
 * HTTP-06: RequestMatcher lambdas that test only the request's path, its method or a header, as configurations write
 * them: a chain for internal paths, rules for preflight requests, deletes under a path, a header the caller sends, a
 * raw URI prefix, and one on the caller's address, which AuthTracer can't evaluate. A last chain takes the requests
 * that carry a partner key.
 */
@Configuration
@EnableWebSecurity
class MatcherLambdasConfig {

    @Bean
    @Order(1)
    SecurityFilterChain internal(HttpSecurity http) throws Exception {
        String internal = "/internal";
        http.securityMatcher(request -> request.getServletPath().startsWith(internal))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("OPS"));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain methods(HttpSecurity http) throws Exception {
        http.securityMatcher("/methods/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                        .requestMatchers(request -> HttpMethod.DELETE.matches(request.getMethod())
                                && request.getServletPath().startsWith("/methods/admin")).hasRole("ADMIN")
                        .requestMatchers(request -> "GET".equals(request.getMethod())).hasRole("READER")
                        .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    @Order(3)
    SecurityFilterChain headers(HttpSecurity http) throws Exception {
        http.securityMatcher("/headers/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(request -> request.getHeader("X-Internal") != null).permitAll()
                        .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    @Order(4)
    SecurityFilterChain uris(HttpSecurity http) throws Exception {
        http.securityMatcher("/uris/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(request -> request.getRequestURI().startsWith("/uris/admin")).hasRole("ADMIN")
                        .requestMatchers(request -> request.getRemoteAddr().startsWith("10.")).hasRole("NETWORK")
                        .anyRequest().permitAll());
        return http.build();
    }

    @Bean
    @Order(5)
    SecurityFilterChain partners(HttpSecurity http) throws Exception {
        http.securityMatcher(request -> request.getHeader("X-Partner-Key") != null)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("PARTNER"));
        return http.build();
    }
}

@RestController
class MatcherLambdasController {

    @GetMapping("/internal/metrics")
    String metrics() {
        return "metrics";
    }

    @RequestMapping(path = "/methods/items", method = org.springframework.web.bind.annotation.RequestMethod.OPTIONS)
    void preflight() {
    }

    @GetMapping("/methods/items")
    String items() {
        return "items";
    }

    @DeleteMapping("/methods/admin/items/{id}")
    void deleteItem(@PathVariable long id) {
    }

    @DeleteMapping("/methods/items/{id}")
    void deleteOwn(@PathVariable long id) {
    }

    @GetMapping("/headers/report")
    String report() {
        return "report";
    }

    @GetMapping("/uris/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/uris/public")
    String open() {
        return "open";
    }

    @GetMapping("/status")
    String status() {
        return "up";
    }
}
