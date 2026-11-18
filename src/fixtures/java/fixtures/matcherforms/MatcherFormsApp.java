package fixtures.matcherforms;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP-06: more of the shapes RequestMatcher lambdas take: a parameter's absence, an exact path, a negated prefix, a
 * helper predicate and a method reference to one, a case-insensitive method, either of two methods, a raw URI
 * compared whole, a header tested by a utility, and a suffix test AuthTracer doesn't read.
 */
@Configuration
@EnableWebSecurity
class MatcherFormsConfig {

    @Bean
    @Order(1)
    SecurityFilterChain params(HttpSecurity http) throws Exception {
        http.securityMatcher("/params/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(request -> request.getParameter("debug") == null).hasRole("USER")
                        .anyRequest().permitAll());
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain paths(HttpSecurity http) throws Exception {
        http.securityMatcher("/paths/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(request -> request.getServletPath().equals("/paths/exact")).hasRole("EXACT")
                        .requestMatchers(request -> !request.getServletPath().startsWith("/paths/api"))
                        .hasRole("OTHER")
                        .requestMatchers(request -> isAdminPath(request)).hasRole("ADMIN")
                        .requestMatchers(MatcherFormsConfig::isTenantPath).hasRole("TENANT")
                        .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    @Order(3)
    SecurityFilterChain verbs(HttpSecurity http) throws Exception {
        http.securityMatcher("/verbs/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(request -> request.getMethod().equalsIgnoreCase("patch")).hasRole("EDITOR")
                        .requestMatchers(request -> "GET".equals(request.getMethod())
                                || "HEAD".equals(request.getMethod())).hasRole("READER")
                        .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    @Order(4)
    SecurityFilterChain raw(HttpSecurity http) throws Exception {
        http.securityMatcher("/raw/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(request -> request.getRequestURI().equals("/raw/report")).hasRole("AUDITOR")
                        .requestMatchers(request -> StringUtils.hasText(request.getHeader("X-Trace"))).permitAll()
                        .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    @Order(5)
    SecurityFilterChain files(HttpSecurity http) throws Exception {
        http.securityMatcher("/files/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(request -> request.getServletPath().endsWith(".json")).permitAll()
                        .anyRequest().hasRole("FILES"));
        return http.build();
    }

    static boolean isAdminPath(HttpServletRequest request) {
        return request.getServletPath().startsWith("/paths/api/admin");
    }

    static boolean isTenantPath(HttpServletRequest request) {
        return request.getServletPath().startsWith("/paths/api/tenants/");
    }
}

@RestController
class MatcherFormsController {

    @GetMapping("/params/report")
    String report() {
        return "report";
    }

    @GetMapping("/paths/exact")
    String exact() {
        return "exact";
    }

    @GetMapping("/paths/exact/{id}")
    String exactChild(@PathVariable String id) {
        return id;
    }

    @GetMapping("/paths/other")
    String other() {
        return "other";
    }

    @GetMapping("/paths/api/admin/users")
    String admins() {
        return "admins";
    }

    @GetMapping("/paths/api/tenants/{tenant}")
    String tenant(@PathVariable String tenant) {
        return tenant;
    }

    @GetMapping("/paths/api/{area}/users")
    String area(@PathVariable String area) {
        return area;
    }

    @PatchMapping("/verbs/item")
    String patch() {
        return "patched";
    }

    @GetMapping("/verbs/item")
    String read() {
        return "item";
    }

    @RequestMapping("/verbs/any")
    String any() {
        return "any";
    }

    @GetMapping("/raw/report")
    String raw() {
        return "raw";
    }

    @GetMapping("/files/list")
    String files() {
        return "files";
    }
}
