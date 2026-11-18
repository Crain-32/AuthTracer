package fixtures.ignoringforms;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * WebSecurityCustomizer beans: one sets the firewall and ignores nothing; the other ignores a path and, through a
 * RequestMatcher AuthTracer can't evaluate, the load balancer's probes.
 */
@Configuration
@EnableWebSecurity
class IgnoringFormsConfig {

    @Bean
    WebSecurityCustomizer firewall() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setAllowSemicolon(true);
        return web -> web.httpFirewall(firewall);
    }

    @Bean
    WebSecurityCustomizer ignoring() {
        return web -> web.ignoring()
                .requestMatchers("/assets/**")
                .requestMatchers(request -> "probe".equals(request.getHeader("User-Agent")));
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class IgnoringFormsController {

    @GetMapping("/assets/logo")
    String logo() {
        return "logo";
    }

    @GetMapping("/orders")
    String orders() {
        return "orders";
    }
}
