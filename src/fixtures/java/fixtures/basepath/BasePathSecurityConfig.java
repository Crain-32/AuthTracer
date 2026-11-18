package fixtures.basepath;

import org.springframework.boot.security.autoconfigure.web.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

/**
 * The DispatcherServlet is mapped to /mvc (application.properties), and the Builder bean adds that base path to
 * every String pattern, so "/admin/**" matches the request /mvc/admin/settings.
 */
@Configuration
class BasePathSecurityConfig {

    @Bean
    PathPatternRequestMatcher.Builder mvc() {
        return PathPatternRequestMatcher.withDefaults().basePath("/mvc");
    }

    @Bean
    WebSecurityCustomizer ignorePublic() {
        return web -> web.ignoring().requestMatchers("/public/**");
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                        .anyRequest().authenticated())
                .httpBasic(basic -> { });
        return http.build();
    }
}
