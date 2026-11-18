package fixtures.filters;

import jakarta.servlet.Filter;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * HTTP-17: filters on the request path. Inside the API chain, one before Spring Security's AuthorizationFilter and one
 * after it; for every request, filter beans Spring Boot registers itself, before Spring Security's filter chain (an
 * {@code @Order} under -100) or after it; and a registration that narrows a filter to {@code /legacy/*}.
 */
@SpringBootApplication
class FiltersApp {
}

@Configuration
@EnableWebSecurity
class FilterChains {

    @Bean
    @Order(1)
    SecurityFilterChain api(HttpSecurity http, AuditFilter audit) throws Exception {
        return http.securityMatcher("/api/**")
                .authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .httpBasic(basic -> { })
                .addFilterBefore(new ApiKeyFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(audit, AuthorizationFilter.class)
                .build();
    }

    @Bean
    SecurityFilterChain web(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.anyRequest().permitAll()).build();
    }

    /**
     * The audit filter runs in the API chain only: this keeps Boot from registering the bean for every request too.
     */
    @Bean
    FilterRegistrationBean<AuditFilter> auditRegistration(AuditFilter audit) {
        FilterRegistrationBean<AuditFilter> registration = new FilterRegistrationBean<>(audit);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    FilterRegistrationBean<LegacyFilter> legacyRegistration() {
        FilterRegistrationBean<LegacyFilter> registration = new FilterRegistrationBean<>(new LegacyFilter());
        registration.addUrlPatterns("/legacy/*");
        registration.setOrder(5);
        return registration;
    }

    /**
     * A Filter bean: Boot registers it for every request, after Spring Security's chain (no order is the lowest).
     */
    @Bean
    Filter maintenance() {
        return new MaintenanceFilter();
    }
}
