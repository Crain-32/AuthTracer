package fixtures.libraryauthfilters;

import jakarta.servlet.ServletContext;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.WebApplicationInitializer;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0071 (amended): Spring Security's own authenticating filters, added by hand: to a chain, as a registration
 * bean Boot puts after the chain, and to the servlet context.
 */
@Configuration
@EnableWebSecurity
class LibraryAuthFiltersApp {

    @Bean
    SecurityFilterChain api(HttpSecurity http, AuthenticationManager manager) throws Exception {
        RequestHeaderAuthenticationFilter headers = new RequestHeaderAuthenticationFilter();
        headers.setAuthenticationManager(manager);
        return http.addFilter(headers).authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .build();
    }

    @Bean
    FilterRegistrationBean<BasicAuthenticationFilter> basic(AuthenticationManager manager) {
        return new FilterRegistrationBean<>(new BasicAuthenticationFilter(manager));
    }

    @Bean
    FilterRegistrationBean<RememberMeAuthenticationFilter> rememberMe(AuthenticationManager manager) {
        FilterRegistrationBean<RememberMeAuthenticationFilter> registration = new FilterRegistrationBean<>(
                new RememberMeAuthenticationFilter(manager, new NullRememberMeServices()));
        registration.setOrder(-200);
        return registration;
    }

    @Bean
    ServletContextInitializer digest() {
        return servletContext -> servletContext.addFilter("digest", new DigestAuthenticationFilter())
                .addMappingForUrlPatterns(null, false, "/*");
    }
}

/**
 * The chain's pre-authentication filter again, ahead of it: one way in.
 */
class HeadersInitializer implements WebApplicationInitializer {

    @Override
    public void onStartup(ServletContext servletContext) {
        servletContext.addFilter("headers", RequestHeaderAuthenticationFilter.class)
                .addMappingForUrlPatterns(null, false, "/*");
    }
}

@RestController
class OrderController {

    @GetMapping("/orders")
    String orders() {
        return "orders";
    }
}
