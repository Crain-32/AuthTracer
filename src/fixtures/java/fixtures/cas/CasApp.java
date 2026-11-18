package fixtures.cas;

import org.apereo.cas.client.validation.Cas30ServiceTicketValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Single sign-on through a CAS server: the filter validates the service ticket, and the session keeps the user.
 */
@Configuration
@EnableWebSecurity
class CasSecurityConfig {

    @Bean
    ServiceProperties serviceProperties() {
        ServiceProperties properties = new ServiceProperties();
        properties.setService("https://app.example.com/login/cas");
        return properties;
    }

    @Bean
    CasAuthenticationProvider casAuthenticationProvider(ServiceProperties properties, UserDetailsService users) {
        CasAuthenticationProvider provider = new CasAuthenticationProvider();
        provider.setServiceProperties(properties);
        provider.setTicketValidator(new Cas30ServiceTicketValidator("https://cas.example.com/cas"));
        provider.setUserDetailsService(users);
        provider.setKey("fixture");
        return provider;
    }

    @Bean
    CasAuthenticationFilter casAuthenticationFilter(AuthenticationManager authenticationManager) {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http, CasAuthenticationFilter casFilter, ServiceProperties properties)
            throws Exception {
        CasAuthenticationEntryPoint entryPoint = new CasAuthenticationEntryPoint();
        entryPoint.setLoginUrl("https://cas.example.com/cas/login");
        entryPoint.setServiceProperties(properties);
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(entryPoint))
                .addFilter(casFilter);
        return http.build();
    }
}

@RestController
class CasController {

    @GetMapping("/inbox")
    String inbox() {
        return "inbox";
    }
}
