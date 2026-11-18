package fixtures.soap;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.PayloadRoots;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;
import org.springframework.ws.transport.http.MessageDispatcherServlet;

/**
 * Decision 0056: SOAP operations behind a MessageDispatcherServlet the application registers at /ws/*, as Spring's
 * guide does.
 */
@SpringBootApplication
@EnableMethodSecurity
class SoapApp {

    @Bean
    ServletRegistrationBean<MessageDispatcherServlet> messageDispatcherServlet(ApplicationContext context) {
        MessageDispatcherServlet servlet = new MessageDispatcherServlet();
        servlet.setApplicationContext(context);
        return new ServletRegistrationBean<>(servlet, "/ws/*");
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/ws/**").hasRole("PARTNER")
                .anyRequest().authenticated());
        return http.build();
    }
}

class Country {

    private String name;
    private String capital;

    public String getName() {
        return name;
    }

    public String getCapital() {
        return capital;
    }
}

@Endpoint
class CountryEndpoint {

    private static final String NAMESPACE = "http://example.com/countries";

    @PayloadRoot(namespace = NAMESPACE, localPart = "getCountryRequest")
    @ResponsePayload
    public Country getCountry(@RequestPayload Object request) {
        return new Country();
    }

    @PayloadRoot(namespace = NAMESPACE, localPart = "deleteCountryRequest")
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteCountry(@RequestPayload Object request) {
    }
}

@Endpoint
class CountryEndpointV2 {

    @PayloadRoot(namespace = "http://example.com/countries/v2", localPart = "getCountryRequest")
    @ResponsePayload
    @PreAuthorize("hasRole('V2')")
    public Country getCountry(@RequestPayload Object request) {
        return new Country();
    }

    // The same local part as CountryEndpoint's, in two namespaces: one Ingress of its own.
    @PayloadRoots({@PayloadRoot(namespace = "http://example.com/countries/v2", localPart = "deleteCountryRequest"),
            @PayloadRoot(namespace = "http://example.com/countries/v3", localPart = "deleteCountryRequest")})
    @PreAuthorize("hasRole('V2')")
    public void deleteCountry(@RequestPayload Object request) {
    }
}
