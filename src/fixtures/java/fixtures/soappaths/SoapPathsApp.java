package fixtures.soappaths;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.transport.http.MessageDispatcherServlet;

/**
 * Decision 0056: a MessageDispatcherServlet given to its registration with setServlet, at two paths the rules treat
 * differently, so its operations are as open as the more open path.
 */
@SpringBootApplication
class SoapPathsApp {

    @Bean
    ServletRegistrationBean<?> messageDispatcherServlet() {
        ServletRegistrationBean<MessageDispatcherServlet> registration = new ServletRegistrationBean<>();
        registration.setServlet(new MessageDispatcherServlet());
        registration.addUrlMappings("/ws/*", "/soap/*");
        return registration;
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/ws/**").hasRole("PARTNER")
                .anyRequest().authenticated());
        return http.build();
    }
}

@Endpoint
class PingEndpoint {

    @PayloadRoot(namespace = "http://example.com/ping", localPart = "pingRequest")
    public void ping(@RequestPayload Object request) {
    }
}
