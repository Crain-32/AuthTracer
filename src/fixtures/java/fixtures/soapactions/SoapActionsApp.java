package fixtures.soapactions;

import java.util.List;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.ws.config.annotation.WsConfigurer;
import org.springframework.ws.server.EndpointInterceptor;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;
import org.springframework.ws.soap.addressing.server.annotation.Action;
import org.springframework.ws.soap.security.wss4j2.Wss4jSecurityInterceptor;
import org.springframework.ws.soap.security.wss4j2.callback.SpringSecurityPasswordValidationCallbackHandler;
import org.springframework.ws.soap.server.endpoint.annotation.SoapAction;
import org.springframework.ws.soap.server.endpoint.annotation.SoapActions;

/**
 * Decision 0056: SOAP operations mapped by their SOAP action and their WS-Addressing action, beside one mapped by its
 * payload root in two namespaces; the HTTP chain lets every SOAP request in, and WS-Security's UsernameToken, checked
 * against the UserDetailsService, authenticates each message.
 */
@SpringBootApplication
@EnableMethodSecurity
class SoapActionsApp {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/services/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }
}

@Configuration
class WsSecurityConfig implements WsConfigurer {

    private final UserDetailsService users;

    WsSecurityConfig(UserDetailsService users) {
        this.users = users;
    }

    @Override
    public void addInterceptors(List<EndpointInterceptor> interceptors) {
        interceptors.add(securityInterceptor());
    }

    @Bean
    Wss4jSecurityInterceptor securityInterceptor() {
        Wss4jSecurityInterceptor interceptor = new Wss4jSecurityInterceptor();
        interceptor.setValidationActions("UsernameToken");
        SpringSecurityPasswordValidationCallbackHandler handler = new SpringSecurityPasswordValidationCallbackHandler();
        handler.setUserDetailsService(users);
        // Its default: the user is loaded for every message.
        handler.setUserCache(new NullUserCache());
        interceptor.setValidationCallbackHandler(handler);
        return interceptor;
    }
}

@Endpoint
class OrderEndpoint {

    @SoapAction("http://example.com/orders/Cancel")
    @PreAuthorize("hasRole('CLERK')")
    public void cancel(@RequestPayload Object request) {
    }

    @Action("http://example.com/orders/Track")
    @ResponsePayload
    public Object track(@RequestPayload Object request) {
        return request;
    }

    @SoapActions({@SoapAction("urn:Archive"), @SoapAction("urn:Purge")})
    public void archive(@RequestPayload Object request) {
    }

    @PayloadRoot(namespace = "http://example.com/orders", localPart = "statusRequest")
    @ResponsePayload
    public Object status(@RequestPayload Object request) {
        return request;
    }

    @PayloadRoot(namespace = "http://example.com/legacy", localPart = "statusRequest")
    @ResponsePayload
    public Object legacyStatus(@RequestPayload Object request) {
        return request;
    }
}
