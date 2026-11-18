package fixtures.soapwscache;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.ws.soap.security.wss4j2.callback.SpringSecurityPasswordValidationCallbackHandler;

/**
 * Decision 0056: WS-Security's UsernameToken checked against users a cache keeps.
 */
@SpringBootApplication
class SoapWsCacheApp {

    @Bean
    SpringSecurityPasswordValidationCallbackHandler validationHandler(UserDetailsService users, UserCache cache) {
        SpringSecurityPasswordValidationCallbackHandler handler = new SpringSecurityPasswordValidationCallbackHandler();
        handler.setUserDetailsService(users);
        handler.setUserCache(cache);
        return handler;
    }
}
