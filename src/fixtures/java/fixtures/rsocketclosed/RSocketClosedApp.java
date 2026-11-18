package fixtures.rsocketclosed;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.rsocket.RSocketSecurity;
import org.springframework.security.rsocket.core.PayloadSocketAcceptorInterceptor;
import org.springframework.stereotype.Controller;

import reactor.core.publisher.Mono;

/**
 * RX-13: authorizePayload with no rules: no exchange matches one, so every one is denied.
 */
@SpringBootApplication
class RSocketClosedApp {

    @Bean
    PayloadSocketAcceptorInterceptor rsocketInterceptor(RSocketSecurity rsocket) {
        return rsocket.authorizePayload(authorize -> {
        }).simpleAuthentication(Customizer.withDefaults()).build();
    }
}

@Controller
class EchoController {

    @MessageMapping("echo")
    Mono<String> echo(String text) {
        return Mono.just(text);
    }
}
