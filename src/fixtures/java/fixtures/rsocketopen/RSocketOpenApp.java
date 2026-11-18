package fixtures.rsocketopen;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.rsocket.RSocketSecurity;
import org.springframework.security.rsocket.core.PayloadSocketAcceptorInterceptor;
import org.springframework.stereotype.Controller;

import reactor.core.publisher.Mono;

/**
 * RX-13: an interceptor that authenticates but never calls authorizePayload, so nothing is authorized.
 */
@SpringBootApplication
class RSocketOpenApp {

    @Bean
    PayloadSocketAcceptorInterceptor rsocketInterceptor(RSocketSecurity rsocket) {
        return rsocket.simpleAuthentication(Customizer.withDefaults()).build();
    }
}

@Controller
class EchoController {

    @MessageMapping("echo")
    Mono<String> echo(String text) {
        return Mono.just(text);
    }
}
