package fixtures.rsocketopaque;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.rsocket.RSocketSecurity;
import org.springframework.security.config.annotation.rsocket.RSocketSecurity.AuthorizePayloadsSpec;
import org.springframework.security.rsocket.core.PayloadSocketAcceptorInterceptor;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.stereotype.Controller;

import reactor.core.publisher.Mono;

/**
 * RX-13: authorizePayload with rules from a bean AuthTracer can't read.
 */
@SpringBootApplication
class RSocketOpaqueApp {

    @Bean
    PayloadSocketAcceptorInterceptor rsocketInterceptor(RSocketSecurity rsocket,
            Customizer<AuthorizePayloadsSpec> rules) {
        return rsocket.authorizePayload(rules).simpleAuthentication(Customizer.withDefaults()).build();
    }
}

@Controller
class EchoController {

    @MessageMapping("echo")
    Mono<String> echo(String text) {
        return Mono.just(text);
    }
}
