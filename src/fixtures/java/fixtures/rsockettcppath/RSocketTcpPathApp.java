package fixtures.rsockettcppath;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.stereotype.Controller;

import reactor.core.publisher.Mono;

/**
 * Decision 0045: a mapping path with the TCP transport and no port. Boot 4.1 serves RSocket at a mapping path only over
 * WebSocket, and starts its own server only on a port, so it starts none.
 */
@SpringBootApplication
class RSocketTcpPathApp {
}

@Controller
class HelloController {

    @MessageMapping("hello")
    Mono<String> hello(String name) {
        return Mono.just("Hello " + name);
    }
}
