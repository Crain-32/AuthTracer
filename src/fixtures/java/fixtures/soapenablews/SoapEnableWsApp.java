package fixtures.soapenablews;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.ws.config.annotation.EnableWs;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;

/**
 * @EnableWs: Boot's web services auto-configuration backs off, and nothing registers a dispatcher servlet.
 */
@SpringBootApplication
class SoapEnableWsApp {
}

@Configuration
@EnableWs
class WsConfig {
}

@Endpoint
class PingEndpoint {

    @PayloadRoot(namespace = "http://example.com/ping", localPart = "pingRequest")
    public void ping(@RequestPayload Object request) {
    }
}
