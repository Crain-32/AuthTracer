package fixtures.soapsupport;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.ws.config.annotation.WsConfigurationSupport;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;

/**
 * Decision 0056: Spring Web Services configured by extending WsConfigurationSupport, which Boot's auto-configuration
 * backs off for, and no dispatcher servlet registered.
 */
@SpringBootApplication
class SoapSupportApp {
}

@Configuration
class WsConfig extends WsConfigurationSupport {
}

@Endpoint
class PingEndpoint {

    @PayloadRoot(namespace = "http://example.com/ping", localPart = "pingRequest")
    public void ping(@RequestPayload Object request) {
    }
}
