package fixtures.soapunregistered;

import org.springframework.context.annotation.Configuration;
import org.springframework.ws.config.annotation.EnableWs;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;

/**
 * Decision 0080: Spring Web Services without Spring Boot and without anything AuthTracer reads that registers its
 * dispatcher servlet (a web.xml would).
 */
@Configuration
@EnableWs
class SoapUnregisteredConfig {
}

@Endpoint
class PingEndpoint {

    @PayloadRoot(namespace = "http://example.com/ping", localPart = "pingRequest")
    public void ping(@RequestPayload Object request) {
    }
}
