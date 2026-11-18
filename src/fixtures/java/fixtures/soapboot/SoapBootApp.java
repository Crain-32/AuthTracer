package fixtures.soapboot;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;

/**
 * Decision 0056: Spring Boot's dispatcher servlet at spring.webservices.path, and Boot's default security.
 */
@SpringBootApplication
class SoapBootApp {
}

@Endpoint
class PingEndpoint {

    @PayloadRoot(namespace = "http://example.com/ping", localPart = "pingRequest")
    public void ping(@RequestPayload Object request) {
    }
}
