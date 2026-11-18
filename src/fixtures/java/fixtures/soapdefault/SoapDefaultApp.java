package fixtures.soapdefault;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.transport.http.MessageDispatcherServlet;

/**
 * Decision 0056: a MessageDispatcherServlet bean registered as the default servlet: the registration's type argument
 * says what it registers.
 */
@SpringBootApplication
class SoapDefaultApp {

    @Bean
    MessageDispatcherServlet dispatcher() {
        return new MessageDispatcherServlet();
    }

    @Bean
    ServletRegistrationBean<MessageDispatcherServlet> messageDispatcherServlet(MessageDispatcherServlet servlet) {
        return new ServletRegistrationBean<>(servlet, "/");
    }
}

@Endpoint
class QuoteEndpoint {

    @PayloadRoot(namespace = "http://example.com/quotes", localPart = "quoteRequest")
    public void quote(@RequestPayload Object request) {
    }
}
