package fixtures.extraport;

import org.apache.catalina.connector.Connector;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A second, plain HTTP connector next to the configured port (as the Spring Authorization Server messages-resource
 * sample adds).
 */
@Configuration
class TomcatConfig {

    @Bean
    WebServerFactoryCustomizer<TomcatServletWebServerFactory> connectors() {
        return tomcat -> tomcat.addAdditionalConnectors(httpConnector());
    }

    private Connector httpConnector() {
        Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
        connector.setPort(8090);
        return connector;
    }
}

@RestController
class MessagesController {

    @GetMapping("/messages")
    String messages() {
        return "hi";
    }
}
