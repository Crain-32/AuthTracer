package fixtures.eurekaheadless;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;

/**
 * Decision 0057: a Eureka server without its dashboard.
 */
@SpringBootApplication
@EnableEurekaServer
class EurekaHeadlessApp {
}
