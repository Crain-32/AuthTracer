package fixtures.cloudclientforms;

import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Decision 0058: a config server it must reach (no {@code optional:}) at {@code spring.cloud.config.uri}, with a
 * username the environment sets, and a Eureka server it reads the registry from without registering.
 */
@SpringBootApplication
class CloudClientFormsApp {
}
