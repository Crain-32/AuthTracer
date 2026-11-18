package fixtures.actuatorport;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.metrics.buffering.BufferingApplicationStartup;

/**
 * Actuator on a port of its own, under management.server.base-path; main buffers the startup steps, so the startup
 * endpoint is there.
 */
@SpringBootApplication
class ActuatorPortApp {

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(ActuatorPortApp.class);
        app.setApplicationStartup(new BufferingApplicationStartup(2048));
        app.run(args);
    }
}
