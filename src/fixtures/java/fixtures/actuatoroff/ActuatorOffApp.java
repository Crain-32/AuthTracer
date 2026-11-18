package fixtures.actuatoroff;

import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Every endpoint exposed, but management.server.port=-1 turns Actuator's HTTP endpoints off.
 */
@SpringBootApplication
class ActuatorOffApp {
}
