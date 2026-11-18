package fixtures.schedules;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Decision 0046: a task on two schedules, which javac puts in their {@code @Schedules} container.
 */
@SpringBootApplication
@EnableScheduling
class SchedulesApp {
}

@Component
class Backups {

    @Scheduled(cron = "0 0 1 * * MON-FRI")
    @Scheduled(cron = "0 0 6 * * SAT")
    public void snapshot() {
    }
}
