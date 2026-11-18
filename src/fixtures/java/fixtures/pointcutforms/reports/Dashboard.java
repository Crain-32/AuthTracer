package fixtures.pointcutforms.reports;

import org.springframework.stereotype.Component;

@Component
public class Dashboard {

    public String summary() {
        return "summary";
    }

    public String health() {
        return "up";
    }
}
