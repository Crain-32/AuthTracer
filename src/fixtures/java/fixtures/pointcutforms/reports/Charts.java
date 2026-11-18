package fixtures.pointcutforms.reports;

import org.springframework.stereotype.Component;

@Component
public class Charts {

    public String render() {
        return "chart";
    }
}
