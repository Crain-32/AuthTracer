package fixtures.textbuilders;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Values built a statement at a time with the library's mutators: text appended, elements added. Each response
 * field comes from the employee's.
 */
@SpringBootApplication
public class TextBuildersApp {
}

class Employee {

    private final String ssn;
    private final String name;

    Employee(String ssn, String name) {
        this.ssn = ssn;
        this.name = name;
    }

    public String getSsn() {
        return ssn;
    }

    public String getName() {
        return name;
    }
}

class Card {

    private String label;
    private String joined;
    private List<String> names;
    private Map<String, String> byName;

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getJoined() {
        return joined;
    }

    public void setJoined(String joined) {
        this.joined = joined;
    }

    public List<String> getNames() {
        return names;
    }

    public void setNames(List<String> names) {
        this.names = names;
    }

    public Map<String, String> getByName() {
        return byName;
    }

    public void setByName(Map<String, String> byName) {
        this.byName = byName;
    }
}

@RestController
class CardController {

    private final Employee employee = new Employee("123", "ada");

    @GetMapping("/card")
    Card card() {
        StringBuilder label = new StringBuilder();
        label.append(employee.getSsn()).append('/');
        label.append(employee.getName());
        StringJoiner joined = new StringJoiner(",");
        joined.add(employee.getSsn());
        List<String> names = new ArrayList<>();
        Collections.addAll(names, employee.getName());
        ArrayDeque<String> queue = new ArrayDeque<>();
        queue.addFirst(employee.getSsn());
        names.addAll(queue);
        Map<String, String> byName = new HashMap<>();
        byName.merge("ada", employee.getSsn(), String::concat);
        Card card = new Card();
        card.setLabel(label.toString());
        card.setJoined(joined.toString());
        card.setNames(names);
        card.setByName(byName);
        return card;
    }
}
