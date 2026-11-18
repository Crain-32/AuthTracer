package fixtures.jsonviews;

import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @JsonView: each handler writes only the fields in its view (and the views it extends).
 */
final class Views {

    interface Summary {
    }

    interface Detail extends Summary {
    }

    private Views() {
    }
}

class Employee {

    @JsonView(Views.Summary.class)
    private String name;

    @JsonView(Views.Detail.class)
    private long salary;

    private String ssn;

    public String getName() {
        return name;
    }

    public long getSalary() {
        return salary;
    }

    public String getSsn() {
        return ssn;
    }
}

@RestController
class EmployeeController {

    @GetMapping("/employees/summary")
    @JsonView(Views.Summary.class)
    Employee summary() {
        return new Employee();
    }

    @GetMapping("/employees/detail")
    @JsonView(Views.Detail.class)
    Employee detail() {
        return new Employee();
    }

    @GetMapping("/employees/raw")
    Employee raw() {
        return new Employee();
    }
}
