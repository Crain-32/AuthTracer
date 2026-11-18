package fixtures.recursivemappers;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Two mappers that call each other: whichever endpoint is read first, each view's fields come from the employee's.
 */
@SpringBootApplication
public class RecursiveMappersApp {
}

class Employee {

    private final String ssn;
    private final String name;
    private final Employee manager;

    Employee(String ssn, String name, Employee manager) {
        this.ssn = ssn;
        this.name = name;
        this.manager = manager;
    }

    public String getSsn() {
        return ssn;
    }

    public String getName() {
        return name;
    }

    public Employee getManager() {
        return manager;
    }
}

record EmployeeView(String ssn, ManagerView manager) {
}

record ManagerView(String name, EmployeeView self) {
}

@RestController
class PeopleController {

    private final Employee employee = new Employee("1", "ada", new Employee("2", "bob", null));

    @GetMapping("/employee")
    EmployeeView employee() {
        return toView(employee);
    }

    @GetMapping("/manager")
    ManagerView manager() {
        return toManager(employee);
    }

    EmployeeView toView(Employee from) {
        return new EmployeeView(from.getSsn(), from.getManager() == null ? null : toManager(from.getManager()));
    }

    ManagerView toManager(Employee from) {
        return new ManagerView(from.getName(), from.getManager() == null ? null : toView(from));
    }
}
