package fixtures.sharedfragments;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

class Employee {

    private String name;
    private String phone;
    private String salary;

    public String getName() {
        return name;
    }

    public String getPhone() {
        return phone;
    }

    public String getSalary() {
        return salary;
    }
}

/**
 * Two views that insert one contact fragment (each at its own line, one inside a guard of its own) and show a field
 * of their own under a guard after it; a third handler renders the first view again.
 */
@Controller
class EmployeeController {

    @GetMapping("/employees/{id}")
    String summary(@PathVariable("id") int id, Model model) {
        model.addAttribute("employee", new Employee());
        return "employees/summary";
    }

    @GetMapping("/employees/{id}/print")
    String print(@PathVariable("id") int id, Model model) {
        model.addAttribute("employee", new Employee());
        return "employees/summary";
    }

    @GetMapping("/employees/{id}/profile")
    String profile(@PathVariable("id") int id, Model model) {
        model.addAttribute("employee", new Employee());
        return "employees/profile";
    }
}
