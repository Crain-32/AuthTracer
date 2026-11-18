package fixtures.typedbodies;

import java.util.List;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

record Employee(String name) {
}

/**
 * A response body whose type is generic: named by an anonymous ParameterizedTypeReference subclass.
 */
@RestController
class StaffController {

    private final RestClient directory = RestClient.create("http://directory:8080");

    @GetMapping("/staff")
    List<Employee> staff() {
        return directory.get().uri("/employees").retrieve().body(new ParameterizedTypeReference<List<Employee>>() {
        });
    }
}
