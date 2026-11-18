package fixtures.viewchoices;

import java.util.Map;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

class Person {

    private String name;

    private String ssn;

    public String getName() {
        return name;
    }

    public String getSsn() {
        return ssn;
    }
}

/**
 * A handler that fills a plain {@code Map} model and renders one of two views, and templates that show one field under
 * two different guards.
 */
@Controller
class PersonController {

    @GetMapping("/people/{id}")
    String show(@PathVariable("id") int id, Map<String, Object> model) {
        model.put("person", new Person());
        return id > 0 ? "people/card" : "people/badge";
    }
}
