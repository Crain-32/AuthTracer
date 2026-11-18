package fixtures.jacksonnames;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Getters whose names start with capitals, which Jackson 2 and Jackson 3 name differently, one of them checked.
 */
@Configuration
@EnableMethodSecurity
class JacksonNamesConfig {
}

class Person {

    private final String ssn = "123";

    @PreAuthorize("hasRole('ADMIN')")
    public String getSSN() {
        return ssn;
    }

    public String getURLValue() {
        return "url";
    }

    public String getName() {
        return "name";
    }
}

@Service
class People {

    @AuthorizeReturnObject
    public Person find() {
        return new Person();
    }
}

@RestController
class PersonController {

    private final People people;

    PersonController(People people) {
        this.people = people;
    }

    @GetMapping("/person")
    Person person() {
        return people.find();
    }
}
