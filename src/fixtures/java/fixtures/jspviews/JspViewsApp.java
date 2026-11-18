package fixtures.jspviews;

import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * JSP views (spring.mvc.view.prefix/suffix), with JSTL and Spring Security's taglib.
 */
record Contact(Long id, String name, String email, String phone) {
}

@Service
class ContactService {

    List<Contact> all() {
        return List.of(new Contact(1L, "ann", "a@x", "1"));
    }
}

@Controller
class ContactController {

    private final ContactService contacts;

    ContactController(ContactService contacts) {
        this.contacts = contacts;
    }

    @GetMapping("/contacts")
    String contacts(Model model) {
        model.addAttribute("contacts", contacts.all());
        return "index";
    }
}
