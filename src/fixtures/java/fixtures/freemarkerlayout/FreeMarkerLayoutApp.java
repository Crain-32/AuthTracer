package fixtures.freemarkerlayout;

import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

/**
 * FreeMarker views under a template loader path of the application's own (views, no trailing slash), written with a
 * layout macro, captured assignments, Spring's form macros and URL-based authorize tags.
 */
record Visit(String date, String description, String diagnosis) {
}

record Owner(Long id, String lastName, String telephone, String notes, List<Visit> visits) {
}

@Controller
class OwnerController {

    @GetMapping("/owners/{id}")
    String show(@PathVariable("id") long id, Model model) {
        model.addAttribute("owner", new Owner(id, "Davis", "555", "allergic", List.of()));
        return "owners/show";
    }
}
