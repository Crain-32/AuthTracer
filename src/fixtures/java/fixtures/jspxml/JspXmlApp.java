package fixtures.jspxml;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * A classic Spring MVC application: its JSP view resolver is a bean in servlet-context.xml.
 */

record Member(String name, String email) {
}

@Controller
class MemberController {

    @GetMapping("/members/me")
    String me(Model model) {
        model.addAttribute("member", new Member("ann", "ann@example.com"));
        return "members/me";
    }
}
