package fixtures.jspconstructor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

/**
 * A JSP view resolver bean made with its prefix and suffix.
 */
@Configuration
class MvcConfig {

    @Bean
    ViewResolver jspViewResolver() {
        return new InternalResourceViewResolver("/WEB-INF/pages/", ".jsp");
    }
}

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
