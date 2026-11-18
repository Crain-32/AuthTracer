package fixtures.jspregistrypaths;

import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.config.annotation.ViewResolverRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * JSP views where the registry is told to look.
 */
@Configuration
class MvcConfig implements WebMvcConfigurer {

    @Override
    public void configureViewResolvers(ViewResolverRegistry registry) {
        registry.jsp("/WEB-INF/views/", ".jsp");
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
