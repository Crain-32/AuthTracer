package fixtures.jspresolver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.JstlView;

/**
 * A JSP view resolver bean, configured with setters.
 */
@Configuration
class MvcConfig {

    @Bean
    ViewResolver jspViewResolver() {
        InternalResourceViewResolver resolver = new InternalResourceViewResolver();
        resolver.setViewClass(JstlView.class);
        resolver.setPrefix("/WEB-INF/jsp/");
        resolver.setSuffix(".jsp");
        resolver.setOrder(1);
        return resolver;
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
