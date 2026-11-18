package fixtures.viewtags;

import java.io.Serializable;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0081 (AUTHZ-14): views that show parts of the page by URL (Thymeleaf's sec:authorize-url, JSP's
 * {@code <sec:authorize url>}, FreeMarker's {@code <@sec.authorize url>}), which the request rules decide, and by
 * ACL ({@code sec:authorize-acl}, {@code <sec:accesscontrollist>}). Two handlers render the dashboard with different
 * models, a third with the same model as one of them. A REST controller inherits a handler that returns a string.
 */
@Configuration
@EnableWebSecurity
class ViewTagsApp {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(requests -> requests
                .requestMatchers("/admin/users/**").hasRole("USER_ADMIN")
                .requestMatchers(HttpMethod.POST, "/admin/purge").hasRole("OPS")
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()).build();
    }

    @Bean
    PermissionEvaluator permissionEvaluator() {
        return new OwnerPermissions();
    }
}

class OwnerPermissions implements PermissionEvaluator {

    @Override
    public boolean hasPermission(Authentication authentication, Object target, Object permission) {
        return false;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable id, String type, Object permission) {
        return false;
    }
}

@Controller
class DashboardController {

    @GetMapping("/dashboard")
    String dashboard(Model model) {
        model.addAttribute("report", new Report());
        model.addAttribute("band", new SalaryBand());
        return "admin/dashboard";
    }

    @GetMapping("/dashboard/lite")
    String lite(Model model) {
        model.addAttribute("report", new Report());
        return "admin/dashboard";
    }

    @GetMapping("/dashboard/print")
    String print(Model model) {
        model.addAttribute("report", new Report());
        return "admin/dashboard";
    }
}

@Controller
class ContactController {

    @GetMapping("/contacts/{id}")
    String show(Model model) {
        model.addAttribute("contact", new Contact());
        return "contacts/show";
    }
}

@Controller
class ReportController {

    @GetMapping("/reports")
    String reports(Model model) {
        model.addAttribute("report", new Report());
        return "reports/summary";
    }
}

abstract class StatusEndpoints {

    @GetMapping("/status")
    String status() {
        return "ok";
    }
}

@RestController
class StatusController extends StatusEndpoints {
}

class Report {

    private String title;
    private int headcount;
    private int purged;
    private String news;
    private String notes;

    public String getTitle() {
        return title;
    }

    public int getHeadcount() {
        return headcount;
    }

    public int getPurged() {
        return purged;
    }

    public String getNews() {
        return news;
    }

    public String getNotes() {
        return notes;
    }
}

class SalaryBand {

    private long top;

    public long getTop() {
        return top;
    }
}

class Contact {

    private long id;
    private String name;
    private String email;
    private String phone;
    private String notes;

    public long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    public String getPhone() {
        return phone;
    }

    public String getNotes() {
        return notes;
    }
}
