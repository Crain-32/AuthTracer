package fixtures.servletbasepaths;

import java.io.IOException;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.security.autoconfigure.web.servlet.PathRequest;
import org.springframework.boot.web.server.servlet.context.ServletComponentScan;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The DispatcherServlet is mapped to /mvc (application.properties), a legacy servlet to /legacy/* and Boot's H2
 * console to /h2-console. The Builder
 * bean's base path is the DispatcherServlet's; the chain gets the bean and gives it the legacy servlet's base path
 * for that servlet's rule.
 */
@SpringBootApplication
@ServletComponentScan
class ServletBasePathsApp {

    @Bean
    PathPatternRequestMatcher.Builder mvc() {
        return PathPatternRequestMatcher.withDefaults().basePath("/mvc");
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http, PathPatternRequestMatcher.Builder mvc) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(mvc.basePath("/legacy").matcher("/**")).hasRole("LEGACY")
                .requestMatchers(PathRequest.toH2Console()).hasRole("DBA")
                .requestMatchers(mvc.matcher(HttpMethod.POST, "/orders/**")).hasRole("WRITER")
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated());
        return http.build();
    }
}

@WebServlet("/legacy/*")
class LegacyServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.getWriter().write("legacy");
    }
}

@RestController
class ServletBasePathsController {

    @PostMapping("/orders/new")
    String create() {
        return "created";
    }

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/legacy/report")
    String report() {
        return "served by the DispatcherServlet, at /mvc/legacy/report";
    }
}
