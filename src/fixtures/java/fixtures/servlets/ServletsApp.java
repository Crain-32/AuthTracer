package fixtures.servlets;

import java.util.List;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.server.servlet.context.ServletComponentScan;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Decision 0053: a @WebServlet, a ServletRegistrationBean's servlet, and Boot's H2 console, which the chain leaves
 * open.
 */
@SpringBootApplication
@ServletComponentScan
class ServletsApp {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/h2-console/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    ServletRegistrationBean<ReportServlet> reports() {
        return new ServletRegistrationBean<>(new ReportServlet(), "/reports/*");
    }

    @Bean
    ServletRegistrationBean<ExportServlet> exports() {
        // No URL mapping: Boot maps it to /*.
        return new ServletRegistrationBean<>(new ExportServlet());
    }

    /**
     * Mapped where the environment says: not /*, and not readable.
     */
    @Bean
    ServletRegistrationBean<ArchiveServlet> archive(@Value("${archive.path}") String path) {
        return new ServletRegistrationBean<>(new ArchiveServlet(), path);
    }

    @Bean
    ServletRegistrationBean<FeedServlet> feeds() {
        ServletRegistrationBean<FeedServlet> registration = new ServletRegistrationBean<>(new FeedServlet());
        registration.setUrlMappings(List.of("/feeds/*"));
        return registration;
    }
}

@WebServlet("/legacy/*")
class LegacyServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
    }
}

class ReportServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    }
}

class BaseExportServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
    }
}

class ExportServlet extends BaseExportServlet {
}

class ArchiveServlet extends HttpServlet {

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) {
    }
}

class FeedServlet extends HttpServlet {

    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) {
    }
}
