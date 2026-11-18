package fixtures.servletregistrations;

import java.util.List;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.server.servlet.context.ServletComponentScan;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.DispatcherServlet;

/**
 * Decision 0053: servlet registrations in the other shapes Spring Boot accepts: set up after the no-argument
 * constructor, a servlet bean injected into its registration, the always-map-URL constructor, a second
 * DispatcherServlet, a Struts-style extension mapping, and URL mappings from configuration.
 */
@SpringBootApplication
@ServletComponentScan
class ServletRegistrationsApp {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/status").permitAll()
                .anyRequest().hasRole("STAFF"));
        return http.build();
    }

    @Bean
    ServletRegistrationBean<StatusServlet> status() {
        ServletRegistrationBean<StatusServlet> registration = new ServletRegistrationBean<>();
        registration.setServlet(new StatusServlet());
        registration.addUrlMappings("/status", "/health/servlet");
        registration.setLoadOnStartup(1);
        return registration;
    }

    @Bean
    ServletRegistrationBean<UploadServlet> uploads(UploadServlet servlet) {
        return new ServletRegistrationBean<>(servlet, true, "/uploads/*");
    }

    /**
     * Spring MVC again, at its own path: its handlers are the controllers', not this registration's.
     */
    @Bean
    ServletRegistrationBean<DispatcherServlet> legacyApi(DispatcherServlet dispatcher) {
        return new ServletRegistrationBean<>(dispatcher, "/legacy-api/*");
    }

    @Bean
    ServletRegistrationBean<ActionServlet> actions() {
        return new ServletRegistrationBean<>(new ActionServlet(), "*.do", "/");
    }

    @Bean
    ServletRegistrationBean<ReportServlet> reports(ReportProperties properties) {
        ServletRegistrationBean<ReportServlet> registration = new ServletRegistrationBean<>(new ReportServlet());
        registration.setUrlMappings(properties.getPaths());
        return registration;
    }

    @Bean
    ServletRegistrationBean<ReportServlet> printedReports(ReportProperties properties) {
        ServletRegistrationBean<ReportServlet> registration = new ServletRegistrationBean<>(new ReportServlet());
        registration.setUrlMappings(List.of("/print", properties.getPrintPath()));
        return registration;
    }
}

@ConfigurationProperties("reports")
class ReportProperties {

    private List<String> paths = List.of("/reports/*");
    private String printPath = "/reports/print";

    public List<String> getPaths() {
        return paths;
    }

    public String getPrintPath() {
        return printPath;
    }
}

/**
 * What every page servlet of the application does on a GET, which the status servlet overrides.
 */
abstract class PageServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        render(response);
    }

    protected abstract void render(HttpServletResponse response);
}

class StatusServlet extends PageServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        doGet(response);
    }

    /**
     * Not a handler: one parameter.
     */
    void doGet(HttpServletResponse response) {
    }

    @Override
    protected void render(HttpServletResponse response) {
    }
}

@Component
class UploadServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    }
}

class ActionServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    }
}

class ReportServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
    }
}

/**
 * Every method, at a path and an extension.
 */
@WebServlet(name = "metrics", urlPatterns = {"/metrics/*", "*.metrics"})
class MetricsServlet extends HttpServlet {

    @Override
    public void service(ServletRequest request, ServletResponse response) {
    }
}
