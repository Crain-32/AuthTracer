package fixtures.servlethelpers;

import java.util.List;
import java.util.function.Supplier;

import jakarta.servlet.Servlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.h2.server.web.JakartaWebServlet;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Decision 0080: servlet registrations AuthTracer reads in part. One a helper builds from the servlet and paths it
 * is given; URL mappings mixing a constant with configuration; a library servlet at a path of the application's;
 * a registration from a supplier; and a servlet given only as a Servlet.
 */
@SpringBootApplication
class ServletHelpersApp {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/db/**").hasRole("DBA")
                .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    ServletRegistrationBean<LegacyServlet> legacy() {
        return register(new LegacyServlet(), "/legacy/*", "/old/*");
    }

    private static <T extends Servlet> ServletRegistrationBean<T> register(T servlet, String... urls) {
        ServletRegistrationBean<T> registration = new ServletRegistrationBean<>(servlet, urls);
        registration.setLoadOnStartup(1);
        return registration;
    }

    @Bean
    ServletRegistrationBean<ExportServlet> exports(ExportProperties properties) {
        ServletRegistrationBean<ExportServlet> registration = new ServletRegistrationBean<>(new ExportServlet());
        registration.setUrlMappings(List.of("/exports/*", properties.getArchivePath()));
        return registration;
    }

    @Bean
    ServletRegistrationBean<JakartaWebServlet> console() {
        return new ServletRegistrationBean<>(new JakartaWebServlet(), "/db/*");
    }

    @Bean
    ServletRegistrationBean<?> plugin(Supplier<ServletRegistrationBean<?>> plugins) {
        return plugins.get();
    }

    @Bean
    ServletRegistrationBean<Servlet> any(Servlet servlet) {
        return new ServletRegistrationBean<>(servlet, "/any/*");
    }
}

@ConfigurationProperties("exports")
class ExportProperties {

    private String archivePath = "/archive/*";

    public String getArchivePath() {
        return archivePath;
    }
}

class LegacyServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
    }
}

class ExportServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
    }
}
