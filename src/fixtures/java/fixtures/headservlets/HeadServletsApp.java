package fixtures.headservlets;

import java.io.IOException;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Decision 0110: HttpServlet#doHead runs doGet, unless the servlet overrides it; a rule for GET doesn't match HEAD.
 */
@Configuration
@EnableWebSecurity
class HeadServletsConfig {

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(HttpMethod.GET, "/files/**").hasRole("ADMIN")
                .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    ServletRegistrationBean<FilesServlet> files() {
        return new ServletRegistrationBean<>(new FilesServlet(), "/files/*");
    }

    @Bean
    ServletRegistrationBean<StatusServlet> status() {
        return new ServletRegistrationBean<>(new StatusServlet(), "/files/status");
    }
}

/**
 * HEAD runs its doGet.
 */
class FilesServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.getWriter().write("files");
    }
}

/**
 * HEAD runs its own doHead.
 */
class StatusServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.getWriter().write("status");
    }

    @Override
    protected void doHead(HttpServletRequest request, HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_OK);
    }
}
