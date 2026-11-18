package fixtures.servletmappings;

import java.io.IOException;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.server.servlet.context.ServletComponentScan;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Decision 0112: an extension mapping takes every path that ends in it, under whichever rule that path gets; the
 * default servlet takes what no other mapping does, and here the DispatcherServlet claims / too.
 */
@SpringBootApplication
@ServletComponentScan
class ServletMappingsApp {

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    ServletRegistrationBean<ExportServlet> exports() {
        return new ServletRegistrationBean<>(new ExportServlet(), "*.csv");
    }
}

/**
 * Writes every user's data: /public/users.csv is under the permitAll rule.
 */
class ExportServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.getWriter().write("users");
    }
}

@WebServlet("/")
class FallbackServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.getWriter().write("fallback");
    }
}
