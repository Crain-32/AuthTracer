package fixtures.interceptors;

import java.io.IOException;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.context.request.WebRequestInterceptor;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;

/**
 * HTTP-17: Spring MVC's interceptors, between the filters and the handler for the DispatcherServlet's mappings, in
 * {@code order(..)}, narrowed by path patterns; a servlet of its own passes none.
 */
@SpringBootApplication
class InterceptorsApp {

    @Bean
    ServletRegistrationBean<LegacyServlet> legacy() {
        return new ServletRegistrationBean<>(new LegacyServlet(), "/legacy/*");
    }
}

@Configuration
class WebConfig implements WebMvcConfigurer {

    private final AuditInterceptor audit;

    WebConfig(AuditInterceptor audit) {
        this.audit = audit;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new TenantInterceptor()).addPathPatterns("/api/**")
                .excludePathPatterns("/api/public/**").order(2);
        registry.addInterceptor(audit).order(1);
        registry.addInterceptor(new LocaleChangeInterceptor());
        registry.addWebRequestInterceptor(new TimingInterceptor());
    }
}

/**
 * Denies by hand before the handler, and records the request after it completes.
 */
@Component
class AuditInterceptor implements HandlerInterceptor {

    private final RestClient audit = RestClient.create("http://audit:8080");

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {
        if (!request.isUserInRole("API")) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return false;
        }
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler,
            Exception failure) {
        audit.post().uri("/audit").retrieve().toBodilessEntity();
    }
}

class TenantInterceptor implements HandlerInterceptor {

    private final RestClient tenants = RestClient.create("http://tenants:8080");

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        tenants.get().uri("/tenants").retrieve().toBodilessEntity();
        return true;
    }
}

class TimingInterceptor implements WebRequestInterceptor {

    private final RestClient timings = RestClient.create("http://timings:8080");

    @Override
    public void preHandle(WebRequest request) {
    }

    @Override
    public void postHandle(WebRequest request, ModelMap model) {
        timings.post().uri("/timings").retrieve().toBodilessEntity();
    }

    @Override
    public void afterCompletion(WebRequest request, Exception failure) {
    }
}

class LegacyServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.getWriter().write("legacy");
    }
}

@RestController
class InterceptedController {

    @GetMapping("/api/orders")
    String orders() {
        return "orders";
    }

    @GetMapping("/api/public/info")
    String info() {
        return "info";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
