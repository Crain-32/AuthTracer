package fixtures.mappedinterceptors;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.ui.ModelMap;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.context.request.WebRequestInterceptor;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.handler.MappedInterceptor;

/**
 * Decision 0070 (amended): {@code MappedInterceptor} beans, which every handler mapping runs before the
 * {@code InterceptorRegistry}'s, whatever its order says.
 */
@SpringBootApplication
class MappedInterceptorsApp implements WebMvcConfigurer {

    @Bean
    MappedInterceptor audit() {
        return new MappedInterceptor(new String[] {"/api/**"}, new AuditInterceptor());
    }

    @Bean
    MappedInterceptor trace() {
        return new MappedInterceptor(null, new String[] {"/api/public/**"}, new TraceInterceptor());
    }

    /**
     * Its HTTP methods aren't read: it may run for any request under /api.
     */
    @Bean
    MappedInterceptor posts() {
        return new MappedInterceptor(new String[] {"/api/**"}, null, new HttpMethod[] {HttpMethod.POST}, null,
                new PostInterceptor(), null);
    }

    @Bean
    MappedInterceptor views() {
        return new MappedInterceptor(new String[] {"/home"}, new ViewInterceptor());
    }

    /**
     * Spring's own: its code is no step.
     */
    @Bean
    MappedInterceptor locales() {
        return new MappedInterceptor(null, new LocaleChangeInterceptor());
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new FirstInterceptor()).order(-10);
    }
}

class ViewInterceptor implements WebRequestInterceptor {

    private final RestClient client = RestClient.builder().baseUrl("http://views:8080").build();

    @Override
    public void preHandle(WebRequest request) {
        client.post().uri("/views").retrieve().toBodilessEntity();
    }

    @Override
    public void postHandle(WebRequest request, ModelMap model) {
    }

    @Override
    public void afterCompletion(WebRequest request, Exception ex) {
    }
}

class PostInterceptor implements HandlerInterceptor {

    private final RestClient client = RestClient.builder().baseUrl("http://posts:8080").build();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        client.post().uri("/posts").retrieve().toBodilessEntity();
        return true;
    }
}

class AuditInterceptor implements HandlerInterceptor {

    private final RestClient client = RestClient.builder().baseUrl("http://audit:8080").build();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        client.post().uri("/audit").retrieve().toBodilessEntity();
        return true;
    }
}

class TraceInterceptor implements HandlerInterceptor {

    private final RestClient client = RestClient.builder().baseUrl("http://trace:8080").build();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        client.post().uri("/trace").retrieve().toBodilessEntity();
        return true;
    }
}

class FirstInterceptor implements HandlerInterceptor {

    private final RestClient client = RestClient.builder().baseUrl("http://first:8080").build();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        client.post().uri("/first").retrieve().toBodilessEntity();
        return true;
    }
}

@RestController
class ApiController {

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
