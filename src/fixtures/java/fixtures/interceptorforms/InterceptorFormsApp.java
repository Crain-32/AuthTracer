package fixtures.interceptorforms;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * HTTP-17: interceptor registrations AuthTracer reads only in part. Path patterns and an order from settings, an
 * exclusion it can't read, and an interceptor a factory makes, which it can't resolve.
 */
@SpringBootApplication
class InterceptorFormsApp {
}

interface InterceptorFactory {

    HandlerInterceptor create();
}

@Configuration
class FormsConfig implements WebMvcConfigurer {

    private final Environment environment;

    private final InterceptorFactory factory;

    FormsConfig(Environment environment, InterceptorFactory factory) {
        this.environment = environment;
        this.factory = factory;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new GuardInterceptor()).addPathPatterns(environment.getProperty("guard.paths"))
                .addPathPatterns("/admin/**").order(environment.getProperty("guard.order", Integer.class, 0));
        registry.addInterceptor(new MetricsInterceptor())
                .excludePathPatterns(environment.getProperty("metrics.excluded"));
        registry.addInterceptor(factory.create()).addPathPatterns("/admin/**");
    }
}

/**
 * Only runs before the handler.
 */
class GuardInterceptor implements HandlerInterceptor {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        client.get().uri("/guard").retrieve().toBodilessEntity();
        return true;
    }
}

class MetricsInterceptor implements HandlerInterceptor {

    private final RestClient client = RestClient.create("http://calls:8080");

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler,
            Exception exception) {
        client.post().uri("/metrics").retrieve().toBodilessEntity();
    }
}

class LocaleInterceptor implements HandlerInterceptor {
}

class ThemeInterceptor implements HandlerInterceptor {
}

@RestController
class FormsController {

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
