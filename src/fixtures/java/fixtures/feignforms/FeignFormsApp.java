package fixtures.feignforms;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import feign.RequestInterceptor;
import feign.RequestTemplate;

/**
 * Decision 0042, the other ways Feign clients are declared: at a fixed URL, named by a placeholder, known only by a
 * context id, with a default method that isn't a request itself; and a client's configuration that is a
 * {@code @Configuration}, which component scanning puts in every client's context, its interceptor built by a helper.
 */
@FeignClient(name = "catalog", url = "http://localhost:8095", configuration = SharedFeignConfig.class)
interface CatalogClient {

    @GetMapping("/products/{id}")
    String product(@PathVariable("id") Long id);

    default String productName(Long id) {
        return product(id).strip();
    }
}

@FeignClient(name = "${stock.service}")
interface StockClient {

    @GetMapping("/stock/{id}")
    String stock(@PathVariable("id") Long id);
}

@FeignClient(contextId = "audit", url = "http://localhost:8096")
interface AuditClient {

    @GetMapping("/audit/{id}")
    String audit(@PathVariable("id") Long id);
}

@Configuration
class SharedFeignConfig {

    @Bean
    RequestInterceptor partnerCredentials() {
        return basic("partner", "secret");
    }

    /**
     * Not a bean: it builds the one partnerCredentials() returns.
     */
    private static RequestInterceptor basic(String user, String password) {
        String token = Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
        return template -> template.header("Authorization", "Basic " + token);
    }
}

/**
 * An interceptor that sets no credentials.
 */
@Component
class TracingInterceptor implements RequestInterceptor {

    @Override
    public void apply(RequestTemplate template) {
        template.header("X-Trace", "feign");
    }
}

@RestController
class CatalogController {

    private final CatalogClient catalog;
    private final StockClient stock;
    private final AuditClient audit;

    CatalogController(CatalogClient catalog, StockClient stock, AuditClient audit) {
        this.catalog = catalog;
        this.stock = stock;
        this.audit = audit;
    }

    @GetMapping("/catalog/{id}/name")
    String productName(@PathVariable("id") Long id) {
        return catalog.productName(id);
    }

    @GetMapping("/catalog/{id}")
    String product(@PathVariable("id") Long id) {
        return catalog.product(id) + stock.stock(id) + audit.audit(id);
    }
}
