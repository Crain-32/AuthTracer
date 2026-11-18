package fixtures.httpinterfaceforms;

import java.util.List;

import org.springframework.boot.restclient.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.client.support.RestTemplateAdapter;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.support.WebClientAdapter;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;
import org.springframework.web.service.registry.ImportHttpServices;
import org.springframework.web.util.DefaultUriBuilderFactory;

/**
 * HTTP interfaces, the other ways they are declared and wired: a method given as an attribute or not at all, a
 * type-level url, a method with no path, a type URL ending in a slash; imported into the default group, imported
 * nowhere, and wired by hand on a WebClient, on RestTemplates with a root URI or a DefaultUriBuilderFactory, and on
 * a client with no base URL.
 */
record Item(Long id, String name) {
}

@HttpExchange(url = "/catalog")
interface CatalogApi {

    @HttpExchange(method = "PATCH", value = "/items/{id}")
    Item rename(@PathVariable Long id, @RequestBody Item item);

    @HttpExchange("/items")
    List<Item> items();

    @GetExchange
    String index();
}

@HttpExchange("/api/")
interface UserApi {

    @GetExchange("users")
    List<String> users();
}

interface AuditApi {

    @PostExchange("/audit")
    void record(@RequestBody String entry);
}

interface PriceApi {

    @GetExchange("/prices/{sku}")
    String price(@PathVariable String sku);
}

interface StockApi {

    @GetExchange("/stock/{sku}")
    String stock(@PathVariable String sku);
}

interface ReviewApi {

    @GetExchange("/reviews")
    String reviews();

    @GetExchange
    String index();
}

interface LegacyApi {

    @GetExchange("/legacy")
    String legacy();
}

@Configuration
@ImportHttpServices(types = { CatalogApi.class, UserApi.class })
@ImportHttpServices(group = "audit", basePackages = "fixtures.elsewhere")
class ClientsConfig {

    @Bean
    PriceApi prices(WebClient.Builder builder) {
        WebClient client = builder.baseUrl("http://prices:8080").build();
        return HttpServiceProxyFactory.builderFor(WebClientAdapter.create(client)).build().createClient(PriceApi.class);
    }

    @Bean
    StockApi stock(RestTemplateBuilder builder) {
        RestTemplate template = builder.rootUri("http://stock:8080").build();
        return HttpServiceProxyFactory.builderFor(RestTemplateAdapter.create(template)).build()
                .createClient(StockApi.class);
    }

    @Bean
    ReviewApi reviews() {
        RestTemplate template = new RestTemplate();
        template.setUriTemplateHandler(new DefaultUriBuilderFactory("http://reviews:8080"));
        return HttpServiceProxyFactory.builderFor(RestTemplateAdapter.create(template)).build()
                .createClient(ReviewApi.class);
    }

    @Bean
    LegacyApi legacy(RestClient.Builder builder) {
        return HttpServiceProxyFactory.builderFor(RestClientAdapter.create(builder.build())).build()
                .createClient(LegacyApi.class);
    }
}

@RestController
class CatalogController {

    private final CatalogApi catalog;
    private final UserApi users;
    private final AuditApi audit;
    private final PriceApi prices;
    private final StockApi stock;
    private final ReviewApi reviews;
    private final LegacyApi legacy;

    CatalogController(CatalogApi catalog, UserApi users, AuditApi audit, PriceApi prices, StockApi stock,
            ReviewApi reviews, LegacyApi legacy) {
        this.catalog = catalog;
        this.users = users;
        this.audit = audit;
        this.prices = prices;
        this.stock = stock;
        this.reviews = reviews;
        this.legacy = legacy;
    }

    @PostMapping("/items/{id}")
    Item rename(@PathVariable Long id, @RequestBody Item item) {
        audit.record("rename " + id);
        return catalog.rename(id, item);
    }

    @GetMapping("/items")
    List<Item> items() {
        return catalog.items();
    }

    @GetMapping("/")
    String index() {
        return catalog.index() + users.users();
    }

    @GetMapping("/items/{sku}/details")
    String details(@PathVariable String sku) {
        return prices.price(sku) + stock.stock(sku) + reviews.reviews() + reviews.index() + legacy.legacy();
    }
}
