package fixtures.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import feign.RequestInterceptor;

/**
 * Spring Cloud OpenFeign clients: one at a configured URL, one found by service name; a RequestInterceptor relays
 * the caller's token.
 */
record Item(Long id, String name) {
}

record Price(String sku, long cents) {
}

@FeignClient(name = "inventory", url = "${inventory.url}", path = "/api")
interface InventoryClient {

    @GetMapping("/items/{id}")
    Item item(@PathVariable("id") Long id);

    @PostMapping("/items")
    Item create(@RequestBody Item item);
}

@FeignClient("pricing")
interface PricingClient {

    @GetMapping("/prices/{sku}")
    Price price(@PathVariable("sku") String sku);
}

/**
 * Reports are fetched with the shop's own token: this configuration isn't a component, so only the client that
 * lists it uses its interceptor.
 */
@FeignClient(name = "reports", configuration = ReportsFeignConfig.class)
interface ReportsClient {

    @GetMapping("/reports/{id}")
    String report(@PathVariable("id") Long id);
}

class ReportsFeignConfig {

    @Bean
    RequestInterceptor serviceToken(OAuth2AuthorizedClientManager manager) {
        return template -> {
            OAuth2AuthorizedClient client = manager.authorize(
                    OAuth2AuthorizeRequest.withClientRegistrationId("reports").principal("shop").build());
            template.header("Authorization", "Bearer " + client.getAccessToken().getTokenValue());
        };
    }
}

@Configuration
class FeignConfig {

    @Bean
    RequestInterceptor bearerRelay() {
        return template -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication instanceof JwtAuthenticationToken jwt) {
                template.header("Authorization", "Bearer " + jwt.getToken().getTokenValue());
            }
        };
    }
}

@RestController
class ShopController {

    private final InventoryClient inventory;
    private final PricingClient pricing;
    private final ReportsClient reports;

    ShopController(InventoryClient inventory, PricingClient pricing, ReportsClient reports) {
        this.inventory = inventory;
        this.pricing = pricing;
        this.reports = reports;
    }

    @GetMapping("/shop/items/{id}")
    Item item(@PathVariable("id") Long id) {
        return inventory.item(id);
    }

    @PostMapping("/shop/items")
    Item create(@RequestBody Item item) {
        return inventory.create(item);
    }

    @GetMapping("/shop/prices/{sku}")
    Price price(@PathVariable("sku") String sku) {
        return pricing.price(sku);
    }

    @GetMapping("/shop/reports/{id}")
    String report(@PathVariable("id") Long id) {
        return reports.report(id);
    }
}
