package fixtures.clients;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ClientsController {

    private final TemplateCatalog catalog;
    private final ReactivePricing pricing;
    private final PartnerCalls partners;
    private final InventoryClient inventory;
    private final VersionedOrders orders;
    private final TwoServices services;

    ClientsController(TemplateCatalog catalog, ReactivePricing pricing, InventoryClient inventory,
            PartnerCalls partners, VersionedOrders orders, TwoServices services) {
        this.catalog = catalog;
        this.pricing = pricing;
        this.partners = partners;
        this.inventory = inventory;
        this.orders = orders;
        this.services = services;
    }

    @GetMapping("/users/{id}/purchases/{purchase}")
    String userPurchase(@PathVariable String id, @PathVariable String purchase) {
        return services.user(id) + services.purchase(purchase);
    }

    @GetMapping("/orders/{id}")
    String order(@PathVariable String id) {
        return orders.order(id);
    }

    @GetMapping("/products/{id}")
    Product product(@PathVariable String id) {
        catalog.archive(id);
        catalog.touch(id);
        return catalog.product(id);
    }

    @GetMapping("/products/{id}/price")
    Price price(@PathVariable String id) {
        pricing.history(id);
        return pricing.price(id);
    }

    @GetMapping("/partners/{id}")
    String partner(@PathVariable String id) {
        return partners.partner(id);
    }

    @GetMapping("/prices/current")
    Price currentPrice() {
        return pricing.current();
    }

    @GetMapping("/products/{id}/stock")
    List<Stock> stock(@PathVariable String id) {
        inventory.reserve(id);
        inventory.level(id);
        return inventory.stock(id);
    }
}
