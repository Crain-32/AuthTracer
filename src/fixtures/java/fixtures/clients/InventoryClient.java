package fixtures.clients;

import java.util.List;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;

@HttpExchange("/inventory")
interface InventoryClient {

    @GetExchange("/stock/{sku}")
    List<Stock> stock(@PathVariable String sku);

    @PostExchange("/reservations/{sku}")
    void reserve(@PathVariable String sku);

    /**
     * No leading slash: Spring puts one between the interface's URL and this.
     */
    @GetExchange("levels/{sku}")
    String level(@PathVariable String sku);
}
