package fixtures.orders;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/orders")
class OrderController {

    private final OrderService orders;
    private final RemoteInventory inventory;

    OrderController(OrderService orders, RemoteInventory inventory) {
        this.orders = orders;
        this.inventory = inventory;
    }

    @GetMapping("/{id}")
    Order get(@PathVariable long id) {
        return orders.find(id);
    }

    @PostMapping
    Order create(@RequestBody Order order) {
        Order created = orders.create(order);
        inventory.reserve(created.sku());
        return created;
    }

    @DeleteMapping("/{id}")
    void delete(@PathVariable long id) {
        orders.delete(id);
    }

    @GetMapping("/{id}/stock")
    Integer stock(@PathVariable long id) {
        return inventory.stock(orders.find(id).sku());
    }

    @GetMapping("/{id}/summary")
    String summary(@PathVariable long id) {
        return orders.summary(id);
    }

    @GetMapping("/{id}/note")
    String note(@PathVariable long id) {
        return new OrderNote("note " + id).getText();
    }

    @RequestMapping(path = "/legacy", method = { RequestMethod.GET, RequestMethod.HEAD })
    String legacy() {
        return "legacy";
    }
}
