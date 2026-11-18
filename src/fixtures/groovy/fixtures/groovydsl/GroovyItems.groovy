package fixtures.groovydsl

import groovy.transform.CompileStatic
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestClient
import org.springframework.web.service.annotation.PostExchange

class Item {
    long id
    String name
    String supplierCode
}

class ItemView {
    long id
    String name
    String supplier
}

/**
 * Dynamic Groovy over a RestClient: past client.post() the chain is untyped.
 */
@Component
class InventoryClient {

    private final RestClient client

    InventoryClient(RestClient.Builder builder, @Value('${inventory.base-url}') String baseUrl) {
        client = builder.baseUrl(baseUrl).build()
    }

    String reserve(long id) {
        client.post().uri('/inventory/{id}/reserve', id).retrieve().body(String)
    }
}

interface InventoryApi {

    @PostExchange('/inventory/{id}/release')
    String release(@PathVariable('id') long id)
}

@Service
class ItemService {

    private final InventoryClient inventory
    private final InventoryApi api

    ItemService(InventoryClient inventory, InventoryApi api) {
        this.inventory = inventory
        this.api = api
    }

    @PreAuthorize("hasAuthority('SCOPE_items.read')")
    Item find(long id) {
        new Item(id: id, name: 'bolt', supplierCode: 'ACME-1')
    }

    @PreAuthorize("hasRole('ADMIN')")
    String reserve(long id) {
        inventory.reserve(id)
    }

    @PreAuthorize("hasRole('ADMIN')")
    String release(long id) {
        api.release(id)
    }

    /** Calls find on this, past Spring's proxy. */
    Item first(long id) {
        find(id)
    }

    /** A closure calls find on its owner, past Spring's proxy too. */
    List<Item> each(List<Long> ids) {
        ids.collect { find(it) }
    }
}

@CompileStatic
@Service
class StaticItemService {

    private final InventoryClient inventory

    StaticItemService(InventoryClient inventory) {
        this.inventory = inventory
    }

    @PreAuthorize("hasRole('ADMIN')")
    String reserve(long id) {
        inventory.reserve(id)
    }
}

@RestController
class ItemController {

    private final ItemService items
    private final StaticItemService staticItems

    ItemController(ItemService items, StaticItemService staticItems) {
        this.items = items
        this.staticItems = staticItems
    }

    @GetMapping('/items/{id}')
    ItemView get(@PathVariable('id') long id) {
        Item item = items.find(id)
        new ItemView(id: item.id, name: item.name, supplier: item.supplierCode)
    }

    @GetMapping('/items/{id}/first')
    Item first(@PathVariable('id') long id) {
        items.first(id)
    }

    @GetMapping('/items/each')
    List<Item> each() {
        items.each([1L])
    }

    @PostMapping('/items/{id}/reserve')
    String reserve(@PathVariable('id') long id) {
        items.reserve(id)
    }

    /** The closure's body runs on the request path: items.find's check applies. */
    @GetMapping('/items')
    List<Item> some() {
        [1L, 2L].collect { items.find(it) }
    }

    @PostMapping('/items/{id}/release')
    String release(@PathVariable('id') long id) {
        items.release(id)
    }

    @CompileStatic
    @PostMapping('/items/{id}/reserve-static')
    String reserveStatic(@PathVariable('id') long id) {
        staticItems.reserve(id)
    }

    @GetMapping('/info')
    String info() {
        'info'
    }

    @GetMapping('/status')
    String status() {
        'up'
    }

    @GetMapping('/reports/public')
    String publicReport() {
        'public'
    }

    @GetMapping('/reports/daily')
    String dailyReport() {
        'daily'
    }

    @GetMapping('/exports/all')
    String exportAll() {
        'all'
    }

    @GetMapping('/audit/log')
    String audit() {
        'log'
    }
}

@CompileStatic
@Component
class StaticInventoryClient {

    private final RestClient client

    StaticInventoryClient(RestClient.Builder builder, @Value('${inventory.base-url}') String baseUrl) {
        client = builder.baseUrl(baseUrl).build()
    }

    String count(long id) {
        client.get().uri('/inventory/{id}/count', id).retrieve().body(String)
    }
}

/**
 * Statically compiled: the RestClient chain and the named-argument constructors are ordinary calls.
 */
@CompileStatic
@RestController
class StaticItemController {

    private final StaticInventoryClient inventory

    StaticItemController(StaticInventoryClient inventory) {
        this.inventory = inventory
    }

    @GetMapping('/static/items/{id}')
    ItemView get(@PathVariable('id') long id) {
        Item item = new Item(id: id, name: 'bolt', supplierCode: 'ACME-1')
        new ItemView(id: item.id, name: item.name, supplier: item.supplierCode)
    }

    @GetMapping('/static/items/{id}/count')
    String count(@PathVariable('id') long id) {
        inventory.count(id)
    }
}
