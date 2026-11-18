package fixtures.groovycalls

import org.springframework.context.annotation.Configuration
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RestController

@Configuration
@EnableMethodSecurity
class MethodSecurityConfig {
}

class Item {
    long id
    String name
}

class ItemView {
    String label
}

@Service
class ItemService {

    @PreAuthorize("hasRole('READER')")
    Item find(long id) {
        new Item(id: id, name: 'bolt')
    }

    @PreAuthorize("hasRole('DESCRIBE')")
    String describe(Item item) {
        item?.name
    }

    /** Groovy passes a varargs method's arguments one by one. */
    @PreAuthorize("hasRole('MANY')")
    List<Item> findAll(long... ids) {
        ids.collect { find(it) }
    }

    @PreAuthorize("hasRole('BATCH')")
    List<Item> eachOf(List<Long> ids, Closure work) {
        ids.collect(work)
    }

    /** Both take a String: Groovy runs the most specific, as the call site's types say. */
    @PreAuthorize("hasRole('NAMES')")
    String lookup(String name) {
        name
    }

    @PreAuthorize("hasRole('TEXT')")
    Integer lookup(CharSequence text) {
        text.length()
    }

    /** Overloads a closure's call can't tell apart: Groovy decides at run time. */
    @PreAuthorize("hasRole('LISTS')")
    String report(List<Long> ids, Closure format) {
        format(ids)
    }

    @PreAuthorize("hasRole('SETS')")
    String report(Set<Long> ids, Closure format) {
        format(ids)
    }
}

/** A cache that is a map: its methods are the library's. */
@Component
class ItemCache extends LinkedHashMap<Long, Item> {
}

/** Inherits eachOf. */
@Service
class AdminItemService extends ItemService {
}

interface Auditor {

    Object record(String action, Closure work)
}

@Component
class LogAuditor implements Auditor {

    @PreAuthorize("hasRole('AUDITOR')")
    Object record(String action, Closure work) {
        work()
    }
}

class Batches {

    /** A static helper handed the service it calls. */
    static Object inTurn(ItemService items, long id, Closure after) {
        items.find(id)
        after()
    }
}

/**
 * Dynamic calls that pass a closure stay dynamic: they run the method their receiver's type and name give.
 */
@RestController
class BatchController {

    private final ItemService items
    private final AdminItemService adminItems
    private final Auditor auditor
    private final ItemCache cache

    BatchController(ItemService items, AdminItemService adminItems, Auditor auditor, ItemCache cache) {
        this.items = items
        this.adminItems = adminItems
        this.auditor = auditor
        this.cache = cache
    }

    /** A property only a getter gives. */
    ItemService getCatalogue() {
        items
    }

    @GetMapping('/batch')
    List<Item> batch() {
        items.eachOf([1L, 2L]) { it }
    }

    @GetMapping('/admin/batch')
    List<Item> adminBatch() {
        adminItems.eachOf([1L]) { it }
    }

    @GetMapping('/audited/{id}')
    Object audited(@PathVariable('id') long id) {
        auditor.record('read') { id }
    }

    @GetMapping('/turns/{id}')
    Object turns(@PathVariable('id') long id) {
        Batches.inTurn(items, id) { 'done' }
    }

    @GetMapping('/names/{name}')
    String name(@PathVariable('name') String name) {
        items.lookup(name)
    }

    @GetMapping('/report')
    String report() {
        items.report([1L]) { it.toString() }
    }

    @GetMapping('/all/{id}')
    List<Item> all(@PathVariable('id') long id) {
        items.findAll(id)
    }

    /** A constant int for a long parameter, and null for an object one. */
    @GetMapping('/constants')
    String constants() {
        items.find(42)
        items.describe(null)
    }

    /** The closure reads the controller's getter-only property. */
    @GetMapping('/catalogue')
    List<Item> catalogue() {
        [1L].collect { catalogue.find(it) }
    }

    /** A call in a try block, whose catch block returns instead. */
    @GetMapping('/tried/{id}')
    Item tried(@PathVariable('id') long id) {
        try {
            items.find(id)
        }
        catch (IllegalStateException ex) {
            null
        }
    }

    /** A property set by assignment, as its setter sets it. */
    @GetMapping('/views/{id}')
    ItemView view(@PathVariable('id') long id) {
        Item item = items.find(id)
        ItemView view = new ItemView()
        view.label = item.name
        view
    }

    /** A Java object's property, set by assignment too. */
    @GetMapping('/labels/{id}')
    Label label(@PathVariable('id') long id) {
        Item item = items.find(id)
        Label label = new Label()
        label.text = item.name
        label
    }

    /** with is Groovy's, on every object: the closure runs here. */
    @GetMapping('/items/{id}')
    Item item(@PathVariable('id') long id) {
        Item item = new Item(id: id)
        item.with { items.find(id) }
    }

    /** computeIfAbsent is the map's, which runs the closure. */
    @GetMapping('/cached/{id}')
    Item cached(@PathVariable('id') long id) {
        cache.computeIfAbsent(id) { items.find(it as long) }
    }
}
