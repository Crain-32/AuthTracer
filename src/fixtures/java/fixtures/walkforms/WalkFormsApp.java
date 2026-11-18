package fixtures.walkforms;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Ways a call path goes that the walk has to follow: through a bridge to an inherited method, to the beans a factory
 * method may return, and to the listeners of what is published.
 */
@Configuration
@EnableMethodSecurity
class WalkFormsApp {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.anyRequest().permitAll());
        return http.build();
    }

    /**
     * Which archive is a run-time choice: any Archive the application has.
     */
    @Bean
    Archive archive(ArchiveSettings settings) {
        return settings.choose();
    }
}

record Doc(long id, String body) {
}

@Service
class Docs {

    @PreAuthorize("hasRole('READER')")
    public Doc find(long id) {
        return new Doc(id, "body");
    }
}

/**
 * Implemented by a class that inherits the method: javac's bridge in DocFinder calls DocFinder.find, which BaseFinder
 * declares.
 */
interface Finder<T> {

    T find(long id);
}

class BaseFinder {

    @PreAuthorize("hasRole('FINDER')")
    public Doc find(long id) {
        return new Doc(id, "found");
    }
}

@Service
class DocFinder extends BaseFinder implements Finder<Doc> {
}

interface Lookup<T> {

    T lookup(long id);
}

/**
 * Narrows the interface's method without implementing it: javac's bridge here calls the abstract method, which
 * CachedLookup implements.
 */
abstract class AbstractLookup implements Lookup<Doc> {

    @Override
    public abstract Doc lookup(long id);
}

@Service
class CachedLookup extends AbstractLookup {

    @Override
    @PreAuthorize("hasRole('LOOKUP')")
    public Doc lookup(long id) {
        return new Doc(id, "cached");
    }
}

/**
 * No object is ever just an Archive: its own store runs for none of the beans, which both override it.
 */
abstract class Archive {

    public String store(long id) {
        return "stored";
    }
}

class ColdArchive extends Archive {

    @Override
    @PreAuthorize("hasRole('COLD')")
    public String store(long id) {
        return "cold";
    }
}

class HotArchive extends Archive {

    @Override
    @PreAuthorize("hasRole('HOT')")
    public String store(long id) {
        return "hot";
    }
}

@Component
class ArchiveSettings {

    Archive choose() {
        return new HotArchive();
    }
}

/**
 * Two beans, neither with a check: a dispatch with nothing to choose between.
 */
interface Formatter {

    String format(Doc doc);
}

@Service
class PlainFormatter implements Formatter {

    public String format(Doc doc) {
        return doc.body();
    }
}

@Service
class UpperFormatter implements Formatter {

    public String format(Doc doc) {
        return doc.body().toUpperCase();
    }
}

/**
 * Six choices of two checks each: 64 ways through, more alternatives than the walk keeps apart.
 */
@Service
class Choices {

    @PreAuthorize("hasRole('LEFT1')")
    public void left1() {
    }

    @PreAuthorize("hasRole('RIGHT1')")
    public void right1() {
    }

    @PreAuthorize("hasRole('LEFT2')")
    public void left2() {
    }

    @PreAuthorize("hasRole('RIGHT2')")
    public void right2() {
    }

    @PreAuthorize("hasRole('LEFT3')")
    public void left3() {
    }

    @PreAuthorize("hasRole('RIGHT3')")
    public void right3() {
    }

    @PreAuthorize("hasRole('LEFT4')")
    public void left4() {
    }

    @PreAuthorize("hasRole('RIGHT4')")
    public void right4() {
    }

    @PreAuthorize("hasRole('LEFT5')")
    public void left5() {
    }

    @PreAuthorize("hasRole('RIGHT5')")
    public void right5() {
    }

    @PreAuthorize("hasRole('LEFT6')")
    public void left6() {
    }

    @PreAuthorize("hasRole('RIGHT6')")
    public void right6() {
    }
}

interface DomainEvent {
}

record DocRead(long id) implements DomainEvent {
}

class DocDeleted extends ApplicationEvent {

    DocDeleted(Object source) {
        super(source);
    }
}

@Service
class Audit {

    @PreAuthorize("hasRole('DOMAIN')")
    public void domain() {
    }

    @PreAuthorize("hasRole('NOTICE')")
    public void notice() {
    }

    @PreAuthorize("hasRole('DELETION')")
    public void deletion() {
    }

    @PreAuthorize("hasRole('TEXT')")
    public void text() {
    }
}

@Component
class DocListeners {

    private final Audit audit;

    DocListeners(Audit audit) {
        this.audit = audit;
    }

    /**
     * Takes the interface the event implements.
     */
    @EventListener
    void onDomainEvent(DomainEvent event) {
        audit.domain();
    }

    /**
     * Names the event it listens to instead of taking it.
     */
    @EventListener(DocRead.class)
    void onRead() {
        audit.notice();
    }

    @EventListener
    void onText(String text) {
        audit.text();
    }
}

@Component
class DeletionListener implements ApplicationListener<DocDeleted> {

    private final Audit audit;

    DeletionListener(Audit audit) {
        this.audit = audit;
    }

    @Override
    public void onApplicationEvent(DocDeleted event) {
        audit.deletion();
    }
}

@RestController
class WalkController {

    private final Docs docs;
    private final Finder<Doc> finder;
    private final Lookup<Doc> lookup;
    private final Archive archive;
    private final Formatter formatter;
    private final Choices choices;
    private final ApplicationEventPublisher events;

    WalkController(Docs docs, Finder<Doc> finder, Lookup<Doc> lookup, Archive archive, Formatter formatter,
            Choices choices, ApplicationEventPublisher events) {
        this.docs = docs;
        this.finder = finder;
        this.lookup = lookup;
        this.archive = archive;
        this.formatter = formatter;
        this.choices = choices;
        this.events = events;
    }

    /**
     * The check runs on a preview and again on every way: it is on every way.
     */
    @GetMapping("/docs/{id}")
    Doc doc(@PathVariable long id, boolean preview) {
        if (preview) {
            docs.find(id);
        }
        return docs.find(id);
    }

    @GetMapping("/found/{id}")
    Doc found(@PathVariable long id) {
        return finder.find(id);
    }

    @GetMapping("/looked-up/{id}")
    Doc lookedUp(@PathVariable long id) {
        return lookup.lookup(id);
    }

    @PostMapping("/archive/{id}")
    String store(@PathVariable long id) {
        return archive.store(id);
    }

    @GetMapping("/formatted/{id}")
    String formatted(@PathVariable long id) {
        return formatter.format(new Doc(id, "body"));
    }

    @GetMapping("/described/{id}")
    String described(@PathVariable long id) {
        return new Doc(id, "body").toString();
    }

    @PostMapping("/chosen")
    void chosen(boolean a, boolean b, boolean c, boolean d, boolean e, boolean f) {
        if (a) {
            choices.left1();
        }
        else {
            choices.right1();
        }
        if (b) {
            choices.left2();
        }
        else {
            choices.right2();
        }
        if (c) {
            choices.left3();
        }
        else {
            choices.right3();
        }
        if (d) {
            choices.left4();
        }
        else {
            choices.right4();
        }
        if (e) {
            choices.left5();
        }
        else {
            choices.right5();
        }
        if (f) {
            choices.left6();
        }
        else {
            choices.right6();
        }
    }

    @PostMapping("/read/{id}")
    void read(@PathVariable long id) {
        events.publishEvent(new DocRead(id));
    }

    @PostMapping("/deleted/{id}")
    void deleted(@PathVariable long id) {
        events.publishEvent(new DocDeleted(this));
    }

    @PostMapping("/refreshed")
    void refreshed() {
        events.publishEvent("refreshed");
    }

    /**
     * Published as Object: which listeners run depends on what it is at run time.
     */
    @PostMapping("/anything")
    void anything() {
        Object payload = load();
        events.publishEvent(payload);
    }

    private Object load() {
        return new DocRead(0);
    }
}
