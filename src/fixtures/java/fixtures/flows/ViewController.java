package fixtures.flows;

import java.math.BigDecimal;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ViewController {

    @GetMapping("/view")
    View view() {
        return View.of(load());
    }

    @GetMapping("/views")
    List<View> views() {
        return List.of(load()).stream().map(View::of).toList();
    }

    @GetMapping("/legacy")
    LegacyView legacy() {
        return new LegacyView(load().last());
    }

    @GetMapping("/bean")
    BeanView bean() {
        Source source = load();
        BeanView view = new BeanView();
        view.setName(source.first());
        view.setLabel(source.first() + " " + source.last());
        return view;
    }

    /**
     * The exception supplier runs only when there is no view: the view is the result.
     */
    @GetMapping("/found")
    View found() {
        return Optional.of(load()).map(View::of).orElseThrow(() -> new IllegalStateException("no view"));
    }

    @GetMapping("/visible")
    List<View> visible() {
        return List.of(load()).stream().map(View::of).filter(view -> view.direct() != null)
                .sorted(Comparator.comparing(View::concatenated)).toList();
    }

    @GetMapping("/fallback")
    View fallback() {
        return Optional.<Source>empty().map(View::of).orElseGet(() -> View.of(load()));
    }

    /**
     * The key picks the value; it isn't the value.
     */
    @GetMapping("/lookup")
    LegacyView lookup() {
        Source source = load();
        Map<String, String> lastNames = new HashMap<>();
        lastNames.put(source.first(), source.last());
        return new LegacyView(lastNames.get(source.first()));
    }

    /**
     * Spring MVC writes the stage's result when it completes.
     */
    @GetMapping("/later")
    CompletionStage<View> later() {
        return CompletableFuture.completedFuture(View.of(load()));
    }

    @GetMapping("/snake")
    SnakeView snake() {
        Source source = load();
        return new SnakeView(source.first(), source.last(), source.first());
    }

    @GetMapping("/order")
    OrderDto order() {
        Source source = load();
        return OrderDto.builder().customer(source.first()).secret(source.secret()).build();
    }

    @GetMapping("/shelter")
    Shelter shelter() {
        return new Shelter(List.of());
    }

    private Source load() {
        return new Source("Ada", "Lovelace", BigDecimal.ONE, "s3cret");
    }
}
