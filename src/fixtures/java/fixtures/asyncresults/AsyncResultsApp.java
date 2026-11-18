package fixtures.asyncresults;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.async.DeferredResult;
import org.springframework.web.context.request.async.WebAsyncTask;

record Report(String title) {
}

/**
 * Spring MVC's asynchronous results: the response is what they complete with.
 */
@RestController
class ReportController {

    @GetMapping("/callable")
    Callable<Report> callable() {
        return () -> new Report("daily");
    }

    @GetMapping("/deferred")
    DeferredResult<Report> deferred() {
        DeferredResult<Report> result = new DeferredResult<>();
        result.setResult(new Report("daily"));
        return result;
    }

    @GetMapping("/task")
    WebAsyncTask<Report> task() {
        return new WebAsyncTask<>(() -> new Report("daily"));
    }

    @GetMapping("/stage")
    CompletionStage<List<Report>> stage() {
        return CompletableFuture.completedFuture(List.of(new Report("daily")));
    }
}
