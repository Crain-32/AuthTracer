package fixtures.lambdacalls;

import java.util.List;
import java.util.Optional;

import fixtures.grpcrelay.GreetReply;
import fixtures.grpcrelay.GreetRequest;
import fixtures.grpcrelay.RelayGrpc;
import io.grpc.stub.StreamObserver;
import org.springframework.grpc.client.GrpcChannelFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import reactor.core.publisher.Mono;

/**
 * Calls out from inside lambdas, nested ones among them, as reactive and Optional-based code makes them: the call is
 * named by the method the lambda is written in, not by the compiler's lambda number.
 */
@RestController
class LambdaCallsController {

    private final Greeter greeter;
    private final Stock stock;

    LambdaCallsController(Greeter greeter, Stock stock) {
        this.greeter = greeter;
        this.stock = stock;
    }

    @GetMapping("/greetings/{name}")
    Mono<String> greet(@PathVariable String name) {
        return greeter.greet(name);
    }

    @GetMapping("/stock/{sku}")
    String stock(@PathVariable String sku) {
        return stock.count(sku);
    }
}

@Component
class Greeter {

    private final RelayGrpc.RelayStub relay;

    Greeter(GrpcChannelFactory channels) {
        this.relay = RelayGrpc.newStub(channels.createChannel("relay"));
    }

    Mono<String> greet(String name) {
        return Mono.just(name).filter(given -> !given.isBlank())
                .flatMap(given -> Mono.<GreetReply>create(sink -> relay.greet(
                        GreetRequest.newBuilder().setName(given).build(), new StreamObserver<>() {

                            @Override
                            public void onNext(GreetReply reply) {
                                sink.success(reply);
                            }

                            @Override
                            public void onError(Throwable error) {
                                sink.error(error);
                            }

                            @Override
                            public void onCompleted() {
                                sink.success();
                            }
                        })))
                .map(GreetReply::getMessage);
    }
}

@Component
class Stock {

    private final RestClient client = RestClient.create("http://stock:8080");

    String count(String sku) {
        return Optional.of(sku).map(code -> List.of(code).stream()
                .map(one -> client.get().uri("/stock/{sku}", one).retrieve().body(String.class))
                .findFirst().orElse("0")).orElse("0");
    }
}
