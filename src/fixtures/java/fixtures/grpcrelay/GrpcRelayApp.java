package fixtures.grpcrelay;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import io.grpc.stub.StreamObserver;
import org.springframework.grpc.client.GrpcChannelFactory;
import org.springframework.grpc.client.interceptor.security.BearerTokenAuthenticationInterceptor;
import org.springframework.grpc.client.interceptor.security.TokenSupplier;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import reactor.core.publisher.MonoSink;

/**
 * gRPC calls with Spring gRPC's bearer interceptor, given its token in the ways applications do: the caller's, read
 * from the Reactor context (a reactive request has no thread-bound caller), a fixed one, an OAuth2 client's from a
 * token supplier, and one from a key store AuthTracer can't follow. The relayed reply is mapped into a record before
 * the controller reads it; a listener waits for one and keeps it.
 */
@RestController
class GreetingController {

    private final RelayingGreeter relaying;
    private final FixedGreeter fixed;
    private final ServiceGreeter service;
    private final KeyedGreeter keyed;

    GreetingController(RelayingGreeter relaying, FixedGreeter fixed, ServiceGreeter service, KeyedGreeter keyed) {
        this.relaying = relaying;
        this.fixed = fixed;
        this.service = service;
        this.keyed = keyed;
    }

    @GetMapping("/greetings/{name}")
    Mono<GreetingView> greet(@PathVariable String name) {
        return relaying.greet(name).map(greeting -> new GreetingView(greeting.message() + "!", greeting.note()));
    }

    @GetMapping("/pings/fixed")
    String fixedPing() {
        return fixed.ping();
    }

    @GetMapping("/pings/service")
    String servicePing() {
        return service.ping();
    }

    @GetMapping("/pings/keyed")
    String keyedPing() {
        return keyed.ping();
    }
}

record Greeting(String message, String note) {

    static Greeting from(GreetReply reply) {
        return new Greeting(reply.getMessage(), reply.getSecretNote());
    }
}

record GreetingView(String text, String note) {
}

@Component
class RelayingGreeter {

    private final RelayGrpc.RelayStub greeter;

    RelayingGreeter(GrpcChannelFactory channels) {
        this.greeter = RelayGrpc.newStub(channels.createChannel("greeter"));
    }

    Mono<Greeting> greet(String name) {
        return ReactiveSecurityContextHolder.getContext()
                .map(context -> ((AbstractOAuth2TokenAuthenticationToken<?>) context.getAuthentication()).getToken()
                        .getTokenValue())
                .flatMap(token -> Mono.<GreetReply>create(sink -> greeter
                        .withInterceptors(new BearerTokenAuthenticationInterceptor(token))
                        .greet(GreetRequest.newBuilder().setName(name).build(), new SinkObserver(sink))))
                .map(Greeting::from);
    }
}

record SinkObserver(MonoSink<GreetReply> sink) implements StreamObserver<GreetReply> {

    @Override
    public void onNext(GreetReply value) {
        sink.success(value);
    }

    @Override
    public void onError(Throwable error) {
        sink.error(error);
    }

    @Override
    public void onCompleted() {
        sink.success();
    }
}

@Component
class FixedGreeter {

    private final RelayGrpc.RelayBlockingStub greeter;

    FixedGreeter(GrpcChannelFactory channels) {
        this.greeter = RelayGrpc.newBlockingStub(channels.createChannel("greeter"))
                .withInterceptors(new BearerTokenAuthenticationInterceptor("ping-token"));
    }

    String ping() {
        return greeter.ping(GreetRequest.getDefaultInstance()).getMessage();
    }
}

/**
 * The service's own token, from its OAuth2 client registration.
 */
class ServiceTokens implements TokenSupplier {

    private final OAuth2AuthorizedClientManager clients;

    ServiceTokens(OAuth2AuthorizedClientManager clients) {
        this.clients = clients;
    }

    @Override
    public String token() {
        return clients.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("greeter").principal("service")
                .build()).getAccessToken().getTokenValue();
    }
}

@Component
class ServiceGreeter {

    private final RelayGrpc.RelayBlockingStub greeter;

    ServiceGreeter(GrpcChannelFactory channels, OAuth2AuthorizedClientManager clients) {
        this.greeter = RelayGrpc.newBlockingStub(channels.createChannel("greeter"))
                .withInterceptors(new BearerTokenAuthenticationInterceptor(new ServiceTokens(clients)));
    }

    String ping() {
        return greeter.ping(GreetRequest.getDefaultInstance()).getMessage();
    }
}

/**
 * Where keys come from at run time: a library's implementation, not the application's.
 */
interface KeyStore {

    String current();
}

@Component
class KeyedGreeter {

    private final RelayGrpc.RelayBlockingStub greeter;

    KeyedGreeter(GrpcChannelFactory channels, KeyStore keys) {
        this.greeter = RelayGrpc.newBlockingStub(channels.createChannel("greeter"))
                .withInterceptors(new BearerTokenAuthenticationInterceptor(keys.current()));
    }

    String ping() {
        return greeter.ping(GreetRequest.getDefaultInstance()).getMessage();
    }
}

record NameChanged(String name) {
}

record Reply(String name, String text) {

    static Reply of(NameChanged changed, Greeting greeting) {
        return new Reply(changed.name(), greeting.message());
    }
}

/**
 * A reactive call with a fixed token, its reply mapped into a record.
 */
@Component
class ListenerGreeter {

    private final RelayGrpc.RelayStub greeter;

    ListenerGreeter(GrpcChannelFactory channels) {
        this.greeter = RelayGrpc.newStub(channels.createChannel("greeter"))
                .withInterceptors(new BearerTokenAuthenticationInterceptor("listener-token"));
    }

    Mono<Greeting> greet(String name) {
        return Mono.<GreetReply>create(sink -> greeter.greet(GreetRequest.newBuilder().setName(name).build(),
                new SinkObserver(sink))).map(Greeting::from);
    }
}

/**
 * Keeps the reply to each name it receives, which it waits for and a factory reads: the reply's text is the gRPC
 * reply's message. The request it builds from the name is only sent.
 */
@Component
class NameListener {

    private final ListenerGreeter greeter;
    private final List<Reply> replies = new CopyOnWriteArrayList<>();

    NameListener(ListenerGreeter greeter) {
        this.greeter = greeter;
    }

    @KafkaListener(topics = "names")
    void changed(NameChanged changed) {
        Greeting greeting = greeter.greet(changed.name()).block(Duration.ofSeconds(5));
        replies.add(Reply.of(changed, greeting));
    }
}
