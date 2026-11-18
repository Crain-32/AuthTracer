package fixtures.grpctokens;

import java.time.Duration;

import fixtures.grpcrelay.GreetReply;
import fixtures.grpcrelay.GreetRequest;
import fixtures.grpcrelay.RelayGrpc;
import io.grpc.stub.StreamObserver;
import org.springframework.grpc.client.GrpcChannelFactory;
import org.springframework.grpc.client.interceptor.security.BearerTokenAuthenticationInterceptor;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import reactor.core.publisher.MonoSink;

/**
 * Calls on one stub, each with its own token: the caller's, relayed in one method; the service's own in another, for
 * work no caller asked for (a listener's), from a reactive authorized-client manager as a WebFlux service gets one
 * outside a request; and, from the same manager, a registration whose grant is the signed-in user's.
 */
@RestController
class TokensController {

    private final TwoWayGreeter greeter;

    TokensController(TwoWayGreeter greeter) {
        this.greeter = greeter;
    }

    @GetMapping("/greetings/{name}")
    Mono<String> greet(@PathVariable String name) {
        return greeter.greet(name);
    }

    @GetMapping("/portal/{name}")
    Mono<String> portal(@PathVariable String name) {
        return greeter.greetForPortal(name);
    }
}

@Component
class GreetingListener {

    private final TwoWayGreeter greeter;

    GreetingListener(TwoWayGreeter greeter) {
        this.greeter = greeter;
    }

    @KafkaListener(topics = "greetings")
    void greeted(String name) {
        greeter.greetAsService(name).block(Duration.ofSeconds(5));
    }
}

@Component
class TwoWayGreeter {

    private final RelayGrpc.RelayStub greeter;
    private final ReactiveOAuth2AuthorizedClientManager clients;

    TwoWayGreeter(GrpcChannelFactory channels, ReactiveOAuth2AuthorizedClientManager clients) {
        this.greeter = RelayGrpc.newStub(channels.createChannel("greeter"));
        this.clients = clients;
    }

    Mono<String> greet(String name) {
        return ReactiveSecurityContextHolder.getContext()
                .map(context -> ((AbstractOAuth2TokenAuthenticationToken<?>) context.getAuthentication()).getToken()
                        .getTokenValue())
                .flatMap(token -> Mono.<GreetReply>create(sink -> greeter
                        .withInterceptors(new BearerTokenAuthenticationInterceptor(token))
                        .greet(GreetRequest.newBuilder().setName(name).build(), new SinkObserver(sink))))
                .map(GreetReply::getMessage);
    }

    Mono<String> greetAsService(String name) {
        OAuth2AuthorizeRequest request = OAuth2AuthorizeRequest.withClientRegistrationId("greeter")
                .principal("greeter").build();
        return clients.authorize(request)
                .map(client -> client.getAccessToken().getTokenValue())
                .flatMap(token -> Mono.<GreetReply>create(sink -> greeter
                        .withInterceptors(new BearerTokenAuthenticationInterceptor(token))
                        .greet(GreetRequest.newBuilder().setName(name).build(), new SinkObserver(sink))))
                .map(GreetReply::getMessage);
    }

    Mono<String> greetForPortal(String name) {
        return clients.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("portal").principal(name).build())
                .map(client -> client.getAccessToken().getTokenValue())
                .flatMap(token -> Mono.<GreetReply>create(sink -> greeter
                        .withInterceptors(new BearerTokenAuthenticationInterceptor(token))
                        .greet(GreetRequest.newBuilder().setName(name).build(), new SinkObserver(sink))))
                .map(GreetReply::getMessage);
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
