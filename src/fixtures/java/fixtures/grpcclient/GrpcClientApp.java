package fixtures.grpcclient;

import java.util.List;

import fixtures.grpc.GreeterGrpc;
import fixtures.grpc.HelloReply;
import fixtures.grpc.HelloRequest;
import org.springframework.grpc.client.ChannelBuilderOptions;
import org.springframework.grpc.client.GrpcChannelFactory;
import org.springframework.grpc.client.interceptor.security.BearerTokenAuthenticationInterceptor;
import org.springframework.grpc.client.interceptor.security.TokenRelayTokenSupplier;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Calls the grpc fixture's Greeter with a blocking stub, relaying the caller's token.
 */
@RestController
class GreetingController {

    private final GreeterGrpc.GreeterBlockingStub greeter;

    GreetingController(GrpcChannelFactory channels, OAuth2AuthorizedClientManager clients) {
        this.greeter = GreeterGrpc.newBlockingStub(channels.createChannel("greeter", ChannelBuilderOptions.defaults()
                .withInterceptors(List.of(new BearerTokenAuthenticationInterceptor(
                        new TokenRelayTokenSupplier(clients))))));
    }

    @GetMapping("/greetings/{name}")
    HelloReply greet(@PathVariable String name) {
        return greeter.sayHello(HelloRequest.newBuilder().setName(name).build());
    }
}
