package fixtures.grpcpackages;

import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.client.ImportGrpcClients;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import fixtures.grpc.GreeterGrpc;
import fixtures.grpc.HelloReply;
import fixtures.grpc.HelloRequest;

/**
 * @ImportGrpcClients scanning packages by name: one that holds no stubs, then a parent package of the stubs'.
 */
@Configuration
@ImportGrpcClients(target = "elsewhere", basePackages = "fixtures.elsewhere")
@ImportGrpcClients(target = "everything", basePackages = "fixtures")
class GrpcClientsConfig {
}

@RestController
class GreetingController {

    private final GreeterGrpc.GreeterBlockingStub greeter;

    GreetingController(GreeterGrpc.GreeterBlockingStub greeter) {
        this.greeter = greeter;
    }

    @GetMapping("/greetings")
    HelloReply greet() {
        return greeter.sayHello(HelloRequest.getDefaultInstance());
    }
}
