package fixtures.grpcscan;

import fixtures.grpc.GreeterGrpc;
import fixtures.grpc.HelloReply;
import fixtures.grpc.HelloRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.client.ImportGrpcClients;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @ImportGrpcClients scanning the stubs in GreeterGrpc's package.
 */
@Configuration
@ImportGrpcClients(target = "scanned", basePackageClasses = GreeterGrpc.class)
class GrpcClientsConfig {
}

@RestController
class PingController {

    private final GreeterGrpc.GreeterBlockingStub greeter;

    PingController(GreeterGrpc.GreeterBlockingStub greeter) {
        this.greeter = greeter;
    }

    @GetMapping("/ping")
    HelloReply ping() {
        return greeter.ping(HelloRequest.getDefaultInstance());
    }
}
