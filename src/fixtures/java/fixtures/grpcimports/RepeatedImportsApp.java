package fixtures.grpcimports;

import fixtures.grpc.GreeterGrpc;
import fixtures.grpc.HelloReply;
import fixtures.grpc.HelloRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.client.ImportGrpcClients;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Two @ImportGrpcClients on one class: each stub type on its own channel.
 */
@Configuration
@ImportGrpcClients(target = "greeter", types = GreeterGrpc.GreeterBlockingStub.class)
@ImportGrpcClients(target = "backup", types = GreeterGrpc.GreeterFutureStub.class)
class GrpcClientsConfig {
}

@RestController
class PingController {

    private final GreeterGrpc.GreeterBlockingStub greeter;

    private final GreeterGrpc.GreeterFutureStub backup;

    PingController(GreeterGrpc.GreeterBlockingStub greeter, GreeterGrpc.GreeterFutureStub backup) {
        this.greeter = greeter;
        this.backup = backup;
    }

    @GetMapping("/ping")
    HelloReply ping() {
        return greeter.ping(HelloRequest.getDefaultInstance());
    }

    @GetMapping("/ping/backup")
    void pingBackup() {
        backup.ping(HelloRequest.getDefaultInstance());
    }
}
