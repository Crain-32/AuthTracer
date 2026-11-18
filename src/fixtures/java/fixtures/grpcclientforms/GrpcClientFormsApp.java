package fixtures.grpcclientforms;

import java.util.Iterator;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.client.GrpcChannelFactory;
import org.springframework.grpc.client.ImportGrpcClients;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.google.common.util.concurrent.ListenableFuture;

import fixtures.grpc.GreeterGrpc;
import fixtures.grpc.HelloReply;
import fixtures.grpc.HelloRequest;

/**
 * gRPC stubs, the other ways their channel is named: an import by value on the default channel (the standalone
 * starter's address property), a channel the client creates from a configured name, and one a @Bean in another
 * class creates, which the caller's class doesn't name.
 */
@Configuration
@ImportGrpcClients(GreeterGrpc.GreeterBlockingStub.class)
class GrpcClientsConfig {

    @Bean
    GreeterGrpc.GreeterFutureStub futures(GrpcChannelFactory channels, @Value("${futures.channel}") String name) {
        return GreeterGrpc.newFutureStub(channels.createChannel(name));
    }
}

@Component
class BackupGreeter {

    private final GreeterGrpc.GreeterBlockingStub greeter;

    BackupGreeter(GrpcChannelFactory channels, @Value("${backup.channel}") String channel) {
        this.greeter = GreeterGrpc.newBlockingStub(channels.createChannel(channel));
    }

    Iterator<HelloReply> greetings() {
        return greeter.listGreetings(HelloRequest.getDefaultInstance());
    }
}

@RestController
class GreetingController {

    private final GreeterGrpc.GreeterBlockingStub greeter;
    private final GreeterGrpc.GreeterFutureStub futures;
    private final BackupGreeter backup;

    GreetingController(GreeterGrpc.GreeterBlockingStub greeter, GreeterGrpc.GreeterFutureStub futures,
            BackupGreeter backup) {
        this.greeter = greeter;
        this.futures = futures;
        this.backup = backup;
    }

    @GetMapping("/greetings")
    HelloReply greet() {
        return greeter.sayHello(HelloRequest.getDefaultInstance());
    }

    @GetMapping("/greetings/later")
    ListenableFuture<HelloReply> later() {
        return futures.ping(HelloRequest.getDefaultInstance());
    }

    @GetMapping("/greetings/backup")
    String backup() {
        return backup.greetings().next().getMessage();
    }
}
