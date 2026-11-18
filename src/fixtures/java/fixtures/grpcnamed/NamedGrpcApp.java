package fixtures.grpcnamed;

import fixtures.grpc.GreeterGrpc;
import fixtures.grpc.HelloReply;
import fixtures.grpc.HelloRequest;
import io.grpc.stub.StreamObserver;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.grpc.server.security.AuthenticationProcessInterceptor;
import org.springframework.grpc.server.security.GrpcSecurity;
import org.springframework.grpc.server.service.GrpcService;
import org.springframework.security.config.Customizer;

/**
 * A Spring Boot gRPC server whose rules run only on the service that names their bean; the global interceptor only
 * authenticates. The first rule's methods come from configuration.
 */
@SpringBootApplication
class NamedGrpcApp {

    @Bean
    AuthenticationProcessInterceptor greeterSecurity(GrpcSecurity grpc, @Value("${grpc.open}") String open)
            throws Exception {
        return grpc.authorizeRequests(requests -> requests.methods(open).hasAuthority("SCOPE_greet")
                        .methods("fixtures.grpc.Greeter/SayHello").hasAuthority("SCOPE_greet"))
                .build();
    }

    @Bean
    @GlobalServerInterceptor
    AuthenticationProcessInterceptor authentication(GrpcSecurity grpc) throws Exception {
        return grpc.httpBasic(Customizer.withDefaults()).build();
    }
}

@GrpcService(interceptorNames = "greeterSecurity")
class NamedGreeter extends GreeterGrpc.GreeterImplBase {

    @Override
    public void sayHello(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
        responseObserver.onNext(HelloReply.newBuilder().setMessage("Hello").build());
        responseObserver.onCompleted();
    }

    @Override
    public void ping(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
        responseObserver.onNext(HelloReply.newBuilder().setMessage("pong").build());
        responseObserver.onCompleted();
    }
}
