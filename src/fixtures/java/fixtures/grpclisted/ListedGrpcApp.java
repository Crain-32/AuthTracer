package fixtures.grpclisted;

import fixtures.grpc.GreeterGrpc;
import fixtures.grpc.HelloReply;
import fixtures.grpc.HelloRequest;
import io.grpc.stub.StreamObserver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.security.AuthenticationProcessInterceptor;
import org.springframework.grpc.server.security.GrpcSecurity;
import org.springframework.grpc.server.service.GrpcService;

/**
 * The service lists the interceptor by its class.
 */
@Configuration
class ListedGrpcSecurityConfig {

    @Bean
    AuthenticationProcessInterceptor grpcSecurity(GrpcSecurity grpc) throws Exception {
        return grpc.authorizeRequests(requests -> requests.allRequests().authenticated()).build();
    }
}

@GrpcService(interceptors = AuthenticationProcessInterceptor.class)
class ListedGreeter extends GreeterGrpc.GreeterImplBase {

    @Override
    public void sayHello(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
        responseObserver.onNext(HelloReply.newBuilder().setMessage("Hello").build());
        responseObserver.onCompleted();
    }
}
