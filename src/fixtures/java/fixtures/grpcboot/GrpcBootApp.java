package fixtures.grpcboot;

import fixtures.grpc.GreeterGrpc;
import fixtures.grpc.HelloReply;
import fixtures.grpc.HelloRequest;
import io.grpc.stub.StreamObserver;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.grpc.server.security.AuthenticationProcessInterceptor;
import org.springframework.grpc.server.security.GrpcSecurity;
import org.springframework.grpc.server.service.GrpcService;
import org.springframework.security.config.Customizer;

/**
 * Decision 0059: a Spring Boot gRPC server, which also serves health and reflection; its rules permit grpc.* to
 * anyone.
 */
@SpringBootApplication
class GrpcBootApp {

    @Bean
    @GlobalServerInterceptor
    AuthenticationProcessInterceptor grpcSecurity(GrpcSecurity grpc) throws Exception {
        return grpc.authorizeRequests(requests -> requests.methods("grpc.*/*").permitAll()
                        .allRequests().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
                .build();
    }
}

@GrpcService
class GreeterService extends GreeterGrpc.GreeterImplBase {

    @Override
    public void ping(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
        responseObserver.onNext(HelloReply.newBuilder().setMessage("pong").build());
        responseObserver.onCompleted();
    }
}
