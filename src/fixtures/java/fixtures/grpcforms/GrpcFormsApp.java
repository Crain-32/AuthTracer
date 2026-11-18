package fixtures.grpcforms;

import fixtures.grpc.GreeterGrpc;
import fixtures.grpc.HelloReply;
import fixtures.grpc.HelloRequest;
import io.grpc.stub.StreamObserver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.grpc.server.security.AuthenticationProcessInterceptor;
import org.springframework.grpc.server.security.GrpcSecurity;
import org.springframework.grpc.server.service.GrpcService;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.config.Customizer;

/**
 * Decision 0032: Spring gRPC's rules with a negated one, a manager passed to access(..), and fully authenticated
 * callers for the rest.
 */
@Configuration
class GrpcFormsSecurityConfig {

    @Bean
    @GlobalServerInterceptor
    AuthenticationProcessInterceptor grpcSecurity(GrpcSecurity grpc) throws Exception {
        return grpc.authorizeRequests(requests -> requests
                        .methods("fixtures.grpc.Greeter/Ping").not().hasAuthority("ROLE_SUSPENDED")
                        .methods("fixtures.grpc.Greeter/list_*").access(AuthorityAuthorizationManager.hasRole("LISTER"))
                        .allRequests().fullyAuthenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
                .build();
    }
}

@GrpcService
class FormsGreeter extends GreeterGrpc.GreeterImplBase {

    @Override
    public void sayHello(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
        responseObserver.onNext(HelloReply.newBuilder().setMessage("Hello " + request.getName()).build());
        responseObserver.onCompleted();
    }

    @Override
    public void listGreetings(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
        responseObserver.onNext(HelloReply.newBuilder().setMessage("Hi").build());
        responseObserver.onCompleted();
    }

    @Override
    public void ping(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
        responseObserver.onNext(HelloReply.newBuilder().setMessage("pong").build());
        responseObserver.onCompleted();
    }
}
