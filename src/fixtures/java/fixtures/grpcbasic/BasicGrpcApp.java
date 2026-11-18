package fixtures.grpcbasic;

import static org.springframework.security.config.Customizer.withDefaults;

import fixtures.grpc.GreeterGrpc;
import fixtures.grpc.HelloReply;
import fixtures.grpc.HelloRequest;
import io.grpc.ServerInterceptor;
import io.grpc.stub.StreamObserver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.grpc.server.security.GrpcSecurity;
import org.springframework.grpc.server.service.GrpcService;

/**
 * As spring-grpc's grpc-secure sample: the interceptor bean typed as a plain ServerInterceptor, HTTP Basic and
 * client certificates.
 */
@Configuration
class BasicGrpcSecurityConfig {

    @Bean
    @GlobalServerInterceptor
    ServerInterceptor securityInterceptor(GrpcSecurity security) throws Exception {
        return security
                .authorizeRequests(requests -> requests.methods("fixtures.grpc.Greeter/SayHello").hasAuthority("ROLE_USER")
                        .methods("grpc.*/*").permitAll()
                        .allRequests().denyAll())
                .httpBasic(withDefaults())
                .preauth(withDefaults())
                .build();
    }
}

@GrpcService
class BasicGreeter extends GreeterGrpc.GreeterImplBase {

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
