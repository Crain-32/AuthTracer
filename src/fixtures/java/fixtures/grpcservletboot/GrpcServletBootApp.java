package fixtures.grpcservletboot;

import fixtures.grpc.GreeterGrpc;
import fixtures.grpc.HelloReply;
import fixtures.grpc.HelloRequest;
import io.grpc.stub.StreamObserver;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.grpc.server.service.GrpcService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Decision 0059: Spring Boot's gRPC services served through the servlet container, reflection turned off: health is
 * a POST like the application's own calls. The greeter implements only one of its rpcs.
 */
@SpringBootApplication
@EnableWebSecurity
class GrpcServletBootApp {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/grpc.health.v1.Health/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }
}

@GrpcService
class PartialGreeter extends GreeterGrpc.GreeterImplBase {

    @Override
    public void sayHello(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
        responseObserver.onNext(HelloReply.newBuilder().setMessage("Hello").build());
        responseObserver.onCompleted();
    }
}
