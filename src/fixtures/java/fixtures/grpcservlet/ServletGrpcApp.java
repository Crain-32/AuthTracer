package fixtures.grpcservlet;

import fixtures.grpc.GreeterGrpc;
import fixtures.grpc.HelloReply;
import fixtures.grpc.HelloRequest;
import io.grpc.stub.StreamObserver;
import org.springframework.boot.grpc.server.autoconfigure.security.web.servlet.GrpcRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.service.GrpcService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * gRPC served through the servlet container (grpc-servlet on the classpath): calls pass the HTTP filter chain.
 */
@Configuration
@EnableWebSecurity
class ServletGrpcSecurityConfig {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests
                .requestMatchers(GrpcRequest.toAnyService().excluding("grpc.health.v1.Health"))
                .hasAuthority("SCOPE_grpc")
                .requestMatchers("/{name}/**").hasAuthority("SCOPE_rest")
                .anyRequest().denyAll());
        return http.build();
    }
}

@GrpcService
class ServletGreeter extends GreeterGrpc.GreeterImplBase {

    @Override
    public void sayHello(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
        responseObserver.onNext(HelloReply.newBuilder().setMessage("Hello").build());
        responseObserver.onCompleted();
    }
}

@RestController
class StatusController {

    @GetMapping("/status/now")
    String now() {
        return "up";
    }
}
