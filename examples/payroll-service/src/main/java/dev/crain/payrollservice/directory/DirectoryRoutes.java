package dev.crain.payrollservice.directory;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

/**
 * A functional endpoint, next to the annotated {@code TeamController}.
 */
@Configuration
public class DirectoryRoutes {

    @Bean
    RouterFunction<ServerResponse> directory(DirectoryHandler handler) {
        return RouterFunctions.route()
                .path("/directory", builder -> builder.GET("/teams", handler::teams))
                .build();
    }
}
