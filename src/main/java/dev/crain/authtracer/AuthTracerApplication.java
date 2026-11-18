package dev.crain.authtracer;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.TraceSource;
import dev.crain.authtracer.link.ZipkinTraces;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@Supports({Feature.GRAPH_SERVER, Feature.COMMAND_LINE})
@SpringBootApplication
@EnableConfigurationProperties(AuthTracerProperties.class)
public class AuthTracerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthTracerApplication.class, args);
    }

    @Supports({Feature.TRACE_OBSERVATIONS, Feature.GRAPH_SERVER})
    @Bean
    TraceSource traceSource(AuthTracerProperties properties) {
        AuthTracerProperties.Zipkin zipkin = properties.zipkin();
        return ZipkinTraces.api(zipkin.baseUrl(), zipkin.lookback(), zipkin.limit());
    }

    @Bean
    Linker linker() {
        return new Linker();
    }
}
