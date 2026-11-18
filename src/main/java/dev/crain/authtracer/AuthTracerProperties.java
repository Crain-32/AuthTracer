package dev.crain.authtracer;

import java.net.URI;
import java.time.Duration;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.util.unit.DataSize;

@Supports(Feature.GRAPH_SERVER)
@ConfigurationProperties("authtracer")
public record AuthTracerProperties(Zipkin zipkin, @DefaultValue Api api) {

    /**
     * @param maxBodySize the most a graph posted to the API may be
     */
    public record Api(@DefaultValue("64MB") DataSize maxBodySize) {
    }

    /**
     * The trace store AuthTracer queries.
     *
     * @param lookback how far back to read traces when linking
     * @param limit the most traces to read per service
     */
    @Supports({Feature.TRACE_OBSERVATIONS, Feature.GRAPH_SERVER})
    public record Zipkin(URI baseUrl, Duration lookback, int limit) {
    }
}
