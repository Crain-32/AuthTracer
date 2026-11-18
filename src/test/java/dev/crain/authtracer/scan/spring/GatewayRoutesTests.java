package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.Egress;
import org.junit.jupiter.api.Test;

class GatewayRoutesTests {

    @Test
    void theFiltersForwardToThePathTheyMake() {
        assertThat(GatewayRoutes.downstream("/api/orders/**", List.of("StripPrefix=1"))).isEqualTo("/orders/**");
        // Spring Cloud Gateway strips one part unless it is told how many.
        assertThat(GatewayRoutes.downstream("/api/orders/**", List.of("StripPrefix"))).isEqualTo("/orders/**");
        assertThat(GatewayRoutes.downstream("/api/orders/**", List.of("StripPrefix=2", "PrefixPath=/v2")))
                .isEqualTo("/v2/**");
    }

    /**
     * A count that isn't a number (an unresolved placeholder) or a rewrite that can't be applied: where the request
     * goes isn't known, which the linker reports, instead of a guessed path.
     */
    @Test
    void aFilterAuthTracerCantReadLeavesTheTargetUnknown() {
        assertThat(GatewayRoutes.downstream("/api/orders/**", List.of("StripPrefix=${strip.parts}")))
                .isEqualTo(Egress.UNKNOWN_TARGET);
        assertThat(GatewayRoutes.downstream("/api/orders/**", List.of("RewritePath=/api/(?<rest, /${rest}")))
                .isEqualTo(Egress.UNKNOWN_TARGET);
    }
}
