package dev.crain.authtracer.graph;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

class RequirementTests {

    private static final Requirement ADMIN = Requirement.anyAuthority(List.of("ROLE_ADMIN"));

    @Test
    void anyonePassesPermitAllAndWhatOnlyCombinesIt() {
        assertThat(Requirement.permitAll().permitsAnyone()).isTrue();
        assertThat(Requirement.and(List.of(Requirement.permitAll(), Requirement.permitAll())).permitsAnyone())
                .isTrue();
        assertThat(Requirement.or(List.of(ADMIN, Requirement.permitAll())).permitsAnyone()).isTrue();
        // One check of an AND still asks.
        assertThat(Requirement.and(List.of(Requirement.permitAll(), ADMIN)).permitsAnyone()).isFalse();
        assertThat(Requirement.authenticated().permitsAnyone()).isFalse();
        assertThat(Requirement.not(ADMIN).permitsAnyone()).isFalse();
    }
}
