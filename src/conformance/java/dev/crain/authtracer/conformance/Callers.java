package dev.crain.authtracer.conformance;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * The callers an endpoint's clauses call for, and whether the graph says Spring lets each in: one that meets every
 * clause (in), an anonymous one (out) and, for each authority clause, one that has every authority but that clause's
 * (out). A denyAll endpoint gets one caller with every authority (out).
 */
final class Callers {

    /**
     * @param caller {@code null} for an anonymous caller
     */
    record Probe(String label, Authentication caller, boolean denied) {
    }

    private Callers() {
    }

    /**
     * Why no caller can be made up for the endpoint, or {@code null} when one can: an expression or a custom
     * manager's decision, or a remember-me session.
     */
    static String untestable(Expectation expectation) {
        for (Expectation.Clause clause : expectation.clauses()) {
            if (clause.kind().equals("OPAQUE")) {
                return "the requirement is an expression or code: " + expectation.requirement();
            }
            if (clause.kind().equals("REMEMBER_ME")) {
                return "a remember-me session can't be made up";
            }
        }
        return null;
    }

    static List<Probe> of(Expectation expectation) {
        Set<String> every = new LinkedHashSet<>();
        expectation.clauses().forEach(clause -> every.addAll(clause.authorities()));
        List<Probe> probes = new ArrayList<>();
        if (expectation.clauses().stream().anyMatch(clause -> clause.kind().equals("DENY"))) {
            probes.add(new Probe("every authority " + every, user(every), true));
            return probes;
        }
        if (expectation.clauses().isEmpty()) {
            probes.add(new Probe("anonymous", null, false));
            return probes;
        }
        probes.add(new Probe("meets all " + every, user(every), false));
        // ROLE_ANONYMOUS in a clause is an authority like any other: where callers who haven't signed in get a token
        // holding it, the graph has already turned the checks it passes into ones that ask nothing (decision 0063).
        probes.add(new Probe("anonymous", null, true));
        for (Expectation.Clause clause : expectation.clauses()) {
            if (clause.kind().equals("ANY")) {
                Set<String> without = new LinkedHashSet<>(every);
                without.removeAll(clause.authorities());
                probes.add(new Probe("lacks " + clause.authorities(), user(without), true));
            }
        }
        return probes;
    }

    /**
     * An authenticated (not remember-me) caller with the authorities; {@code FACTOR_} ones are factors Spring
     * Security's multi-factor checks accept, issued now.
     */
    static Authentication user(Set<String> authorities) {
        List<GrantedAuthority> granted = new ArrayList<>();
        for (String authority : authorities) {
            granted.add(authority.startsWith("FACTOR_") ? FactorGrantedAuthority.fromAuthority(authority)
                    : new SimpleGrantedAuthority(authority));
        }
        return UsernamePasswordAuthenticationToken.authenticated("conformance", "n/a", granted);
    }
}
