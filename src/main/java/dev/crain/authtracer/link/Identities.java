package dev.crain.authtracer.link;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.IdentityUsage;
import dev.crain.authtracer.graph.Requirement;

/**
 * Decision 0023: for each identity traces show, what it was granted and which of it the checks it passed needed.
 * Spring Security tags every authorization span with the caller's granted authorities
 * ({@code spring.security.authentication.authorities}) next to the decision.
 */
@Supports(Feature.IDENTITIES)
final class Identities {

    private static final String AUTHORITIES = "spring.security.authentication.authorities";
    private static final String TYPE = "spring.security.authentication.type";
    private static final String ANONYMOUS = "AnonymousAuthenticationToken";
    /**
     * What Spring Security's observation convention tags when there is no {@code Authentication} at all, e.g. a
     * health check on a permitted path.
     */
    private static final String NONE = "n/a";
    /**
     * An authority object printed with its fields, e.g. {@code FactorGrantedAuthority [authority=FACTOR_BEARER, ..]}.
     */
    private static final Pattern WRAPPED = Pattern.compile("\\[authority=([^,\\]]+)");
    /**
     * Spring Security 7 grants these itself, one per authentication factor; they are not what an identity was given.
     */
    private static final String FACTOR = "FACTOR_";

    private final Map<String, Identity> byKey = new LinkedHashMap<>();

    /**
     * The identity a request's authorization spans were evaluated for, counting the request; empty when they name
     * none, an anonymous one, or no authentication at all.
     */
    Optional<Identity> request(List<TraceSpan> decisions, String endpoint) {
        for (TraceSpan decision : decisions) {
            Optional<String> authorities = decision.tag(AUTHORITIES);
            if (authorities.isEmpty()) {
                continue;
            }
            String type = decision.tag(TYPE).orElse("?");
            if (type.equals(ANONYMOUS) || type.equals(NONE)) {
                return Optional.empty();
            }
            List<String> granted = granted(authorities.get());
            Identity identity = byKey.computeIfAbsent(type + " " + granted, key -> new Identity(granted, type));
            identity.requests++;
            identity.endpoints.add(endpoint);
            return Optional.of(identity);
        }
        return Optional.empty();
    }

    List<IdentityUsage> usages() {
        List<IdentityUsage> usages = new ArrayList<>();
        for (Identity identity : byKey.values()) {
            List<String> unneeded = identity.granted.stream().filter(authority -> !identity.needed.contains(authority))
                    .toList();
            usages.add(new IdentityUsage(identity.granted, identity.type, identity.requests,
                    new ArrayList<>(identity.endpoints), new ArrayList<>(identity.needed), unneeded, identity.denied,
                    identity.unread));
        }
        return usages;
    }

    /**
     * The authorities in Spring's {@code Collection#toString} of them, sorted, without the {@code FACTOR_} ones.
     */
    static List<String> granted(String tag) {
        String list = tag.strip();
        if (list.startsWith("[") && list.endsWith("]")) {
            list = list.substring(1, list.length() - 1);
        }
        Set<String> granted = new TreeSet<>();
        int depth = 0;
        int start = 0;
        for (int i = 0; i <= list.length(); i++) {
            char c = i < list.length() ? list.charAt(i) : ',';
            if (c == '[') {
                depth++;
            }
            else if (c == ']') {
                depth--;
            }
            else if (c == ',' && depth == 0) {
                String item = list.substring(start, i).strip();
                Matcher wrapped = WRAPPED.matcher(item);
                String authority = wrapped.find() ? wrapped.group(1).strip() : item;
                if (!authority.isEmpty() && !authority.startsWith(FACTOR)) {
                    granted.add(authority);
                }
                start = i + 1;
            }
        }
        return List.copyOf(granted);
    }

    static final class Identity {

        private final List<String> granted;
        private final String type;
        private final Set<String> endpoints = new TreeSet<>();
        private final Set<String> needed = new TreeSet<>();
        private long requests;
        private long denied;
        private long unread;

        private Identity(List<String> granted, String type) {
            this.granted = granted;
            this.type = type;
        }

        /**
         * One check on one of its requests. What the check asked for is read from the decision when Spring names the
         * authorities, else from the static Location it matched, whose role checks include the roles a
         * RoleHierarchy lets in.
         *
         * @param details the decision's details, e.g. {@code AuthorityAuthorizationDecision [granted=true,
         *        authorities=[ROLE_ADMIN]]}
         * @param requirement the matched Location's requirement, if it matched one
         */
        void check(boolean allowed, String details, Optional<Requirement> requirement) {
            if (!allowed) {
                denied++;
                return;
            }
            Set<String> held = held(Linker.askedAuthorities(details));
            if (held.isEmpty()) {
                held = held(requirement.map(Identity::authorities).orElse(Set.of()));
            }
            needed.addAll(held);
            boolean needsNothing = requirement.map(found -> found.kind() == Requirement.Kind.PERMIT_ALL
                    || found.kind() == Requirement.Kind.AUTHENTICATED
                    || found.kind() == Requirement.Kind.FULLY_AUTHENTICATED
                    || found.kind() == Requirement.Kind.REMEMBER_ME
                    || found.kind() == Requirement.Kind.ANONYMOUS)
                    .orElse(Linker.askedAuthorities(details).isEmpty() && !Linker.namesExpression(details));
            if (held.isEmpty() && !needsNothing) {
                unread++;
            }
        }

        private Set<String> held(Set<String> authorities) {
            Set<String> held = new TreeSet<>(authorities);
            held.retainAll(granted);
            return held;
        }

        private static Set<String> authorities(Requirement requirement) {
            Set<String> all = new TreeSet<>(requirement.authorities());
            requirement.operands().forEach(operand -> all.addAll(authorities(operand)));
            return all;
        }
    }
}
