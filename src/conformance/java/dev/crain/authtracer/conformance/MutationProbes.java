package dev.crain.authtracer.conformance;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Boots one version of a fixture with {@link FixtureApps} and sends it callers, saying what Spring did with each, and
 * what each response wrote of the fields asked about. Runs inside a {@link MutantLoader}, so only JDK types cross its
 * boundary.
 */
public final class MutationProbes {

    /**
     * Starts a caller signed in through remember-me.
     */
    static final String REMEMBERED = "remembered:";
    /**
     * A field's state when the handler didn't answer, so the response has no field to read.
     */
    static final String NO_BODY = "-";

    private MutationProbes() {
    }

    /**
     * @param endpoints {@code method, route, params}, then the body paths of the fields to read in its responses
     *        ({@link BodyFields}), tab-separated
     * @param probes {@code endpoint index, caller}, tab-separated: the caller is {@code anonymous}, or the
     *        authorities it holds, comma-separated (none for a caller with none), after {@code remembered:} for one
     *        signed in through remember-me
     * @return how it booted ({@code BOOTED <how>}, {@code NOT_BOOTED <reason>}), then {@code outcome, detail} for
     *         each probe and each of its endpoint's fields' {@link #state}, tab-separated
     */
    public static List<String> run(String fixture, String resources, List<String> endpoints, List<String> probes) {
        List<String> results = new ArrayList<>();
        FixtureApps.App app;
        try {
            app = FixtureApps.boot(fixture, Path.of(resources));
        } catch (FixtureApps.NotBooted e) {
            results.add("NOT_BOOTED\t" + e.getMessage());
            return results;
        } catch (RuntimeException | LinkageError e) {
            results.add("NOT_BOOTED\t" + Clients.root(e));
            return results;
        }
        try (app) {
            results.add("BOOTED\t" + app.how());
            List<Expectation> expectations = new ArrayList<>();
            List<List<String>> fields = new ArrayList<>();
            for (String endpoint : endpoints) {
                String[] cells = endpoint.split("\t", -1);
                expectations.add(new Expectation(fixture, cells[0], cells[1], cells[2], List.of(), ""));
                fields.add(List.of(cells).subList(3, cells.length));
            }
            for (String probe : probes) {
                String[] cells = probe.split("\t", -1);
                String caller = cells[1];
                boolean remembered = caller.startsWith(REMEMBERED);
                Set<String> authorities = new LinkedHashSet<>();
                for (String authority : caller.substring(remembered ? REMEMBERED.length() : 0).split(",")) {
                    if (!authority.isEmpty()) {
                        authorities.add(authority);
                    }
                }
                Authentication user = caller.equals("anonymous") ? null : Callers.user(authorities);
                if (remembered) {
                    user = new RememberMeAuthenticationToken("conformance", user.getPrincipal(),
                            user.getAuthorities());
                }
                Callers.Probe sent = new Callers.Probe(caller, user, false);
                int endpoint = Integer.parseInt(cells[0]);
                Clients.Result result;
                try {
                    result = app.client().send(expectations.get(endpoint), sent);
                } catch (RuntimeException e) {
                    result = new Clients.Result(Clients.Outcome.ERROR, Clients.root(e));
                }
                StringBuilder line = new StringBuilder(result.outcome() + "\t"
                        + result.detail().replaceAll("[\t\n\r]", " "));
                for (String path : fields.get(endpoint)) {
                    line.append('\t').append(state(result, path));
                }
                results.add(line.toString());
            }
        }
        return results;
    }

    /**
     * What a response wrote at a body path: {@code W:<digest of the value>}, {@code NULL}, {@code ABSENT},
     * {@code ?<why it can't be read>}, or {@link #NO_BODY} when the handler didn't answer.
     */
    static String state(Clients.Result result, String path) {
        if (result.outcome() != Clients.Outcome.ALLOWED) {
            return NO_BODY;
        }
        BodyFields.State state = BodyFields.at(result.body(), result.contentType(), path);
        return switch (state.kind()) {
            case WRITTEN -> "W:" + digest(state.value());
            case NULL, ABSENT -> state.kind().name();
            case UNREADABLE -> "?" + state.reason().replaceAll("[\t\n\r]", " ");
        };
    }

    private static String digest(String value) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash, 0, 8);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
