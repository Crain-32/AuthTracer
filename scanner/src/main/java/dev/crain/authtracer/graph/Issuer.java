package dev.crain.authtracer.graph;

import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * What an authorization server issues tokens with (SRC-19, decision 0075): the clients registered with it and the
 * scopes each can be granted. A token it issues carries only scopes of the client it is issued to.
 *
 * @param clients each registered client's id and the scopes it can be granted
 * @param claims the claims its token customizers add, by name
 * @param unread what AuthTracer can't read that may let a token carry other scopes: a client store, clients
 *        registered at run time, a customizer that writes the scope claim
 */
@Supports({Feature.CALL_CREDENTIALS, Feature.FINDING_TOKEN_REJECTED, Feature.FINDING_ALWAYS_DENIED,
        Feature.APPLICATION_GRAPH})
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record Issuer(SortedMap<String, SortedSet<String>> clients, SortedSet<String> claims,
        SortedSet<String> unread) {

    public Issuer {
        SortedMap<String, SortedSet<String>> copied = new TreeMap<>();
        if (clients != null) {
            clients.forEach((client, scopes) -> copied.put(client, new TreeSet<>(scopes)));
        }
        clients = copied;
        claims = claims == null ? new TreeSet<>() : new TreeSet<>(claims);
        unread = unread == null ? new TreeSet<>() : new TreeSet<>(unread);
    }

    /**
     * Every scope a token it issues may carry, when AuthTracer reads them all.
     */
    public SortedSet<String> scopes() {
        SortedSet<String> scopes = new TreeSet<>();
        clients.values().forEach(scopes::addAll);
        return scopes;
    }
}
