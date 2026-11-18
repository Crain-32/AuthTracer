package dev.crain.authtracer.scan;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import sootup.core.graph.ControlFlowGraph;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.JReturnVoidStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0027: which statements of a method run on every way it returns normally. A statement dominates a return
 * when every path from the method's start to the return passes it. Only normal control flow counts: a catch block
 * runs after something in its try block threw, which says nothing about which calls ran, so its returns don't make
 * the try block's calls conditional. The exception is a handler that catches a denial ({@code AccessDeniedException}
 * or a supertype) and goes on to return: a check that denies there is swallowed, so the call is one way, the handler
 * another.
 */
@Supports(Feature.CALL_PATHS)
public final class Branches {

    static final int MAX_ALTERNATIVES = 32;
    /**
     * What a check throws when it denies, and the types a handler catches it as.
     */
    private static final Set<String> DENIALS = Set.of("org.springframework.security.access.AccessDeniedException",
            "org.springframework.security.authorization.AuthorizationDeniedException", "java.lang.RuntimeException",
            "java.lang.Exception", "java.lang.Throwable");

    private final ControlFlowGraph<?> graph;
    private final List<Stmt> returns;
    private final Map<Stmt, Set<Stmt>> reachableAvoiding = new HashMap<>();
    /**
     * For each call whose denial a handler swallows, the handlers that go on to return.
     */
    private final Map<Stmt, List<Stmt>> swallowing = new HashMap<>();

    private Branches(ControlFlowGraph<?> graph) {
        this.graph = graph;
        this.returns = graph.getNodes().stream()
                .filter(stmt -> stmt instanceof JReturnStmt || stmt instanceof JReturnVoidStmt).toList();
        Map<Stmt, Boolean> returning = new HashMap<>();
        for (Stmt stmt : graph.getNodes()) {
            if (Locals.invoke(stmt).isEmpty()) {
                continue;
            }
            List<Stmt> handlers = graph.exceptionalSuccessors(stmt).entrySet().stream()
                    .filter(entry -> DENIALS.contains(entry.getKey().getFullyQualifiedName()))
                    .map(Map.Entry::getValue).distinct()
                    .filter(handler -> returning.computeIfAbsent(handler, this::returns)).toList();
            if (!handlers.isEmpty()) {
                swallowing.put(stmt, handlers);
            }
        }
    }

    public static Branches of(JavaSootMethod method) {
        return new Branches(method.getBody().getControlFlowGraph());
    }

    /**
     * Whether the statement runs before every normal return (trivially so for a method that never returns).
     */
    public boolean onEveryReturn(Stmt stmt) {
        return !swallowing.containsKey(stmt) && returns.stream().allMatch(exit -> dominates(stmt, exit));
    }

    public boolean dominates(Stmt stmt, Stmt exit) {
        return !reachableAvoiding.computeIfAbsent(stmt, this::reachableAvoiding).contains(exit);
    }

    /**
     * The ways through the method: for every path from its start to a normal return, the nodes the conditional calls
     * on it reach. Paths that merge keep their alternatives apart, so {@code flag ? a() : b()} gives {a} and {b}.
     * Past {@link #MAX_ALTERNATIVES} the alternatives collapse to what they all share, which can only ask less.
     *
     * @param reached the nodes each conditional call reaches
     */
    public List<Set<String>> alternatives(Map<Stmt, ? extends Collection<String>> reached) {
        return alternatives(reached, () -> { });
    }

    /**
     * @param collapsed told when the alternatives collapse
     */
    public List<Set<String>> alternatives(Map<Stmt, ? extends Collection<String>> reached, Runnable collapsed) {
        Map<Stmt, Set<Set<String>>> before = new HashMap<>();
        Stmt start = graph.getStartingStmt();
        before.put(start, new HashSet<>(Set.of(Set.of())));
        Deque<Stmt> work = new ArrayDeque<>(List.of(start));
        while (!work.isEmpty()) {
            Stmt stmt = work.removeFirst();
            Set<Set<String>> after = new HashSet<>();
            for (Set<String> alternative : before.get(stmt)) {
                Set<String> extended = new TreeSet<>(alternative);
                Collection<String> here = reached.get(stmt);
                if (here != null) {
                    extended.addAll(here);
                }
                after.add(Set.copyOf(extended));
            }
            List<Map.Entry<Stmt, Set<Set<String>>>> edges = new ArrayList<>();
            graph.successors(stmt).forEach(next -> edges.add(Map.entry(next, after)));
            // A denial the handler swallows: the call's checks didn't let the request through, it went on anyway.
            Set<Set<String>> denied = Set.copyOf(before.get(stmt));
            swallowing.getOrDefault(stmt, List.of()).forEach(handler -> edges.add(Map.entry(handler, denied)));
            for (Map.Entry<Stmt, Set<Set<String>>> edge : edges) {
                Stmt next = edge.getKey();
                Set<Set<String>> merged = before.computeIfAbsent(next, key -> new HashSet<>());
                if (merged.addAll(edge.getValue())) {
                    if (merged.size() > MAX_ALTERNATIVES) {
                        collapsed.run();
                        Set<String> shared = new TreeSet<>(merged.iterator().next());
                        merged.forEach(shared::retainAll);
                        merged.clear();
                        merged.add(Set.copyOf(shared));
                    }
                    work.addLast(next);
                }
            }
        }
        Set<Set<String>> ways = new HashSet<>();
        for (Stmt exit : returns) {
            ways.addAll(before.getOrDefault(exit, Set.of()));
        }
        return ways.stream().sorted(Comparator.comparing(Set::toString)).toList();
    }

    /**
     * Whether a normal return is reachable from the statement.
     */
    private boolean returns(Stmt from) {
        Set<Stmt> reached = new HashSet<>(Set.of(from));
        Deque<Stmt> queue = new ArrayDeque<>(List.of(from));
        while (!queue.isEmpty()) {
            Stmt stmt = queue.removeFirst();
            if (stmt instanceof JReturnStmt || stmt instanceof JReturnVoidStmt) {
                return true;
            }
            for (Stmt next : graph.successors(stmt)) {
                if (reached.add(next)) {
                    queue.add(next);
                }
            }
        }
        return false;
    }

    /**
     * The statements reachable from the start without passing {@code avoided}.
     */
    private Set<Stmt> reachableAvoiding(Stmt avoided) {
        Set<Stmt> reached = new HashSet<>();
        Deque<Stmt> queue = new ArrayDeque<>();
        Stmt start = graph.getStartingStmt();
        if (!start.equals(avoided)) {
            queue.add(start);
            reached.add(start);
        }
        while (!queue.isEmpty()) {
            for (Stmt next : graph.successors(queue.removeFirst())) {
                if (!next.equals(avoided) && reached.add(next)) {
                    queue.add(next);
                }
            }
        }
        return reached;
    }
}
