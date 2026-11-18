package dev.crain.authtracer.scan.spring;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.scan.CallTraversal;
import dev.crain.authtracer.scan.Locals;
import sootup.core.graph.ControlFlowGraph;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0070 (amended): a servlet filter hands the request on with {@code chain.doFilter(request, response)}, which
 * returns once everything after it, the handler included, has run. What the filter's own body does on the way from
 * that call (its statements reachable from it) runs after the handler, not at the filter's place before it.
 */
@Supports(Feature.CALL_PATHS)
final class FilterChainCalls {

    private static final String FILTER_CHAIN = "jakarta.servlet.FilterChain";

    /**
     * A filter method's steps: before it hands the request on, and after.
     */
    record Split(List<CallTraversal.Step> before, List<CallTraversal.Step> after) {
    }

    private FilterChainCalls() {
    }

    static Split walk(CallTraversal traversal, JavaSootMethod filter, ClassType receiver,
            CallTraversal.Listener listener) {
        Set<Stmt> later = afterChain(filter);
        if (later.isEmpty()) {
            return new Split(traversal.walk(filter.getSignature(), receiver, listener), List.of());
        }
        Sorting sorting = new Sorting(listener, filter, later);
        List<CallTraversal.Step> before = new ArrayList<>();
        List<CallTraversal.Step> after = new ArrayList<>();
        for (CallTraversal.Step step : traversal.walk(filter.getSignature(), receiver, sorting)) {
            (sorting.after.contains(step.nodeId()) && !sorting.before.contains(step.nodeId()) ? after : before)
                    .add(step);
        }
        return new Split(before, after);
    }

    /**
     * The statements of the method reachable from its {@code chain.doFilter(..)} calls, through an exception the
     * chain throws too (a {@code finally} block's copy for it).
     */
    private static Set<Stmt> afterChain(JavaSootMethod method) {
        if (!method.hasBody()) {
            return Set.of();
        }
        ControlFlowGraph<?> graph = method.getBody().getControlFlowGraph();
        Set<Stmt> reached = new HashSet<>();
        Deque<Stmt> queue = new ArrayDeque<>();
        for (Stmt stmt : method.getBody().getStmts()) {
            if (Locals.invoke(stmt).filter(FilterChainCalls::handsOn).isPresent()) {
                queue.addAll(graph.getAllSuccessors(stmt));
            }
        }
        while (!queue.isEmpty()) {
            Stmt next = queue.removeFirst();
            if (reached.add(next)) {
                queue.addAll(graph.getAllSuccessors(next));
            }
        }
        return reached;
    }

    private static boolean handsOn(AbstractInvokeExpr invoke) {
        return invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName().equals(FILTER_CHAIN)
                && invoke.getMethodSignature().getName().equals("doFilter");
    }

    /**
     * Tells apart the nodes reached through the filter's statements before the request is handed on and after.
     */
    private static final class Sorting implements CallTraversal.Listener {

        private final CallTraversal.Listener listener;
        private final JavaSootMethod filter;
        private final Set<Stmt> later;
        private final Set<String> before = new HashSet<>();
        private final Set<String> after = new HashSet<>();
        private boolean handedOn;

        private Sorting(CallTraversal.Listener listener, JavaSootMethod filter, Set<Stmt> later) {
            this.listener = listener;
            this.filter = filter;
            this.later = later;
        }

        private List<String> sort(List<String> ids) {
            (handedOn ? after : before).addAll(ids);
            return ids;
        }

        @Override
        public List<String> onEnter(JavaSootMethod method, AbstractInvokeExpr call, boolean viaThis,
                List<String> stack) {
            return sort(listener.onEnter(method, call, viaThis, stack));
        }

        @Override
        public List<String> onCallSite(JavaSootMethod caller, Stmt stmt, AbstractInvokeExpr invoke) {
            if (caller.equals(filter)) {
                handedOn = later.contains(stmt);
            }
            return sort(listener.onCallSite(caller, stmt, invoke));
        }

        @Override
        public List<String> onExit(JavaSootMethod method, boolean viaThis) {
            if (method.equals(filter)) {
                handedOn = false;
            }
            return sort(listener.onExit(method, viaThis));
        }

        @Override
        public List<String> onBranches(JavaSootMethod method, List<List<String>> branches, List<String> conditional) {
            if (method.equals(filter)) {
                handedOn = false;
            }
            return sort(listener.onBranches(method, branches, conditional));
        }

        @Override
        public List<String> onTooDeep(JavaSootMethod method, AbstractInvokeExpr call, int limit) {
            return sort(listener.onTooDeep(method, call, limit));
        }

        @Override
        public List<String> onDispatch(JavaSootMethod caller, AbstractInvokeExpr call, List<JavaSootMethod> targets,
                List<List<String>> reached) {
            return sort(listener.onDispatch(caller, call, targets, reached));
        }
    }
}
