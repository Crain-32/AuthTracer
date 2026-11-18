package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiFunction;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.FieldSignature;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.core.types.Type;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0048: with {@code @EnableAsync}, a call to an {@code @Async} method through its proxy runs on another
 * thread, and Spring's {@code AsyncAnnotationBeanPostProcessor} puts its advisor before the existing ones (6.2/7.0
 * bytecode: {@code setBeforeExistingAdvisors(true)}, after the auto-proxy creator at the highest precedence), so
 * even the method's own checks run there. The {@code SecurityContext} is thread-local: without an executor that
 * carries it over, what runs there has no caller. Carried over by Spring Security's
 * {@code DelegatingSecurityContext*} executors, a {@code TaskDecorator} that copies it, or a strategy other than
 * the thread-local one ({@code SecurityContextHolder.setStrategyName(..)}, {@code setContextHolderStrategy(..)}, a
 * {@code SecurityContextHolderStrategy} bean; the {@code spring.security.strategy} system property isn't an
 * application property, so it isn't read).
 * <p>
 * Decision 0062: so does a lambda or method reference handed to another thread: a task executor's
 * ({@code execute}, {@code submit}, {@code schedule}, ...) unless something carries the context over as above;
 * {@code CompletableFuture}'s {@code *Async} methods, which without an executor run on the common pool that no
 * decorator reaches; and a new or virtual {@code Thread}, which only an inheritable strategy reaches.
 * <p>
 * Decision 0084: a lambda a Reactor pipeline runs on a {@code Scheduler}'s thread ({@code subscribeOn},
 * {@code publishOn}) leaves the thread-local context behind too, but not the Reactor {@code Context} that reactive
 * method security reads; an {@code @Async("name")} method runs on that executor, which carries the context only if
 * it does; and a caller that waits for the other thread's result ({@code get()}, {@code join()}, {@code block()},
 * or a handler that returns it to Spring) sees its denial.
 */
@Supports(Feature.CALL_PATHS)
final class AsyncCalls {

    private static final String ENABLE = "org.springframework.scheduling.annotation.EnableAsync";
    private static final String ASYNC = "org.springframework.scheduling.annotation.Async";
    private static final String TASK_DECORATOR = "org.springframework.core.task.TaskDecorator";
    private static final String CONTEXT_PROPAGATING_DECORATOR =
            "org.springframework.core.task.support.ContextPropagatingTaskDecorator";
    private static final Set<String> PROPAGATING = Set.of(
            "org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor",
            "org.springframework.security.task.DelegatingSecurityContextTaskExecutor",
            "org.springframework.security.scheduling.DelegatingSecurityContextTaskScheduler",
            "org.springframework.security.concurrent.DelegatingSecurityContextExecutor",
            "org.springframework.security.concurrent.DelegatingSecurityContextExecutorService",
            "org.springframework.security.concurrent.DelegatingSecurityContextScheduledExecutorService",
            CONTEXT_PROPAGATING_DECORATOR);
    private static final String SECURITY_CONTEXT_HOLDER =
            "org.springframework.security.core.context.SecurityContextHolder";
    private static final String SECURITY = "org.springframework.security.";
    private static final String STRATEGY = SECURITY + "core.context.SecurityContextHolderStrategy";
    private static final String THREAD_LOCAL_STRATEGY = SECURITY + "core.context.ThreadLocalSecurityContextHolderStrategy";
    private static final String THREAD_LOCAL_CLASS = "java.lang.ThreadLocal";
    private static final String INHERITABLE = "java.lang.InheritableThreadLocal";
    /**
     * What a {@code TaskDecorator} uses when it copies the caller's {@code SecurityContext} to the task: the holder or
     * a context, Spring Security's delegating tasks, or Micrometer's context propagation, for which Spring Security
     * 7.1.1 registers {@code SecurityContextHolderThreadLocalAccessor} ({@code META-INF/services}).
     */
    private static final Set<String> COPIES_CONTEXT = Set.of(SECURITY_CONTEXT_HOLDER, STRATEGY,
            SECURITY + "core.context.SecurityContext", SECURITY + "concurrent.DelegatingSecurityContextRunnable",
            SECURITY + "concurrent.DelegatingSecurityContextCallable", "io.micrometer.context.ContextSnapshot",
            "io.micrometer.context.ContextSnapshotFactory", CONTEXT_PROPAGATING_DECORATOR);
    /**
     * {@code SecurityContextHolder.MODE_THREADLOCAL}, which javac inlines.
     */
    private static final String THREAD_LOCAL = "MODE_THREADLOCAL";
    private static final String EXECUTOR = "java.util.concurrent.Executor";
    private static final Set<String> COMPLETABLE = Set.of("java.util.concurrent.CompletableFuture",
            "java.util.concurrent.CompletionStage");
    private static final Set<String> FUTURES = Set.of("java.util.concurrent.CompletableFuture",
            "java.util.concurrent.CompletionStage", "java.util.concurrent.Future",
            "java.util.concurrent.FutureTask", "java.util.concurrent.ScheduledFuture");
    /**
     * Executors and schedulers by their declared types, and the interfaces any other one implements.
     */
    private static final Set<String> EXECUTORS = Set.of(EXECUTOR, "java.util.concurrent.ExecutorService",
            "java.util.concurrent.ScheduledExecutorService", "java.util.concurrent.AbstractExecutorService",
            "java.util.concurrent.ThreadPoolExecutor", "java.util.concurrent.ScheduledThreadPoolExecutor",
            "java.util.concurrent.ForkJoinPool", "org.springframework.core.task.TaskExecutor",
            "org.springframework.core.task.AsyncTaskExecutor", "org.springframework.core.task.SimpleAsyncTaskExecutor",
            "org.springframework.scheduling.TaskScheduler",
            "org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor",
            "org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler",
            "org.springframework.scheduling.concurrent.ConcurrentTaskExecutor",
            "org.springframework.scheduling.concurrent.SimpleAsyncTaskScheduler");
    private static final Set<String> SUBMITS = Set.of("execute", "submit", "submitCompletable", "submitListenable",
            "schedule", "scheduleAtFixedRate", "scheduleWithFixedDelay");
    /**
     * Executors that start a thread for each task, which inherits from the caller's thread: no pool.
     */
    private static final Set<String> THREAD_PER_TASK = Set.of("org.springframework.core.task.SimpleAsyncTaskExecutor",
            "org.springframework.scheduling.concurrent.SimpleAsyncTaskScheduler");
    /**
     * Boot's executor builders, to which Boot 4.1.1 applies the application's {@code TaskDecorator} bean
     * ({@code TaskExecutorConfigurations}).
     */
    private static final Set<String> BOOT_BUILDERS = Set.of("org.springframework.boot.task.ThreadPoolTaskExecutorBuilder",
            "org.springframework.boot.task.SimpleAsyncTaskExecutorBuilder");
    private static final Set<String> REACTOR = Set.of("reactor.core.publisher.Mono", "reactor.core.publisher.Flux");
    /**
     * Calls that put what they are given into a collection.
     */
    private static final Set<String> COLLECTS = Set.of("add", "addAll", "addFirst", "addLast", "put", "putIfAbsent",
            "offer", "offerFirst", "offerLast", "push", "set");
    /**
     * How far a pipeline's chain is followed back in one method.
     */
    private static final int MAX_CHAIN = 32;
    /**
     * How many methods deep a future or pipeline is followed: into lambdas, the methods that return or take it.
     */
    private static final int MAX_METHODS = 3;
    /**
     * What a handler returns that Spring answers the request with when it completes.
     */
    private static final Set<String> ANSWERED = Set.of("java.util.concurrent.CompletableFuture",
            "java.util.concurrent.CompletionStage", "reactor.core.publisher.Mono", "reactor.core.publisher.Flux",
            "org.reactivestreams.Publisher");
    /**
     * Waiting for a future or a pipeline's result: it rethrows what failed on the other thread.
     */
    private static final Set<String> WAITS = Set.of("get", "join", "resultNow", "block", "blockFirst", "blockLast",
            "blockOptional", "toIterable", "toStream");
    /**
     * Operators that recover from a failure: what failed upstream doesn't reach whoever waits downstream.
     */
    private static final Set<String> RECOVERS = Set.of("exceptionally", "exceptionallyCompose", "handle",
            "exceptionallyAsync", "exceptionallyComposeAsync", "handleAsync", "onErrorResume", "onErrorReturn",
            "onErrorComplete", "onErrorContinue", "onErrorMap");
    /**
     * Exceptions a handler may catch the other thread's failure as, from a wait.
     */
    private static final Set<String> CAUGHT = Set.of("java.util.concurrent.ExecutionException",
            "java.util.concurrent.CompletionException", "java.lang.RuntimeException", "java.lang.Exception",
            "java.lang.Throwable", SECURITY + "core.AuthenticationException",
            SECURITY + "authentication.AuthenticationCredentialsNotFoundException",
            SECURITY + "access.AccessDeniedException");

    /**
     * A hand-off to another thread.
     *
     * @param thread what takes the work there, e.g. {@code ExecutorService.submit}
     * @param waiter the method that waits for its result, so sees its failure, {@code null} when none does
     * @param pooled whether the thread is a pool's, which the strategy alone gives a context: the one it got when it
     *        was created, not the caller's
     */
    record HandOff(String thread, String waiter, boolean pooled) {

        HandOff(String thread, String waiter) {
            this(thread, waiter, false);
        }
    }

    /**
     * Where work starts on another thread.
     *
     * @param thread what takes the work there, e.g. {@code ExecutorService.submit}
     * @param at the statement whose result stands for the work: the future or pipeline
     */
    record Started(String thread, Stmt at) {
    }

    /**
     * Where a method on the walk was called from.
     */
    record Site(JavaSootMethod method, Stmt stmt) {
    }

    /**
     * The walk's entry, the handler, which Spring calls.
     */
    static final Site ENTRY = new Site(null, null);

    /**
     * What a method does with the result of a call that starts work on another thread.
     */
    private enum Wait {
        /**
         * It waits for it ({@code get()}, {@code join()}, {@code block()}): the other thread's failure is its own.
         */
        WAITS,
        /**
         * It returns it to its caller.
         */
        RETURNS,
        /**
         * It goes on, catches the failure, or recovers from it.
         */
        NONE
    }

    private final ScanContext context;
    /**
     * What carries the SecurityContext to other threads.
     */
    private final Set<String> propagation;
    private final boolean asyncEnabled;
    /**
     * Whether a Reactor scheduler's thread gets the context the caller's thread has.
     */
    private final boolean reactorCarries;
    private final Map<String, Boolean> executors = new HashMap<>();

    AsyncCalls(ScanContext context) {
        this.context = context;
        this.propagation = propagation();
        this.asyncEnabled = context.anyClassAnnotated(ENABLE);
        this.reactorCarries = reactorCarries();
    }

    /**
     * Whether calling the method leaves the caller's thread, and its SecurityContext, behind: an {@code @Async}
     * method (or one of an {@code @Async} class) whose executor doesn't carry the context over.
     */
    boolean hops(JavaSootMethod method, boolean viaThis) {
        if (!asyncEnabled || viaThis) {
            // A call on this doesn't go through the proxy: it runs right there.
            return false;
        }
        Optional<AnnotationUsage> async = context.findAnnotation(method, ASYNC).or(() -> context.findClass(
                method.getDeclaringClassType()).flatMap(cls -> context.findAnnotation(cls, ASYNC)));
        if (async.isEmpty()) {
            return false;
        }
        // Decision 0084: @Async("name") runs on that executor bean (AsyncExecutionAspectSupport's
        // findQualifiedExecutor), the qualifier's placeholders resolved.
        Optional<String> qualifier = Annotations.string(async.get(), "value").filter(name -> !name.isEmpty())
                .map(name -> context.properties().resolveKnown(name));
        return qualifier.map(name -> !executorCarries(name)).orElse(propagation.isEmpty());
    }

    /**
     * Decision 0084: the method that waits for the work a statement starts on another thread (an {@code @Async}
     * call, or a hand-off): the first on the way up that waits for its result, through those that return it to their
     * callers, or the handler that returns it to Spring.
     *
     * @param start where the work starts
     * @param callers where each method on the way up was called from, innermost first, down to {@link #ENTRY}
     */
    Optional<String> waiter(Site start, Iterator<Site> callers) {
        Site site = start;
        while (true) {
            Outcome outcome = waits(site.method(), site.stmt());
            if (outcome.kind() == Wait.WAITS) {
                return Optional.of(MethodNames.key(site.method().getSignature()));
            }
            boolean returned = outcome.kind() == Wait.RETURNS;
            Site caller = (returned || !outcome.kept().isEmpty()) && callers.hasNext() ? callers.next() : null;
            if (caller == ENTRY && returned) {
                // Spring MVC 7.0.9 answers a CompletionStage when it completes (DeferredResultMethodReturnValueHandler)
                // and a publisher when it signals, as WebFlux does; a plain Future is a body like any other.
                return ANSWERED.contains(site.method().getReturnType().toString())
                        ? Optional.of(MethodNames.key(site.method().getSignature())) : Optional.empty();
            }
            if (caller == null || caller.method() == null) {
                return Optional.empty();
            }
            if (!returned) {
                return laterWait(caller, outcome.kept());
            }
            site = caller;
        }
    }

    /**
     * Decision 0099: the method the caller calls after the one that kept the future in a field (or in a collection a
     * field holds) that reads the field and waits on it: {@code batch.start(..); return batch.await();}.
     */
    private Optional<String> laterWait(Site caller, Set<FieldSignature> kept) {
        List<Stmt> stmts = caller.method().getBody().getStmts();
        return stmts.subList(stmts.indexOf(caller.stmt()) + 1, stmts.size()).stream()
                .flatMap(stmt -> Locals.invoke(stmt).stream())
                .filter(call -> context.isApplication(call.getMethodSignature().getDeclClassType()))
                .flatMap(call -> context.findMethod(call.getMethodSignature()).filter(JavaSootMethod::hasBody).stream())
                .filter(method -> scan(method, Set.of(), kept, 1).kind() == Wait.WAITS).findFirst()
                .map(method -> MethodNames.key(method.getSignature()));
    }

    /**
     * Decision 0062: the thread the lambda or method reference the statement creates is handed to, when it runs there
     * without the caller's SecurityContext: the call that hands it over, e.g. {@code ExecutorService.submit}, and
     * where.
     *
     * @param callers where each method on the way up was called from, innermost first, down to {@link #ENTRY}
     */
    Optional<Started> handsOff(JavaSootMethod caller, Stmt stmt, Iterator<Site> callers) {
        return handOff(caller, stmt, (use, invoke) -> REACTOR.contains(invoke.getMethodSignature().getDeclClassType()
                .getFullyQualifiedName()) ? reactor(caller, use, invoke, callers)
                        : thread(invoke.getMethodSignature()));
    }

    /**
     * Decision 0084, amended: the pool the lambda or method reference the statement creates is handed to, when only
     * a strategy that isn't thread-local carries the SecurityContext there. A pooled thread doesn't take the caller's
     * context: an inheritable strategy gave it the context of the request that created the thread, and keeps it for
     * every task after; the global one, whatever was set last. The call that hands it over, and where.
     */
    Optional<Started> handsOffToPool(JavaSootMethod caller, Stmt stmt) {
        return handOff(caller, stmt, (use, invoke) -> pool(invoke.getMethodSignature()));
    }

    private Optional<Started> handOff(JavaSootMethod caller, Stmt stmt,
            BiFunction<Stmt, AbstractInvokeExpr, Optional<String>> takes) {
        if (!(stmt instanceof AbstractDefinitionStmt definition)
                || !(definition.getRightOp() instanceof JDynamicInvokeExpr)
                || !(definition.getLeftOp() instanceof Local created)) {
            return Optional.empty();
        }
        Set<Local> values = new HashSet<>(Set.of(created));
        for (Stmt use : caller.getBody().getStmts()) {
            if (use instanceof AbstractDefinitionStmt copy && copy.getLeftOp() instanceof Local to
                    && copy.getRightOp() instanceof Local from && values.contains(from)) {
                values.add(to);
                continue;
            }
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(use);
            if (invoke.isPresent() && invoke.get().getArgs().stream().anyMatch(values::contains)) {
                Optional<String> thread = takes.apply(use, invoke.get());
                if (thread.isPresent()) {
                    return Optional.of(new Started(thread.get(), use));
                }
            }
        }
        return Optional.empty();
    }

    /**
     * A pool a hand-off reaches with the context only the strategy gives it: an executor's, or the common pool or
     * executor of {@code CompletableFuture}'s {@code *Async}. Not one that starts a thread for each task from the
     * caller's (Spring 7.0.9: {@code SimpleAsyncTaskExecutor}, and {@code SimpleAsyncTaskScheduler}'s
     * {@code execute}/{@code submit}; its {@code schedule*} start them from its trigger thread).
     */
    private Optional<String> pool(MethodSignature signature) {
        String owner = signature.getDeclClassType().getFullyQualifiedName();
        String name = signature.getName();
        String call = MethodNames.simpleName(owner).replace('$', '.') + "." + name;
        if (!propagation.equals(Set.of(SECURITY_CONTEXT_HOLDER))) {
            return Optional.empty();
        }
        if (COMPLETABLE.contains(owner) && name.endsWith("Async")) {
            return Optional.of(call);
        }
        boolean perTask = THREAD_PER_TASK.contains(owner) && !name.startsWith("schedule");
        return SUBMITS.contains(name) && !perTask && executor(signature.getDeclClassType()) ? Optional.of(call)
                : Optional.empty();
    }

    /**
     * Decision 0084, amended: an {@code @Async} method the strategy alone carries the context to, on a pool: the
     * executor bean its name names, unless it starts a thread per task or carries the context itself; unnamed, Boot's
     * {@code applicationTaskExecutor}, a {@code ThreadPoolTaskExecutor} unless virtual threads are on.
     */
    Optional<String> pooledAsync(JavaSootMethod method, boolean viaThis) {
        Optional<AnnotationUsage> async = viaThis || !asyncEnabled ? Optional.empty()
                : context.findAnnotation(method, ASYNC).or(() -> context.findClass(method.getDeclaringClassType())
                        .flatMap(cls -> context.findAnnotation(cls, ASYNC)));
        if (async.isEmpty() || !propagation.contains(SECURITY_CONTEXT_HOLDER)) {
            return Optional.empty();
        }
        Optional<String> qualifier = Annotations.string(async.get(), "value").filter(name -> !name.isEmpty())
                .map(name -> context.properties().resolveKnown(name));
        List<JavaSootMethod> beans = qualifier.map(name -> SpringBeans.beanMethods(context).stream()
                .filter(bean -> named(bean, name)).toList()).orElse(List.of());
        String annotation = qualifier.map(name -> "@Async(\"" + name + "\")").orElse("@Async");
        if (beans.isEmpty()) {
            // The application-wide executor, or one AuthTracer doesn't find (Boot's applicationTaskExecutor).
            return propagation.size() == 1 && !context.properties().flag("spring.threads.virtual.enabled")
                    .orElse(false) ? Optional.of(annotation) : Optional.empty();
        }
        return beans.stream().anyMatch(bean -> !carries(bean) && !THREAD_PER_TASK.contains(bean.getReturnType()
                .toString())) ? Optional.of(annotation) : Optional.empty();
    }

    private Optional<String> thread(MethodSignature signature) {
        String owner = signature.getDeclClassType().getFullyQualifiedName();
        String name = signature.getName();
        String call = MethodNames.simpleName(owner).replace('$', '.') + "." + name;
        boolean inheritable = propagation.contains(SECURITY_CONTEXT_HOLDER);
        if (COMPLETABLE.contains(owner) && name.endsWith("Async")) {
            // Without an executor, the common pool.
            boolean executor = signature.getParameterTypes().stream()
                    .anyMatch(type -> type.toString().equals(EXECUTOR));
            return (executor ? propagation.isEmpty() : !inheritable) ? Optional.of(call) : Optional.empty();
        }
        if (owner.equals("java.lang.Thread") && (name.equals("<init>") || name.equals("startVirtualThread"))
                || owner.startsWith("java.lang.Thread$Builder") && (name.equals("start") || name.equals("unstarted"))) {
            return inheritable ? Optional.empty() : Optional.of(name.equals("<init>") ? "new Thread" : call);
        }
        return SUBMITS.contains(name) && !PROPAGATING.contains(owner) && executor(signature.getDeclClassType())
                && propagation.isEmpty() ? Optional.of(call) : Optional.empty();
    }

    /**
     * Decision 0084: a lambda a Reactor operator (or factory) takes runs on a scheduler's thread when the pipeline
     * subscribes on one ({@code subscribeOn}, which moves everything up to the next {@code publishOn}) or publishes
     * on one before it ({@code publishOn}); not on {@code Schedulers.immediate()}. Decision 0099: also when the
     * pipeline it is added to comes from an application method that schedules it, or is subscribed on one in a caller
     * it is returned to or a method it is passed to.
     */
    private Optional<String> reactor(JavaSootMethod caller, Stmt use, AbstractInvokeExpr operator,
            Iterator<Site> callers) {
        if (reactorCarries) {
            return Optional.empty();
        }
        Optional<AbstractInvokeExpr> hop = scheduledBefore(caller, operator instanceof AbstractInstanceInvokeExpr
                instance ? instance.getBase() : null, 0)
                .or(() -> use instanceof AbstractDefinitionStmt definition && definition.getLeftOp() instanceof Local
                        result ? subscribedLater(caller, result, callers, 0) : Optional.empty());
        return hop.map(call -> MethodNames.simpleName(call.getMethodSignature().getDeclClassType()
                .getFullyQualifiedName()) + "." + call.getMethodSignature().getName());
    }

    /**
     * The nearest operator before, back along the pipeline's chain and into the application methods that return the
     * pipeline it starts from, that puts the work on a scheduler: {@code publishOn} or {@code subscribeOn}.
     */
    private Optional<AbstractInvokeExpr> scheduledBefore(JavaSootMethod method, Value start, int depth) {
        Value current = start;
        for (int i = 0; i < MAX_CHAIN && current instanceof Local local; i++) {
            if (!(Locals.definition(method.getBody(), local).orElse(null) instanceof AbstractInvokeExpr previous)) {
                return Optional.empty();
            }
            if (!REACTOR.contains(previous.getMethodSignature().getDeclClassType().getFullyQualifiedName())) {
                // Decision 0099: the pipeline an application method returns.
                return depth < MAX_METHODS && context.isApplication(previous.getMethodSignature().getDeclClassType())
                        ? context.findMethod(previous.getMethodSignature()).filter(JavaSootMethod::hasBody).stream()
                                .flatMap(callee -> callee.getBody().getStmts().stream()
                                        .filter(JReturnStmt.class::isInstance)
                                        .flatMap(returned -> scheduledBefore(callee, ((JReturnStmt) returned).getOp(),
                                                depth + 1).stream()))
                                .findFirst()
                        : Optional.empty();
            }
            if (scheduled(method, previous, "publishOn") || scheduled(method, previous, "subscribeOn")) {
                return Optional.of(previous);
            }
            current = previous instanceof AbstractInstanceInvokeExpr instance ? instance.getBase() : null;
        }
        return Optional.empty();
    }

    /**
     * A {@code subscribeOn} on the pipeline further down: on its chain in this method, and, decision 0099, in the
     * caller on the walk it is returned to, or in the application method it is passed to.
     */
    private Optional<AbstractInvokeExpr> subscribedLater(JavaSootMethod method, Local start, Iterator<Site> callers,
            int depth) {
        Set<Value> chain = new HashSet<>(Set.of(start));
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof JReturnStmt returned && chain.contains(returned.getOp())) {
                // The caller's call keeps it in a local, unless it drops it.
                Site site = callers.hasNext() ? callers.next() : ENTRY;
                return Optional.ofNullable(site.method()).filter(caller -> depth < MAX_METHODS)
                        .flatMap(caller -> Optional.of(site.stmt()).filter(AbstractDefinitionStmt.class::isInstance)
                                .map(call -> ((AbstractDefinitionStmt) call).getLeftOp())
                                .filter(Local.class::isInstance)
                                .flatMap(result -> subscribedLater(caller, (Local) result, callers, depth + 1)));
            }
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isEmpty()) {
                continue;
            }
            AbstractInvokeExpr call = invoke.get();
            if (call instanceof AbstractInstanceInvokeExpr instance && chain.contains(instance.getBase())) {
                if (scheduled(method, call, "subscribeOn")) {
                    return Optional.of(call);
                }
                if (stmt instanceof AbstractDefinitionStmt definition
                        && REACTOR.contains(definition.getLeftOp().getType().toString())) {
                    chain.add(definition.getLeftOp());
                }
                continue;
            }
            int passed = call.getArgs().stream().filter(chain::contains).findFirst()
                    .map(call.getArgs()::indexOf).orElse(-1);
            if (passed >= 0 && depth < MAX_METHODS && context.isApplication(call.getMethodSignature()
                    .getDeclClassType())) {
                Optional<AbstractInvokeExpr> found = context.findMethod(call.getMethodSignature())
                        .filter(JavaSootMethod::hasBody).flatMap(callee -> subscribedLater(callee,
                                callee.getBody().getParameterLocal(passed), Collections.emptyIterator(), depth + 1));
                if (found.isPresent()) {
                    return found;
                }
            }
        }
        return Optional.empty();
    }

    private static boolean scheduled(JavaSootMethod caller, AbstractInvokeExpr call, String operator) {
        if (!call.getMethodSignature().getName().equals(operator) || call.getArgCount() == 0) {
            return false;
        }
        // Schedulers.immediate() runs the work where it is.
        return !(call.getArg(0) instanceof Local scheduler && Locals.definition(caller.getBody(), scheduler)
                .orElse(null) instanceof AbstractInvokeExpr factory && factory.getMethodSignature().getName()
                        .equals("immediate"));
    }

    /**
     * What a method does with the futures it follows, and the fields it keeps them in without waiting.
     */
    private record Outcome(Wait kind, Set<FieldSignature> kept) {

        static final Outcome NONE = new Outcome(Wait.NONE, Set.of());
    }

    /**
     * Decision 0084: what the method does with what the statement's call starts on another thread: it waits when it
     * calls {@code get()}, {@code join()} or {@code block()} on its future or pipeline (or on one chained from it,
     * or combined with it) outside a handler that may catch the failure; not when an operator on the way recovers
     * from the failure ({@code exceptionally}, {@code onErrorResume}, ...).
     */
    private Outcome waits(JavaSootMethod caller, Stmt start) {
        if (!(start instanceof AbstractDefinitionStmt definition) || !(definition.getLeftOp() instanceof Local result)) {
            return Outcome.NONE;
        }
        return scan(caller, Set.of(result), Set.of(), 0);
    }

    /**
     * Decision 0099: what holds a future holds the wait too: a local it is copied or cast to, a collection it is
     * added to or a {@code java.util} factory it is passed to, what is read from those, a field it is stored in and
     * read back from; and a lambda run in place ({@code futures.forEach(CompletableFuture::join)}) that waits on what
     * it is handed or on a future it captures.
     *
     * @param seeds the locals that hold the futures
     * @param held the fields that hold them
     */
    private Outcome scan(JavaSootMethod method, Set<Local> seeds, Set<FieldSignature> held, int depth) {
        Set<Value> values = new HashSet<>(seeds);
        Set<FieldSignature> fields = new HashSet<>(held);
        Set<FieldSignature> kept = new LinkedHashSet<>();
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt assign && !(assign.getRightOp() instanceof AbstractInvokeExpr)) {
                if (holds(assign.getRightOp(), values, fields)) {
                    keep(assign.getLeftOp(), values, fields, kept);
                }
                continue;
            }
            if (stmt instanceof JReturnStmt returned && values.contains(returned.getOp())) {
                return new Outcome(Wait.RETURNS, kept);
            }
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isEmpty()) {
                continue;
            }
            AbstractInvokeExpr call = invoke.get();
            String name = call.getMethodSignature().getName();
            Value receiver = call instanceof AbstractInstanceInvokeExpr instance ? instance.getBase() : null;
            boolean onReceiver = values.contains(receiver);
            boolean passed = call.getArgs().stream().anyMatch(values::contains);
            if (inPlace(call) && call.getArgs().stream().anyMatch(arg -> lambdaWaits(method, arg, onReceiver,
                    values, depth))) {
                return new Outcome(waitsAt(method, stmt), kept);
            }
            if (receiver != null && !onReceiver && passed && COLLECTS.contains(name)) {
                // A collection the future is added to holds it, and so does the field that holds the collection.
                values.add(receiver);
                Locals.definition(method.getBody(), (Local) receiver).filter(JFieldRef.class::isInstance)
                        .ifPresent(field -> keep(field, values, fields, kept));
                continue;
            }
            boolean on = receiver != null ? onReceiver : passed && (future(call.getMethodSignature().getType())
                    || inPlace(call));
            if (!on) {
                continue;
            }
            if (RECOVERS.contains(name)) {
                return Outcome.NONE;
            }
            if (WAITS.contains(name)) {
                return new Outcome(waitsAt(method, stmt), kept);
            }
            if (stmt instanceof AbstractDefinitionStmt chained) {
                values.add(chained.getLeftOp());
            }
        }
        return new Outcome(Wait.NONE, kept);
    }

    /**
     * Whether the value holds a followed future: a local that does, a cast of one, a read of a field that does.
     */
    private static boolean holds(Value value, Set<Value> values, Set<FieldSignature> fields) {
        Value read = value instanceof JCastExpr cast ? cast.getOp() : value;
        return values.contains(read) || read instanceof JFieldRef field && fields.contains(field.getFieldSignature());
    }

    /**
     * What a followed future is assigned to holds it: a local, an array's element (CompletableFuture.allOf(..)'s
     * array), a field the method keeps it in.
     */
    private static void keep(Value target, Set<Value> values, Set<FieldSignature> fields, Set<FieldSignature> kept) {
        if (target instanceof JFieldRef field) {
            fields.add(field.getFieldSignature());
            kept.add(field.getFieldSignature());
        }
        else {
            values.add(target instanceof JArrayRef element ? element.getBase() : target);
        }
    }

    /**
     * A wait outside a handler that may catch the other thread's failure.
     */
    private static Wait waitsAt(JavaSootMethod method, Stmt stmt) {
        return method.getBody().getControlFlowGraph().exceptionalSuccessors(stmt).keySet().stream()
                .anyMatch(caught -> CAUGHT.contains(caught.getFullyQualifiedName())) ? Wait.NONE : Wait.WAITS;
    }

    /**
     * A call of {@code java.util}'s that runs what it is given where it is called (a collection's {@code forEach}, a
     * stream's {@code map}, {@code Optional.map}), or makes a collection of what it is given; not
     * {@code java.util.concurrent}'s.
     */
    private static boolean inPlace(AbstractInvokeExpr call) {
        String owner = call.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        return owner.startsWith("java.util.") && !owner.startsWith("java.util.concurrent.")
                || owner.equals("java.lang.Iterable");
    }

    /**
     * Whether the value is a lambda or method reference that waits: on what it is handed, when the call's receiver
     * holds the futures ({@code CompletableFuture::join}, {@code f -> f.join()}), or on a future it captures.
     *
     * @param handed whether what it is handed is a followed future
     */
    private boolean lambdaWaits(JavaSootMethod method, Value value, boolean handed, Set<Value> values, int depth) {
        if (depth >= MAX_METHODS || !(value instanceof Local local)
                || !(Locals.definition(method.getBody(), local).orElse(null) instanceof JDynamicInvokeExpr lambda)) {
            return false;
        }
        // A string concatenation's has no method.
        return lambda.getBootstrapArgs().stream().filter(MethodHandle.class::isInstance)
                .map(handle -> ((MethodHandle) handle).getReferenceSignature())
                .filter(MethodSignature.class::isInstance).map(MethodSignature.class::cast).findFirst()
                .map(target -> waitsIn(target, lambda.getArgs(), handed, values, depth)).orElse(false);
    }

    /**
     * Whether the lambda's body, or the method referenced, waits on the futures it captures or is handed.
     */
    private boolean waitsIn(MethodSignature target, List<? extends Value> captured, boolean handed, Set<Value> values,
            int depth) {
        if (!context.isApplication(target.getDeclClassType())) {
            // A reference to a wait: unbound, on what it is handed; bound, on the future it is bound to.
            return WAITS.contains(target.getName()) && future(target.getDeclClassType())
                    && (captured.isEmpty() ? handed : values.contains(captured.getFirst()));
        }
        return context.findMethod(target).filter(JavaSootMethod::hasBody).map(body -> {
            // Its parameters are what it captures (after an instance lambda's this), then what it is handed.
            int receiver = body.isStatic() ? 0 : 1;
            Set<Local> seeds = new HashSet<>();
            for (int i = receiver; i < captured.size(); i++) {
                if (values.contains(captured.get(i))) {
                    seeds.add(body.getBody().getParameterLocal(i - receiver));
                }
            }
            int own = captured.size() - receiver;
            if (handed && own < body.getParameterCount()) {
                seeds.add(body.getBody().getParameterLocal(own));
            }
            return !seeds.isEmpty() && scan(body, seeds, Set.of(), depth + 1).kind() == Wait.WAITS;
        }).orElse(false);
    }

    private static boolean future(Type type) {
        return type instanceof ClassType cls && (FUTURES.contains(cls.getFullyQualifiedName())
                || REACTOR.contains(cls.getFullyQualifiedName()));
    }

    private boolean executor(ClassType type) {
        return EXECUTORS.contains(type.getFullyQualifiedName()) || context.interfacesOf(type).stream()
                .anyMatch(implemented -> EXECUTORS.contains(implemented.getFullyQualifiedName()));
    }

    /**
     * Decision 0084: whether the executor bean of that name (or {@code @Qualifier}) carries the SecurityContext: it is
     * one of Spring Security's delegating executors, gets a {@code TaskDecorator} that copies the context, or comes
     * from Boot's builder, to which Boot applies a decorator bean; or the strategy carries it to any thread. An
     * executor AuthTracer doesn't find keeps the application-wide reading.
     */
    private boolean executorCarries(String name) {
        return executors.computeIfAbsent(name, qualifier -> {
            if (propagation.contains(SECURITY_CONTEXT_HOLDER)) {
                return true;
            }
            List<JavaSootMethod> beans = SpringBeans.beanMethods(context).stream()
                    .filter(bean -> named(bean, qualifier)).toList();
            if (beans.isEmpty()) {
                return !propagation.isEmpty();
            }
            return beans.stream().anyMatch(this::carries);
        });
    }

    private boolean named(JavaSootMethod bean, String qualifier) {
        Optional<AnnotationUsage> annotation = context.findAnnotation(bean, SpringNames.BEAN);
        List<String> names = new ArrayList<>(annotation.map(found -> Annotations.strings(found, "name"))
                .orElse(List.of()));
        annotation.ifPresent(found -> names.addAll(Annotations.strings(found, "value")));
        boolean qualified = context.findAnnotation(bean, "org.springframework.beans.factory.annotation.Qualifier")
                .flatMap(found -> Annotations.string(found, "value")).filter(qualifier::equals).isPresent();
        return qualified || (names.isEmpty() ? bean.getName().equals(qualifier) : names.contains(qualifier));
    }

    /**
     * Whether the executor a bean method builds carries the context.
     */
    private boolean carries(JavaSootMethod bean) {
        if (PROPAGATING.contains(bean.getReturnType().toString())) {
            return true;
        }
        Optional<Boolean> decorated = Optional.empty();
        boolean built = false;
        for (JavaSootMethod method : withLambdas(bean, 2)) {
            for (Stmt stmt : method.getBody().getStmts()) {
                if (stmt instanceof AbstractDefinitionStmt definition
                        && definition.getRightOp() instanceof JNewExpr created
                        && PROPAGATING.contains(created.getType().getFullyQualifiedName())) {
                    return true;
                }
                Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                String name = invoke.map(call -> call.getMethodSignature().getName()).orElse("");
                if ((name.equals("setTaskDecorator") || name.equals("taskDecorator"))
                        && invoke.get().getArgCount() == 1) {
                    boolean copies = decorates(method, invoke.get().getArg(0));
                    decorated = Optional.of(decorated.orElse(false) || copies);
                }
                built |= name.equals("build") && BOOT_BUILDERS.contains(invoke.get().getMethodSignature()
                        .getDeclClassType().getFullyQualifiedName());
            }
        }
        // Boot's builder has the application's TaskDecorator bean, unless the bean method sets its own.
        boolean viaBuilder = built;
        return decorated.orElseGet(() -> viaBuilder && decoratorBeanCopies());
    }

    /**
     * Whether the application's {@code TaskDecorator} bean, or component, copies the context.
     */
    private boolean decoratorBeanCopies() {
        return propagation.stream().anyMatch(carrier -> carrier.equals(CONTEXT_PROPAGATING_DECORATOR)
                || !carrier.equals(SECURITY_CONTEXT_HOLDER) && !PROPAGATING.contains(carrier));
    }

    /**
     * Whether the decorator a value is copies the context: one created there, a lambda, or one the method is given
     * (a bean: the application's decorator bean).
     */
    private boolean decorates(JavaSootMethod method, Value decorator) {
        if (!(decorator instanceof Local local)) {
            // null: no decorator.
            return false;
        }
        Value definition = Locals.definition(method.getBody(), local).orElse(null);
        if (definition instanceof JNewExpr created) {
            return context.findClass(created.getType()).filter(found -> context.isApplication(created.getType()))
                    .map(this::copiesContext).orElse(false);
        }
        if (definition instanceof JDynamicInvokeExpr lambda) {
            return lambda(lambda).map(body -> copiesContext(List.of(body))).orElse(false);
        }
        return Locals.parameterIndex(method.getBody(), local).isPresent() && decoratorBeanCopies();
    }

    private boolean copiesContext(JavaSootClass decorator) {
        return copiesContext(decorator.getMethods().stream().filter(JavaSootMethod::hasBody).toList());
    }

    /**
     * Whether the code, the lambdas it creates or the application methods it calls, reads or sets the
     * SecurityContext, or wraps the task to.
     */
    private boolean copiesContext(List<JavaSootMethod> methods) {
        for (JavaSootMethod root : methods) {
            for (JavaSootMethod method : withLambdas(root, 2)) {
                for (Stmt stmt : method.getBody().getStmts()) {
                    if (stmt instanceof AbstractDefinitionStmt definition
                            && definition.getRightOp() instanceof JNewExpr created
                            && COPIES_CONTEXT.contains(created.getType().getFullyQualifiedName())) {
                        return true;
                    }
                    if (Locals.invoke(stmt).filter(invoke -> COPIES_CONTEXT.contains(invoke.getMethodSignature()
                            .getDeclClassType().getFullyQualifiedName())).isPresent()) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * The method, the lambdas it creates and the application methods it calls, as deep as asked.
     */
    private List<JavaSootMethod> withLambdas(JavaSootMethod method, int depth) {
        List<JavaSootMethod> found = new ArrayList<>(List.of(method));
        if (depth == 0 || !method.hasBody()) {
            return found.stream().filter(JavaSootMethod::hasBody).toList();
        }
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            Optional<JavaSootMethod> next = invoke.flatMap(call -> call instanceof JDynamicInvokeExpr dynamic
                    ? lambda(dynamic) : context.isApplication(call.getMethodSignature().getDeclClassType())
                            ? context.findMethod(call.getMethodSignature()).filter(JavaSootMethod::hasBody)
                            : Optional.empty());
            next.filter(target -> !target.equals(method))
                    .ifPresent(target -> found.addAll(withLambdas(target, depth - 1)));
        }
        return found.stream().filter(JavaSootMethod::hasBody).distinct().toList();
    }

    private Optional<JavaSootMethod> lambda(JDynamicInvokeExpr dynamic) {
        return dynamic.getBootstrapArgs().stream().filter(MethodHandle.class::isInstance).map(MethodHandle.class::cast)
                .map(MethodHandle::getReferenceSignature).filter(MethodSignature.class::isInstance)
                .map(MethodSignature.class::cast).filter(target -> context.isApplication(target.getDeclClassType()))
                .findFirst().flatMap(context::findMethod).filter(JavaSootMethod::hasBody);
    }

    /**
     * Decision 0084: whether a Reactor scheduler's thread has the caller's context: reactive method security reads
     * the Reactor {@code Context}, which follows the subscriber across schedulers
     * ({@code ReactiveSecurityContextHolder.getContext()} is {@code Mono.deferContextual(..)}); automatic context
     * propagation restores the thread-local one there ({@code spring.reactor.context-propagation=auto}, Boot 4.1.1's
     * {@code ReactorAutoConfiguration} calling {@code Hooks.enableAutomaticContextPropagation()}, or the application
     * calling it); a schedule hook that copies it does as a decorator does; and an inheritable strategy reaches new
     * threads.
     */
    private boolean reactorCarries() {
        if (context.anyClassAnnotated(SECURITY + "config.annotation.method.configuration.EnableReactiveMethodSecurity")
                || context.properties().get("spring.reactor.context-propagation")
                        .filter(mode -> mode.trim().equalsIgnoreCase("auto")).isPresent()
                || propagation.contains(SECURITY_CONTEXT_HOLDER)) {
            return true;
        }
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                for (Stmt stmt : method.hasBody() ? method.getBody().getStmts() : List.<Stmt>of()) {
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                    String called = invoke.map(call -> call.getMethodSignature().getDeclClassType()
                            .getFullyQualifiedName() + "#" + call.getMethodSignature().getName()).orElse("");
                    if (called.equals("reactor.core.publisher.Hooks#enableAutomaticContextPropagation")
                            || called.equals("reactor.core.scheduler.Schedulers#onScheduleHook")
                                    && hookCopies(method, invoke.get().getArg(1))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Whether a schedule hook ({@code Schedulers.onScheduleHook(key, task -> ..)}), which wraps every task a
     * scheduler runs as a {@code TaskDecorator} does, copies the context.
     */
    private boolean hookCopies(JavaSootMethod method, Value hook) {
        return hook instanceof Local local && Locals.definition(method.getBody(), local).orElse(null)
                instanceof JDynamicInvokeExpr lambda && lambda(lambda).map(body -> copiesContext(List.of(body)))
                        .orElse(false);
    }

    /**
     * What carries the SecurityContext to other threads: {@code SecurityContextHolder} for a strategy other than
     * the thread-local one.
     */
    private Set<String> propagation() {
        Set<String> found = new LinkedHashSet<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            if (context.interfacesOf(cls.getType()).stream()
                    .anyMatch(type -> type.getFullyQualifiedName().equals(TASK_DECORATOR)) && copiesContext(cls)) {
                found.add(cls.getType().getFullyQualifiedName());
            }
            for (JavaSootMethod method : cls.getMethods()) {
                boolean bean = context.hasAnnotation(method, SpringNames.BEAN);
                if (bean && method.getReturnType() instanceof ClassType type
                        && (type.getFullyQualifiedName().equals(TASK_DECORATOR) && method.hasBody()
                                && copiesContext(List.of(method))
                                || PROPAGATING.contains(type.getFullyQualifiedName()))) {
                    found.add(type.getFullyQualifiedName());
                }
                if (bean && method.getReturnType() instanceof ClassType type && strategy(type) && method.hasBody()
                        && !threadLocal(method)) {
                    // Spring Security's filters and method interceptors use a SecurityContextHolderStrategy bean
                    // (7.1.1: PrePostMethodSecurityConfiguration.setSecurityContextHolderStrategy).
                    found.add(SECURITY_CONTEXT_HOLDER);
                }
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    if (stmt instanceof AbstractDefinitionStmt definition
                            && definition.getRightOp() instanceof JNewExpr created
                            && PROPAGATING.contains(created.getType().getFullyQualifiedName())) {
                        found.add(created.getType().getFullyQualifiedName());
                    }
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                    String owner = invoke.map(call -> call.getMethodSignature().getDeclClassType()
                            .getFullyQualifiedName()).orElse("");
                    String name = invoke.map(call -> call.getMethodSignature().getName()).orElse("");
                    if (owner.equals(SECURITY_CONTEXT_HOLDER) && name.equals("setStrategyName")) {
                        // A strategy that isn't a constant may be an inheritable one.
                        if (!(invoke.get().getArg(0) instanceof StringConstant strategy
                                && strategy.getValue().equals(THREAD_LOCAL))) {
                            found.add(SECURITY_CONTEXT_HOLDER);
                        }
                    }
                    else if (owner.equals(SECURITY_CONTEXT_HOLDER) && name.equals("setContextHolderStrategy")
                            && invoke.get().getArgCount() == 1 && !threadLocal(method, invoke.get().getArg(0))) {
                        found.add(SECURITY_CONTEXT_HOLDER);
                    }
                    else if (PROPAGATING.contains(owner)) {
                        found.add(owner);
                    }
                }
            }
        }
        return found;
    }

    private boolean strategy(ClassType type) {
        return type.getFullyQualifiedName().equals(STRATEGY) || context.interfacesOf(type).stream()
                .anyMatch(implemented -> implemented.getFullyQualifiedName().equals(STRATEGY));
    }

    /**
     * Whether a {@code SecurityContextHolderStrategy} bean method returns one that keeps the context on its thread.
     */
    private boolean threadLocal(JavaSootMethod bean) {
        return bean.getBody().getStmts().stream().filter(JReturnStmt.class::isInstance)
                .allMatch(returned -> threadLocal(bean, ((JReturnStmt) returned).getOp()));
    }

    /**
     * Whether the strategy a value is keeps the context on its thread: the holder's own
     * ({@code getContextHolderStrategy()}, which the holder's mode decides), or one created whose class keeps it in
     * a plain {@code ThreadLocal}. Spring Security 7.1.1's own strategy classes are package-private, so an application
     * creates its own; when unsure, it carries the context, so the checks keep their requirements.
     */
    private boolean threadLocal(JavaSootMethod method, Value strategy) {
        if (!(strategy instanceof Local local)) {
            return false;
        }
        Optional<ClassType> created = Locals.created(method.getBody(), local);
        if (created.isPresent()) {
            return created.get().getFullyQualifiedName().equals(THREAD_LOCAL_STRATEGY) || threadLocal(created.get());
        }
        return Locals.definition(method.getBody(), local).orElse(null) instanceof AbstractInvokeExpr call
                && call.getMethodSignature().getName().equals("getContextHolderStrategy");
    }

    /**
     * Whether an application's strategy class keeps the context in a plain {@code ThreadLocal}, or hands it to the
     * holder's own strategy; not when it uses an {@code InheritableThreadLocal}.
     */
    private boolean threadLocal(ClassType type) {
        Optional<JavaSootClass> strategy = context.findClass(type).filter(found -> context.isApplication(type));
        if (strategy.isEmpty()) {
            return false;
        }
        boolean threadLocal = false;
        for (JavaSootMethod method : strategy.get().getMethods()) {
            if (!method.hasBody()) {
                continue;
            }
            for (Stmt stmt : method.getBody().getStmts()) {
                if (stmt instanceof AbstractDefinitionStmt definition
                        && definition.getRightOp() instanceof JNewExpr holder) {
                    String created = holder.getType().getFullyQualifiedName();
                    String parent = context.findClass(holder.getType()).flatMap(JavaSootClass::getSuperclass)
                            .map(ClassType::getFullyQualifiedName).orElse("");
                    if (created.equals(INHERITABLE) || parent.equals(INHERITABLE)) {
                        return false;
                    }
                    threadLocal |= created.equals(THREAD_LOCAL_CLASS) || parent.equals(THREAD_LOCAL_CLASS);
                }
                Optional<MethodSignature> called = Locals.invoke(stmt).map(AbstractInvokeExpr::getMethodSignature);
                threadLocal |= called.filter(signature -> signature.getDeclClassType().getFullyQualifiedName()
                        .equals(THREAD_LOCAL_CLASS) && signature.getName().equals("withInitial")
                        || signature.getDeclClassType().getFullyQualifiedName().equals(SECURITY_CONTEXT_HOLDER)
                                && signature.getName().equals("getContextHolderStrategy")).isPresent();
            }
        }
        return threadLocal;
    }
}
