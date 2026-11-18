package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0046: with {@code @EnableScheduling}, each {@code @Scheduled} (or {@code @Schedules}) method is an entry
 * point nobody calls, {@code SCHEDULED Reports.nightly}: what it calls (other services among it) is on its path, and
 * its method checks run without a caller ({@link NoCaller}).
 */
@Supports(Feature.SCHEDULED_TASKS)
final class ScheduledTasks {

    static final String SCHEDULED = "SCHEDULED";
    private static final String ENABLE = "org.springframework.scheduling.annotation.EnableScheduling";
    private static final String SCHEDULED_ANNOTATION = "org.springframework.scheduling.annotation.Scheduled";
    private static final String SCHEDULES = "org.springframework.scheduling.annotation.Schedules";

    private final ScanContext context;

    ScheduledTasks(ScanContext context) {
        this.context = context;
    }

    static boolean isScheduled(Ingress ingress) {
        return SCHEDULED.equals(ingress.httpMethod());
    }

    List<RequestMappings.Mapping> detect() {
        List<RequestMappings.Mapping> mappings = new ArrayList<>();
        if (!context.anyClassAnnotated(ENABLE)) {
            return mappings;
        }
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!RequestMappings.suspendImpl(method) && (context.hasAnnotation(method, SCHEDULED_ANNOTATION)
                        || context.hasAnnotation(method, SCHEDULES))) {
                    mappings.add(new RequestMappings.Mapping(ingress(method), method, true));
                }
            }
        }
        return mappings;
    }

    /**
     * What runs the method when nobody calls it: {@code SCHEDULED ReportJob.nightly}.
     */
    static Ingress ingress(JavaSootMethod method) {
        String owner = method.getDeclaringClassType().getClassName();
        return Ingress.of(SCHEDULED, owner.substring(owner.lastIndexOf('$') + 1) + "." + method.getName(),
                MethodNames.codeRef(method.getSignature()));
    }
}
