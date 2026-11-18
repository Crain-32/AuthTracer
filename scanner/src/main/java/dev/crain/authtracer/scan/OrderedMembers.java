package dev.crain.authtracer.scan;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import sootup.core.frontend.SootClassSource;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.interceptor.BodyInterceptor;
import sootup.core.model.SootMethod;
import sootup.core.model.SourceType;
import sootup.core.types.ClassType;
import sootup.core.views.View;
import sootup.java.core.JavaSootClassSource;
import sootup.java.core.OverridingJavaClassSource;

/**
 * Decision 0089: classes whose methods come in signature order. SootUp 3.0.1 collects a class's methods into a hash
 * set of objects that hash by identity, so each scan walked them in a different order, and whatever a scan took from
 * that order (which colliding mapping keeps the plain id, which of two checks comes first, the first of several
 * types) changed from one scan of the same code to the next. Its {@code getFields()} makes a new hash set on every
 * call, so code that needs fields in an order sorts them itself.
 */
@Supports(Feature.APPLICATION_GRAPH)
final class OrderedMembers implements AnalysisInputLocation {

    private final AnalysisInputLocation location;

    OrderedMembers(AnalysisInputLocation location) {
        this.location = location;
    }

    @Override
    public Optional<? extends SootClassSource> getClassSource(ClassType type, View view) {
        return location.getClassSource(type, view).map(OrderedMembers::ordered);
    }

    @Override
    public Stream<? extends SootClassSource> getClassSources(View view) {
        return location.getClassSources(view).map(OrderedMembers::ordered);
    }

    @Override
    public SourceType getSourceType() {
        return location.getSourceType();
    }

    @Override
    public List<BodyInterceptor> getBodyInterceptors() {
        return location.getBodyInterceptors();
    }

    @Override
    public void close() throws Exception {
        location.close();
    }

    /**
     * The Java frontends' locations make only Java class sources.
     */
    private static SootClassSource ordered(SootClassSource source) {
        return new Ordered((JavaSootClassSource) source);
    }

    private static final class Ordered extends OverridingJavaClassSource {

        Ordered(JavaSootClassSource source) {
            super(source);
        }

        @Override
        public Collection<? extends SootMethod> resolveMethods() {
            List<SootMethod> methods = new ArrayList<>(super.resolveMethods());
            methods.sort(Comparator.comparing(method -> method.getSignature().toString()));
            return methods;
        }
    }
}
