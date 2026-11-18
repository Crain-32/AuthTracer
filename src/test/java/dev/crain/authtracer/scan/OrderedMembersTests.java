package dev.crain.authtracer.scan;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import sootup.core.frontend.SootClassSource;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.interceptor.BodyInterceptor;
import sootup.core.model.SourceType;
import sootup.core.types.ClassType;
import sootup.core.views.View;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.JavaSootClass;
import sootup.java.core.views.JavaView;

/**
 * Decision 0089: a class's methods in signature order, whatever order SootUp collected them in.
 */
class OrderedMembersTests {

    @Test
    void aClassesMethodsComeInSignatureOrder() {
        List<AnalysisInputLocation> locations = Stream.of(System.getProperty("authtracer.fixtures.classes")
                .split(File.pathSeparator)).filter(dir -> new File(dir).isDirectory())
                .map(dir -> (AnalysisInputLocation) new OrderedMembers(new JavaClassPathAnalysisInputLocation(dir,
                        SourceType.Application, List.of())))
                .toList();
        JavaView view = new JavaView(locations);
        JavaSootClass cls = view.getClass(view.getIdentifierFactory().getClassType(
                "fixtures.builtproxies.StatementController")).orElseThrow();
        List<String> methods = cls.getMethods().stream().map(method -> method.getSignature().toString()).toList();
        assertThat(methods).hasSizeGreaterThan(2).isSorted();
    }

    @Test
    void theLocationIsOtherwiseTheOneItWraps() throws Exception {
        AtomicBoolean closed = new AtomicBoolean();
        List<BodyInterceptor> interceptors = List.of();
        AnalysisInputLocation location = new AnalysisInputLocation() {

            @Override
            public Optional<? extends SootClassSource> getClassSource(ClassType type, View view) {
                return Optional.empty();
            }

            @Override
            public Stream<? extends SootClassSource> getClassSources(View view) {
                return Stream.empty();
            }

            @Override
            public SourceType getSourceType() {
                return SourceType.Library;
            }

            @Override
            public List<BodyInterceptor> getBodyInterceptors() {
                return interceptors;
            }

            @Override
            public void close() {
                closed.set(true);
            }
        };
        try (OrderedMembers ordered = new OrderedMembers(location)) {
            assertThat(ordered.getSourceType()).isEqualTo(SourceType.Library);
            assertThat(ordered.getBodyInterceptors()).isSameAs(interceptors);
        }
        assertThat(closed).isTrue();
    }
}
