package dev.crain.authtracer.scan;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import dev.crain.authtracer.scan.ClassFileMetadata.GenericType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import sootup.java.core.JavaIdentifierFactory;

class ClassFileMetadataTests {

    private final ClassFileMetadata classFiles = new ClassFileMetadata(Arrays.stream(System.getProperty(
            "authtracer.fixtures.classes").split(File.pathSeparator)).map(Path::of).toList());

    @Test
    void anUnboundedWildcardKeepsItsPlace() {
        GenericType returned = classFiles.genericReturnType(JavaIdentifierFactory.getInstance().getMethodSignature(
                "fixtures.accessors.MemberController", "index", "java.util.Map", List.of())).orElseThrow();

        assertThat(returned.arguments()).extracting(GenericType::name)
                .containsExactly("java.lang.Object", "fixtures.accessors.MemberView");
    }

    @Test
    void aCovariantOverridesBridgeIsNotTheProperty() {
        assertThat(classFiles.getters("fixtures.accessors.AdminDto"))
                .extracting(ClassFileMetadata.Member::type).containsExactly("fixtures.accessors.AdminDetails");
    }

    @Test
    void aGetterNamedWithCapitalsKeepsThemAsJacksonDoes() {
        assertThat(ClassFileMetadata.property("getSsn")).contains("ssn");
        assertThat(ClassFileMetadata.property("getSSN")).contains("SSN");
        assertThat(ClassFileMetadata.property("getURL")).contains("URL");
        assertThat(ClassFileMetadata.property("getX")).contains("x");
        assertThat(ClassFileMetadata.property("isActive")).contains("active");
    }

    @Test
    void jackson2LowerCasesTheLeadingCapitals() {
        assertThat(ClassFileMetadata.property("getSsn", true)).contains("ssn");
        assertThat(ClassFileMetadata.property("getSSN", true)).contains("ssn");
        assertThat(ClassFileMetadata.property("getURLValue", true)).contains("urlvalue");
        assertThat(ClassFileMetadata.property("isActive", true)).contains("active");
        assertThat(ClassFileMetadata.property("getClass", true)).isEmpty();
    }

    @Test
    void namesThatArentGettersHaveNoProperty() {
        assertThat(ClassFileMetadata.property("getClass")).isEmpty();
        assertThat(ClassFileMetadata.property("get")).isEmpty();
        assertThat(ClassFileMetadata.property("is")).isEmpty();
        assertThat(ClassFileMetadata.property("issue")).isEmpty();
        assertThat(ClassFileMetadata.property("getaway")).isEmpty();
        assertThat(ClassFileMetadata.property("name")).isEmpty();
    }

    @Test
    void aClassWithoutGenericsHasItsRawSupertypes() {
        ClassFileMetadata.GenericDeclaration declaration = classFiles.declaration("fixtures.walkforms.PlainFormatter");

        assertThat(declaration.typeParameters()).isEmpty();
        assertThat(declaration.supertypes()).extracting(GenericType::name)
                .containsExactly("java.lang.Object", "fixtures.walkforms.Formatter");
    }

    @Test
    void anUnreadableLibraryLeavesItsClassesUnknown(@TempDir Path dir) throws IOException {
        Path broken = Files.writeString(dir.resolve("broken.jar"), "not a zip");
        ClassFileMetadata withBrokenJar = new ClassFileMetadata(List.of(), List.of(broken));

        assertThat(withBrokenJar.declaration("org.example.Missing").supertypes()).isEmpty();
        // The JDK's classes are still read.
        assertThat(withBrokenJar.declaration("java.util.ArrayList").typeParameters()).containsExactly("E");
    }
}
