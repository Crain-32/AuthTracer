package dev.crain.authtracer.scan.flow;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.scan.ClassFileMetadata;
import dev.crain.authtracer.scan.ClassFileMetadata.GenericType;
import dev.crain.authtracer.scan.ClassFileMetadata.Member;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootField;

/**
 * The JSON-visible properties of application types: record components, or public fields and getters for classes
 * (including inherited ones), honoring Jackson's {@code @JsonProperty} and {@code @JsonIgnore}.
 */
@Supports(Feature.RESPONSE_FIELDS)
public final class TypeProperties {

    private static final String JSON_PROPERTY = "com.fasterxml.jackson.annotation.JsonProperty";
    private static final String JSON_IGNORE = "com.fasterxml.jackson.annotation.JsonIgnore";
    private static final String JSON_IGNORE_PROPERTIES = "com.fasterxml.jackson.annotation.JsonIgnoreProperties";
    private static final String JSON_VIEW = "com.fasterxml.jackson.annotation.JsonView";
    private static final String JSON_AUTO_DETECT = "com.fasterxml.jackson.annotation.JsonAutoDetect";
    /**
     * What on a member makes Jackson write its type as something other than its properties, and how to say so.
     */
    private static final Map<String, String> MEMBERS_WRITTEN_OTHERWISE = Map.of(
            "com.fasterxml.jackson.annotation.JsonValue", "@JsonValue writes it as one value",
            "com.fasterxml.jackson.annotation.JsonAnyGetter", "@JsonAnyGetter adds the entries of a map to it");
    /**
     * What on the class does.
     */
    private static final Map<String, String> CLASSES_WRITTEN_OTHERWISE = Map.of(
            "com.fasterxml.jackson.annotation.JsonTypeInfo", "@JsonTypeInfo writes its subtypes' properties too",
            "com.fasterxml.jackson.annotation.JsonSubTypes", "@JsonSubTypes writes its subtypes' properties too",
            "tools.jackson.databind.annotation.JsonSerialize", "@JsonSerialize gives it a serializer of its own",
            "com.fasterxml.jackson.databind.annotation.JsonSerialize",
            "@JsonSerialize gives it a serializer of its own");
    /**
     * Jackson 3's and 2's.
     */
    private static final List<String> JSON_NAMING = List.of("tools.jackson.databind.annotation.JsonNaming",
            "com.fasterxml.jackson.databind.annotation.JsonNaming");
    private static final String GROOVY_META_CLASS = "groovy.lang.MetaClass";
    private static final String BOOT_JACKSON2_CONVERTERS =
            "org.springframework.boot.http.converter.autoconfigure.Jackson2HttpMessageConvertersConfiguration";
    /**
     * Written as the value they hold, as Jackson 3.1's ReferenceType serializers write them.
     */
    private static final Set<String> REFERENCES = Set.of("java.util.Optional",
            "java.util.concurrent.atomic.AtomicReference");
    /**
     * Generated message classes extend these (protobuf-java 4, then 3).
     */
    private static final Set<String> PROTOBUF_MESSAGES = Set.of("com.google.protobuf.GeneratedMessage",
            "com.google.protobuf.GeneratedMessageV3");
    private static final String FIELD_NUMBER = "_FIELD_NUMBER";

    /**
     * What a property written from its field reads it with: no method.
     */
    static final String FIELD = "";

    /**
     * @param accessor the method that reads it: the record accessor or the getter; {@link #FIELD} for a field
     */
    public record Property(String name, String jsonName, String type, String accessor, List<String> views) {

        public Property(String name, String jsonName, String type, String accessor) {
            this(name, jsonName, type, accessor, List.of());
        }
    }

    private final ScanContext context;
    private final GenericTypes generics;
    private final Map<String, List<Property>> cache = new ConcurrentHashMap<>();
    private final boolean jackson2;

    public TypeProperties(ScanContext context) {
        this.context = context;
        this.generics = new GenericTypes(context);
        this.jackson2 = jackson2(context);
    }

    /**
     * Decision 0078: whether the application writes its JSON with Jackson 2, whose getter names differ from Jackson
     * 3's ({@link ClassFileMetadata#property(String, boolean)}): Spring Framework 7.0.9 writes with Jackson 3 whenever
     * {@code tools.jackson.databind.ObjectMapper} is on the classpath, else with Jackson 2
     * ({@code DefaultHttpMessageConverters}); Spring Boot 4.1.1 also with Jackson 2 when
     * {@code spring.http.converters.preferred-json-mapper} is {@code jackson2}
     * ({@code Jackson2HttpMessageConvertersConfiguration}).
     */
    public static boolean jackson2(ScanContext context) {
        if (context.findClass("com.fasterxml.jackson.databind.ObjectMapper").isEmpty()) {
            return false;
        }
        return context.findClass("tools.jackson.databind.ObjectMapper").isEmpty()
                || context.findClass(BOOT_JACKSON2_CONVERTERS).isPresent() && context.properties()
                        .get("spring.http.converters.preferred-json-mapper").map(String::trim)
                        .filter("jackson2"::equals).isPresent();
    }

    public boolean isApplicationType(String type) {
        return context.isApplication(context.type(type));
    }

    /**
     * Properties in declaration order; empty for library types.
     */
    public List<Property> of(String type) {
        // Not computeIfAbsent: resolving a class resolves its superclass, a recursive update of the same map.
        List<Property> cached = cache.get(type);
        if (cached != null) {
            return cached;
        }
        List<Property> resolved = resolve(type);
        List<Property> raced = cache.putIfAbsent(type, resolved);
        return raced != null ? raced : resolved;
    }

    /**
     * The property an accessor call reads, e.g. {@code getSsn} or a record's {@code ssn}.
     */
    public Optional<Property> byAccessor(String type, String accessor) {
        return of(type).stream().filter(property -> property.accessor().equals(accessor)).findFirst();
    }

    public Optional<Property> byName(String type, String name) {
        return of(type).stream().filter(property -> property.name().equals(name)).findFirst();
    }

    /**
     * The type a property holds as Jackson writes it, when that is an application type in a container: an array of
     * them ({@code app.Pet[]}) for an array, collection or stream of them (a library's too, such as a {@code Page}),
     * an object of them ({@code app.Pet{}}) for a map whose values they are, the type itself for an {@code Optional}
     * or {@code AtomicReference}; else the property's declared type.
     */
    public String heldType(String owner, Property property) {
        String declared = property.type();
        if (declared.endsWith("[]")) {
            return declared;
        }
        if (isApplicationType(declared)) {
            return declared;
        }
        Optional<GenericType> generic = context.classFiles().genericFieldType(owner, property.name())
                .or(() -> context.findClass(owner).flatMap(cls -> cls.getMethods().stream()
                        .filter(method -> method.getName().equals(property.accessor())
                                && method.getParameterCount() == 0).findFirst())
                        .flatMap(accessor -> context.classFiles().genericReturnTypeIn(owner, accessor.getSignature())));
        if (generic.isEmpty() || generic.get().arguments().isEmpty()) {
            return declared;
        }
        boolean reference = REFERENCES.contains(declared);
        GenericType element = reference ? generic.get().arguments().getFirst() : generics.element(generic.get());
        if (element == generic.get() || !isApplicationType(element.name())) {
            return declared;
        }
        return reference ? element.name() : element.name() + (generics.isMap(declared) ? "{}" : "[]");
    }

    private List<Property> resolve(String type) {
        if (!isApplicationType(type)) {
            return List.of();
        }
        ClassFileMetadata classFiles = context.classFiles();
        // @JsonIgnoreProperties({"password"}) on the class; with allowGetters, they are still written.
        Map<String, String> classAnnotations = classFiles.classAnnotations(type);
        UnaryOperator<String> naming = naming(classAnnotations);
        Set<String> ignoredNames = "true".equals(classAnnotations.get(JSON_IGNORE_PROPERTIES + ".allowGetters"))
                ? Set.of() : Set.copyOf(Arrays.asList(classAnnotations.getOrDefault(JSON_IGNORE_PROPERTIES + ".value",
                        "").split(",")));
        // A class-level @JsonView is the view of the properties that name none.
        List<String> classViews = views(classAnnotations, List.of());
        Optional<List<Member>> components = classFiles.recordComponents(type);
        if (components.isPresent()) {
            return components.get().stream().filter(member -> !hidden(member, ignoredNames, naming))
                    .map(member -> new Property(member.name(), jsonName(member, naming), member.type(), member.name(),
                            views(member.annotations(), classViews)))
                    .toList();
        }
        Optional<Set<String>> protobuf = protobufFields(type);
        if (protobuf.isPresent()) {
            // A protobuf message: its fields, not the getters the generated code adds (getSerializedSize(), ..). A
            // repeated field's getter is getXList(), a map field's getXMap().
            Map<String, Property> fields = new LinkedHashMap<>();
            List<Member> getters = classFiles.getters(type, jackson2);
            for (Member getter : getters) {
                if (protobuf.get().contains(normalized(getter.name()))) {
                    fields.put(normalized(getter.name()), new Property(getter.name(), getter.name(), getter.type(),
                            getter.accessor()));
                }
            }
            for (Member getter : getters) {
                for (String suffix : List.of("List", "Map")) {
                    String name = getter.name();
                    String field = name.endsWith(suffix) ? name.substring(0, name.length() - suffix.length()) : "";
                    if (!field.isEmpty() && protobuf.get().contains(normalized(field))
                            && !fields.containsKey(normalized(field))) {
                        fields.put(normalized(field), new Property(field, field, getter.type(), getter.accessor()));
                    }
                }
            }
            return List.copyOf(fields.values());
        }
        Map<String, Property> properties = new LinkedHashMap<>();
        Optional<String> superclass = classFiles.superclass(type);
        if (superclass.isPresent() && isApplicationType(superclass.get())) {
            of(superclass.get()).forEach(property -> properties.put(property.name(), property));
        }
        // Decision 0078: Jackson's default visibility (2 and 3) writes public fields; @JsonProperty makes any field
        // a property, and so does field visibility ANY (@JsonAutoDetect, spring.jackson.visibility.field).
        boolean anyField = "ANY".equals(classAnnotations.get(JSON_AUTO_DETECT + ".fieldVisibility"))
                || !classAnnotations.containsKey(JSON_AUTO_DETECT + ".fieldVisibility") && context.properties()
                        .get("spring.jackson.visibility.field").filter("any"::equalsIgnoreCase).isPresent();
        for (ClassFileMetadata.DeclaredField field : classFiles.fields(type)) {
            Member member = new Member(field.name(), field.type(), field.annotations(), FIELD);
            if (!((field.isPublic() || anyField) && !field.isTransient())
                    && !field.annotations().containsKey(JSON_PROPERTY)) {
                continue;
            }
            if (hidden(member, ignoredNames, naming)) {
                properties.remove(field.name());
                continue;
            }
            properties.put(field.name(), new Property(field.name(), jsonName(member, naming), field.type(), FIELD,
                    views(field.annotations(), classViews)));
        }
        for (Member getter : classFiles.getters(type, jackson2)) {
            // Jackson leaves out Groovy's getMetaClass().
            if (hidden(getter, ignoredNames, naming) || getter.type().equals(GROOVY_META_CLASS)) {
                properties.remove(getter.name());
                continue;
            }
            properties.put(getter.name(), new Property(getter.name(), jsonName(getter, naming), getter.type(),
                    getter.accessor(), views(getter.annotations(), classViews)));
        }
        return new ArrayList<>(properties.values());
    }

    /**
     * Why Jackson writes the type as something other than the properties {@link #of} lists, when it does: a
     * {@code @JsonValue}, {@code @JsonAnyGetter}, a serializer of its own, or subtypes.
     */
    public Optional<String> writtenOtherwise(String type) {
        if (!isApplicationType(type)) {
            return Optional.empty();
        }
        Set<String> onClass = context.classFiles().classAnnotations(type).keySet();
        Set<String> onMembers = context.classFiles().memberAnnotations(type);
        return Stream.concat(CLASSES_WRITTEN_OTHERWISE.entrySet().stream().filter(entry -> onClass.contains(
                entry.getKey())), MEMBERS_WRITTEN_OTHERWISE.entrySet().stream().filter(entry -> onMembers.contains(
                        entry.getKey()))).map(Map.Entry::getValue).sorted().findFirst();
    }

    private static List<String> views(Map<String, String> annotations, List<String> fallback) {
        String views = annotations.get(JSON_VIEW + ".value");
        return views == null || views.isEmpty() ? fallback : List.of(views.split(","));
    }

    /**
     * Not serialized: {@code @JsonIgnore} on the field, getter or setter, {@code @JsonProperty(access = WRITE_ONLY)},
     * or named in the class's {@code @JsonIgnoreProperties}.
     */
    private static boolean hidden(Member member, Set<String> ignoredNames, UnaryOperator<String> naming) {
        Map<String, String> annotations = member.annotations();
        return annotations.containsKey(JSON_IGNORE) && !"false".equals(annotations.get(JSON_IGNORE + ".value"))
                || "WRITE_ONLY".equals(annotations.get(JSON_PROPERTY + ".access"))
                || ignoredNames.contains(member.name()) || ignoredNames.contains(jsonName(member, naming));
    }

    /**
     * Whether the type is a generated protobuf message (it has fields only through its builder).
     */
    public boolean isProtobufMessage(String type) {
        return protobufFields(type).isPresent();
    }

    /**
     * Whether the type is a generated protobuf message's builder ({@code Msg$Builder}).
     */
    public boolean isProtobufBuilder(String type) {
        return type.endsWith("$Builder") && isProtobufMessage(type.substring(0, type.length() - "$Builder".length()));
    }

    /**
     * A protobuf field's name as its constant and its getter both spell it: {@code secret_note},
     * {@code SECRET_NOTE} and {@code secretNote}, and {@code SECRETNOTE} for one written {@code secretNote}, are all
     * {@code secretnote}.
     */
    private static String normalized(String name) {
        return name.replace("_", "").toLowerCase(Locale.ROOT);
    }

    /**
     * The fields of a generated protobuf message, from its {@code SECRET_NOTE_FIELD_NUMBER} constants, as
     * {@link #normalized} names.
     */
    private Optional<Set<String>> protobufFields(String type) {
        Optional<JavaSootClass> cls = context.findClass(type);
        if (cls.isEmpty() || cls.get().getSuperclass().map(ClassType::getFullyQualifiedName)
                .filter(PROTOBUF_MESSAGES::contains).isEmpty()) {
            return Optional.empty();
        }
        Set<String> fields = new LinkedHashSet<>();
        // By name: a class's fields come in no fixed order.
        for (JavaSootField field : cls.get().getFields().stream().sorted(Comparator.comparing(JavaSootField::getName))
                .toList()) {
            String name = field.getName();
            if (field.isStatic() && name.endsWith(FIELD_NUMBER)) {
                fields.add(normalized(name.substring(0, name.length() - FIELD_NUMBER.length())));
            }
        }
        return Optional.of(fields);
    }

    private static String jsonName(Member member, UnaryOperator<String> naming) {
        String renamed = member.annotations().get(JSON_PROPERTY);
        return renamed == null || renamed.isEmpty() ? naming.apply(member.name()) : renamed;
    }

    /**
     * The naming strategy for the names {@code @JsonProperty} doesn't set: the class's {@code @JsonNaming}, else
     * {@code spring.jackson.property-naming-strategy}, else the names as they are.
     */
    private UnaryOperator<String> naming(Map<String, String> classAnnotations) {
        String strategy = JSON_NAMING.stream().map(naming -> classAnnotations.get(naming + ".value"))
                .filter(java.util.Objects::nonNull)
                .findFirst().or(() -> context.properties().get("spring.jackson.property-naming-strategy"))
                .orElse("");
        String name = strategy.substring(Math.max(strategy.lastIndexOf('.'), strategy.lastIndexOf('$')) + 1)
                .replace("_", "").replace("Strategy", "").toUpperCase(Locale.ROOT);
        return switch (name) {
            case "SNAKECASE" -> TypeProperties::snakeCase;
            case "UPPERSNAKECASE" -> property -> snakeCase(property).toUpperCase(Locale.ROOT);
            case "KEBABCASE" -> property -> separated(property, '-');
            case "LOWERDOTCASE" -> property -> separated(property, '.');
            case "LOWERCASE" -> property -> property.toLowerCase(Locale.ROOT);
            case "UPPERCAMELCASE" -> property -> property.isEmpty() ? property
                    : Character.toUpperCase(property.charAt(0)) + property.substring(1);
            default -> property -> property;
        };
    }

    /**
     * Jackson's {@code SnakeCaseStrategy}: an underscore before each run of capitals, lower case, a leading underscore
     * left out ({@code firstName} is {@code first_name}, {@code homeURL} is {@code home_url}, {@code _id} is
     * {@code id}).
     */
    private static String snakeCase(String property) {
        StringBuilder result = new StringBuilder();
        boolean previousUpper = false;
        for (int i = 0; i < property.length(); i++) {
            char c = property.charAt(i);
            if (i == 0 && c == '_') {
                continue;
            }
            if (Character.isUpperCase(c)) {
                if (!previousUpper && !result.isEmpty() && result.charAt(result.length() - 1) != '_') {
                    result.append('_');
                }
                result.append(Character.toLowerCase(c));
                previousUpper = true;
            }
            else {
                result.append(c);
                previousUpper = false;
            }
        }
        return result.isEmpty() ? property : result.toString();
    }

    /**
     * Jackson's kebab and lower-dot case: the separator before each word, lower case, where the last capital of a run
     * followed by a lower-case letter starts a word ({@code myHTTPServer} is {@code my-http-server}).
     */
    private static String separated(String property, char separator) {
        StringBuilder result = new StringBuilder();
        int capitals = 0;
        for (int i = 0; i < property.length(); i++) {
            char c = property.charAt(i);
            char lower = Character.toLowerCase(c);
            if (lower == c) {
                if (capitals > 1) {
                    result.insert(result.length() - 1, separator);
                }
                capitals = 0;
            }
            else {
                if (capitals == 0 && i > 0) {
                    result.append(separator);
                }
                capitals++;
            }
            result.append(lower);
        }
        return result.toString();
    }
}
