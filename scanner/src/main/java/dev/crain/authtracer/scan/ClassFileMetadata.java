package dev.crain.authtracer.scan;

import java.beans.Introspector;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.classfile.Annotation;
import java.lang.classfile.AnnotationValue;
import java.lang.classfile.Attributes;
import java.lang.classfile.ClassFile;
import java.lang.classfile.ClassModel;
import java.lang.classfile.FieldModel;
import java.lang.classfile.MethodModel;
import java.lang.classfile.Signature;
import java.lang.classfile.attribute.RuntimeVisibleAnnotationsAttribute;
import java.lang.classfile.attribute.RuntimeVisibleParameterAnnotationsAttribute;
import java.lang.classfile.attribute.SignatureAttribute;
import java.lang.constant.ClassDesc;
import java.lang.reflect.AccessFlag;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ArrayType;
import sootup.core.types.ClassType;
import sootup.core.types.PrimitiveType;
import sootup.core.types.Type;
import sootup.core.types.VoidType;

/**
 * What SootUp's model drops but the scan needs: generic signatures, record components, and annotations on
 * parameters, fields and record accessors. Read straight from class files with the JDK's ClassFile API: the
 * application's, and for the lookups by method or by any class, a library's or the JDK's too.
 */
@Supports(Feature.APPLICATION_GRAPH)
public final class ClassFileMetadata {

    private static final Logger log = LoggerFactory.getLogger(ClassFileMetadata.class);

    /**
     * A type with its generic arguments, e.g. {@code java.util.List<dev.example.Employee>}.
     */
    public record GenericType(String name, List<GenericType> arguments, boolean variable) {

        public GenericType(String name, List<GenericType> arguments) {
            this(name, arguments, false);
        }

        static GenericType variable(String name) {
            return new GenericType(name, List.of(), true);
        }
    }

    /**
     * A generic class or method's type parameters, and a class's generic supertypes (superclass first).
     */
    public record GenericDeclaration(List<String> typeParameters, List<GenericType> supertypes) {

        static final GenericDeclaration NONE = new GenericDeclaration(List.of(), List.of());
    }

    /**
     * A record component or getter-backed property.
     *
     * @param annotations annotation class name to its {@code value} (empty string when it has none)
     * @param accessor the method that reads it, as declared: a record's {@code ssn()}, a getter's {@code getSsn()},
     *        {@code isActive()}, or Kotlin's {@code getActive()} for a {@code Boolean} property
     */
    public record Member(String name, String type, Map<String, String> annotations, String accessor) {
    }

    private static final String OBJECT = "java.lang.Object";
    private static final String JSON_PROPERTY = "com.fasterxml.jackson.annotation.JsonProperty";
    private static final String JSON_GETTER = "com.fasterxml.jackson.annotation.JsonGetter";

    private final List<Path> classDirs;
    private final List<Path> libraries;
    private final Map<String, Optional<ClassModel>> models = new ConcurrentHashMap<>();
    private final Map<String, Optional<ClassModel>> libraryModels = new ConcurrentHashMap<>();
    private volatile Map<String, Path> libraryIndex;

    public ClassFileMetadata(List<Path> classDirs) {
        this(classDirs, List.of());
    }

    /**
     * @param libraries jars whose classes the lookups by method (generic signatures, parameter annotations) and
     *        {@link #declaration}, {@link #genericFieldType} and {@link #declares} also read, as the JDK's; the record,
     *        getter and class-annotation lookups read the application's classes only
     */
    public ClassFileMetadata(List<Path> classDirs, List<Path> libraries) {
        this.classDirs = classDirs;
        this.libraries = libraries;
    }

    /**
     * The method's generic return type, for a method of the application, a library or the JDK.
     */
    public Optional<GenericType> genericReturnType(MethodSignature method) {
        return genericReturnTypeIn(method.getDeclClassType().getFullyQualifiedName(), method);
    }

    /**
     * The generic return type of the method as {@code className} declares it, if it does.
     */
    public Optional<GenericType> genericReturnTypeIn(String className, MethodSignature method) {
        return methodModel(className, method)
                .flatMap(model -> model.findAttribute(Attributes.signature()))
                .map(SignatureAttribute::asMethodSignature)
                .map(signature -> generic(signature.result()));
    }

    /**
     * Where the application's class declares the method among its methods, as its class file lists them (javac keeps
     * the source order); {@link Integer#MAX_VALUE} when it doesn't.
     */
    public int declarationIndex(MethodSignature method) {
        String descriptor = descriptor(method);
        List<MethodModel> methods = classModel(method.getDeclClassType().getFullyQualifiedName())
                .map(ClassModel::methods).orElse(List.of());
        for (int i = 0; i < methods.size(); i++) {
            if (methods.get(i).methodName().stringValue().equals(method.getName())
                    && methods.get(i).methodType().stringValue().equals(descriptor)) {
                return i;
            }
        }
        return Integer.MAX_VALUE;
    }

    /**
     * Whether the class declares a method with the signature's name and descriptor.
     */
    public boolean declares(String className, MethodSignature method) {
        return methodModel(className, method).isPresent();
    }

    /**
     * A class's type parameters and generic supertypes, for a class of the application, a library or the JDK.
     */
    public GenericDeclaration declaration(String className) {
        return anyClassModel(className).map(model -> model.findAttribute(Attributes.signature())
                .map(SignatureAttribute::asClassSignature)
                .map(signature -> {
                    List<GenericType> supertypes = new ArrayList<>();
                    supertypes.add(generic(signature.superclassSignature()));
                    signature.superinterfaceSignatures().forEach(type -> supertypes.add(generic(type)));
                    return new GenericDeclaration(signature.typeParameters().stream()
                            .map(parameter -> parameter.identifier()).toList(), supertypes);
                })
                .orElseGet(() -> {
                    // Not generic: its supertypes are the raw ones.
                    List<GenericType> supertypes = new ArrayList<>();
                    model.superclass().ifPresent(superclass -> supertypes.add(new GenericType(
                            superclass.asInternalName().replace('/', '.'), List.of())));
                    model.interfaces().forEach(type -> supertypes.add(new GenericType(
                            type.asInternalName().replace('/', '.'), List.of())));
                    return new GenericDeclaration(List.of(), supertypes);
                }))
                .orElse(GenericDeclaration.NONE);
    }

    /**
     * A field's declared type with its generic arguments, e.g. {@code List<Pet>} for {@code pets}.
     */
    public Optional<GenericType> genericFieldType(String className, String fieldName) {
        return anyClassModel(className).flatMap(model -> model.fields().stream()
                .filter(field -> field.fieldName().stringValue().equals(fieldName)).findFirst())
                .map(field -> field.findAttribute(Attributes.signature())
                        .map(signature -> generic(signature.asTypeSignature()))
                        .orElseGet(() -> new GenericType(typeName(field.fieldTypeSymbol()), List.of())));
    }

    /**
     * The method's parameter types with their generic arguments, e.g. {@code Continuation<Customer>}.
     */
    public List<GenericType> genericParameterTypes(MethodSignature method) {
        return methodModel(method)
                .flatMap(model -> model.findAttribute(Attributes.signature()))
                .map(SignatureAttribute::asMethodSignature)
                .map(signature -> signature.arguments().stream().map(ClassFileMetadata::generic).toList())
                .orElse(List.of());
    }

    /**
     * The generic superclass, e.g. {@code ParameterizedTypeReference<List<EmployeeDto>>} for an anonymous subclass.
     */
    public Optional<GenericType> genericSuperclass(String className) {
        return classModel(className)
                .flatMap(model -> model.findAttribute(Attributes.signature()))
                .map(SignatureAttribute::asClassSignature)
                .map(signature -> generic(signature.superclassSignature()));
    }

    /**
     * Class names used as type arguments in the method's generic return type, outermost first,
     * e.g. {@code [dev.example.Employee]} for {@code List<Employee>}.
     */
    public List<String> returnTypeArguments(MethodSignature method) {
        List<String> names = new ArrayList<>();
        genericReturnType(method).ifPresent(type -> type.arguments().forEach(argument -> collect(argument, names)));
        return names;
    }

    /**
     * Record components in declaration order, with the annotations javac copies onto their field and accessor.
     */
    @Supports(Feature.RESPONSE_FIELDS)
    public Optional<List<Member>> recordComponents(String className) {
        return classModel(className).flatMap(model -> model.findAttribute(Attributes.record()).map(record -> {
            List<Member> members = new ArrayList<>();
            for (var component : record.components()) {
                String name = component.name().stringValue();
                Map<String, String> annotations = new LinkedHashMap<>();
                model.fields().stream().filter(field -> field.fieldName().stringValue().equals(name))
                        .findFirst().ifPresent(field -> annotations.putAll(annotations(field)));
                model.methods().stream()
                        .filter(method -> method.methodName().stringValue().equals(name)
                                && method.methodTypeSymbol().parameterCount() == 0)
                        .findFirst().ifPresent(method -> annotations.putAll(annotations(method)));
                members.add(new Member(name, typeName(component.descriptorSymbol()), annotations, name));
            }
            return members;
        }));
    }

    /**
     * Public instance getters ({@code getX()}/{@code isX()}) declared by the class, as properties named the way
     * Jackson 3 names them.
     */
    @Supports(Feature.RESPONSE_FIELDS)
    public List<Member> getters(String className) {
        return getters(className, false);
    }

    /**
     * Public instance getters ({@code getX()}/{@code isX()}) declared by the class, as properties (what reads a field:
     * Jackson writes an {@code isX()} only of a boolean),
     * and any no-argument method marked {@code @JsonProperty} or {@code @JsonGetter}, which Jackson writes whatever
     * its name or visibility ({@code @JsonProperty("iban") String maskedIban()} is the property {@code maskedIban},
     * written as {@code iban}).
     *
     * @param jackson2 name them as Jackson 2 does ({@link #property(String, boolean)})
     */
    @Supports(Feature.RESPONSE_FIELDS)
    public List<Member> getters(String className, boolean jackson2) {
        return classModel(className).map(model -> model.methods().stream()
                .filter(method -> !method.flags().has(AccessFlag.STATIC))
                // A covariant override's bridge (Object getId() for Long getId()) comes after it: not a property.
                .filter(method -> !method.flags().has(AccessFlag.BRIDGE))
                .filter(method -> method.methodTypeSymbol().parameterCount() == 0)
                .filter(method -> !method.methodTypeSymbol().returnType().descriptorString().equals("V"))
                .map(method -> {
                    String name = method.methodName().stringValue();
                    Map<String, String> own = annotations(method);
                    boolean marked = own.containsKey(JSON_PROPERTY) || own.containsKey(JSON_GETTER);
                    Optional<String> property = method.flags().has(AccessFlag.PUBLIC) ? property(name, jackson2)
                            : Optional.empty();
                    if (property.isEmpty() && marked && !name.startsWith("<")) {
                        property = property(name, jackson2).or(() -> Optional.of(name));
                    }
                    return property.map(found -> {
                        Map<String, String> annotations = propertyAnnotations(model, found, method);
                        // @JsonGetter("iban") names the property as @JsonProperty("iban") does.
                        if (!own.getOrDefault(JSON_GETTER, "").isEmpty() && annotations.getOrDefault(JSON_PROPERTY,
                                "").isEmpty()) {
                            annotations.put(JSON_PROPERTY, own.get(JSON_GETTER));
                        }
                        return new Member(found, typeName(method.methodTypeSymbol().returnType()), annotations, name);
                    });
                })
                .flatMap(Optional::stream)
                .toList()).orElse(List.of());
    }

    /**
     * The annotations on any of the class's own methods and fields, by name: what says it is written some other way
     * than as its properties ({@code @JsonValue}, {@code @JsonAnyGetter}).
     */
    public Set<String> memberAnnotations(String className) {
        return classModel(className).map(model -> {
            Set<String> names = new LinkedHashSet<>();
            model.methods().forEach(method -> names.addAll(annotations(method).keySet()));
            model.fields().forEach(field -> names.addAll(annotations(field).keySet()));
            return names;
        }).orElse(Set.of());
    }

    /**
     * The class's own instance fields, in declaration order, with their annotations: whether a serializer writes one
     * depends on its visibility and markers.
     *
     * @param annotations annotation class name to its {@code value}, as for {@link Member}
     */
    public record DeclaredField(String name, String type, Map<String, String> annotations, boolean isPublic,
            boolean isTransient) {
    }

    @Supports(Feature.RESPONSE_FIELDS)
    public List<DeclaredField> fields(String className) {
        return classModel(className).map(model -> model.fields().stream()
                .filter(field -> !field.flags().has(AccessFlag.STATIC) && !field.flags().has(AccessFlag.SYNTHETIC))
                .map(field -> new DeclaredField(field.fieldName().stringValue(), typeName(field.fieldTypeSymbol()),
                        annotations(field), field.flags().has(AccessFlag.PUBLIC),
                        field.flags().has(AccessFlag.TRANSIENT)))
                .toList()).orElse(List.of());
    }

    /**
     * Jackson reads a property's annotations from its field, getter and setter together: {@code @JsonIgnore} on the
     * field hides the getter's property too. A Kotlin class's constructor property has them on its primary
     * constructor's parameter (Kotlin's default use-site target), where jackson-module-kotlin reads them.
     */
    private static Map<String, String> propertyAnnotations(ClassModel model, String property, MethodModel getter) {
        Map<String, String> annotations = new LinkedHashMap<>(constructorParameterAnnotations(model, property));
        model.fields().stream().filter(field -> field.fieldName().stringValue().equals(property)).findFirst()
                .ifPresent(field -> annotations.putAll(annotations(field)));
        String setter = "set" + Character.toUpperCase(property.charAt(0)) + property.substring(1);
        model.methods().stream().filter(method -> method.methodName().stringValue().equals(setter)
                && method.methodTypeSymbol().parameterCount() == 1).findFirst()
                .ifPresent(method -> annotations.putAll(annotations(method)));
        annotations.putAll(annotations(getter));
        return annotations;
    }

    /**
     * For a Kotlin class, the annotations of the primary constructor's parameter for the property. jackson-module-
     * kotlin links a constructor parameter to the property of its name, so a plain parameter ({@code code: String},
     * not a {@code val}) lends its annotations to the body's property of that name, and one that isn't a property's
     * lends them to none: the longest constructor's that has a parameter of the property's name.
     */
    private static Map<String, String> constructorParameterAnnotations(ClassModel model, String property) {
        boolean kotlin = model.findAttribute(Attributes.runtimeVisibleAnnotations()).map(ClassFileMetadata::annotations)
                .filter(found -> found.containsKey("kotlin.Metadata")).isPresent();
        if (!kotlin) {
            return Map.of();
        }
        List<MethodModel> constructors = model.methods().stream()
                .filter(method -> method.methodName().stringValue().equals("<init>")
                        && !method.flags().has(AccessFlag.SYNTHETIC))
                .sorted(Comparator.comparingInt((MethodModel method) -> method.methodTypeSymbol().parameterCount())
                        .reversed())
                .toList();
        for (MethodModel constructor : constructors) {
            int index = parameterNames(constructor).indexOf(property);
            if (index >= 0) {
                return constructor.findAttribute(Attributes.runtimeVisibleParameterAnnotations())
                        .map(RuntimeVisibleParameterAnnotationsAttribute::parameterAnnotations)
                        .filter(all -> index < all.size()).map(all -> annotations(all.get(index))).orElse(Map.of());
            }
        }
        return Map.of();
    }

    /**
     * A method's parameter names: its {@code MethodParameters} attribute's (javac's and kotlinc's
     * {@code -parameters}/{@code -java-parameters}), else its {@code LocalVariableTable}'s (debug information, which
     * kotlinc writes by default); empty when it has neither.
     */
    private static List<String> parameterNames(MethodModel method) {
        Optional<List<String>> declared = method.findAttribute(Attributes.methodParameters())
                .map(attribute -> attribute.parameters().stream()
                        .map(parameter -> parameter.name().map(name -> name.stringValue()).orElse("")).toList());
        if (declared.isPresent()) {
            return declared.get();
        }
        List<ClassDesc> types = method.methodTypeSymbol().parameterList();
        Map<Integer, String> bySlot = new HashMap<>();
        method.code().flatMap(code -> code.findAttribute(Attributes.localVariableTable()))
                .ifPresent(table -> table.localVariables().forEach(local -> bySlot.putIfAbsent(local.slot(),
                        local.name().stringValue())));
        if (bySlot.isEmpty()) {
            return List.of();
        }
        List<String> names = new ArrayList<>();
        int slot = method.flags().has(AccessFlag.STATIC) ? 0 : 1;
        for (ClassDesc type : types) {
            names.add(bySlot.getOrDefault(slot, ""));
            slot += type.descriptorString().equals("J") || type.descriptorString().equals("D") ? 2 : 1;
        }
        return names;
    }

    /**
     * The class's own annotations, by name, with their elements as {@code name.element} entries.
     */
    public Map<String, String> classAnnotations(String className) {
        return classModel(className).flatMap(model -> model.findAttribute(Attributes.runtimeVisibleAnnotations()))
                .map(ClassFileMetadata::annotations).orElse(Map.of());
    }

    public Optional<String> superclass(String className) {
        return classModel(className).flatMap(ClassModel::superclass)
                .map(entry -> entry.asInternalName().replace('/', '.'));
    }

    public boolean isRecord(String className) {
        return classModel(className).flatMap(model -> model.findAttribute(Attributes.record())).isPresent();
    }

    /**
     * {@code getSsn} → {@code ssn}, {@code isActive} → {@code active}, and {@code getSSN} → {@code SSN}: Jackson 3's
     * standard bean naming (Spring Boot 4's default), which keeps a name whose first two letters are capitals.
     */
    @Supports(Feature.RESPONSE_FIELDS)
    public static Optional<String> property(String getterName) {
        return property(getterName, false);
    }

    /**
     * The property a getter reads, as Jackson 3 names it ({@link #property(String)}) or as Jackson 2 does: 2.21's
     * default ({@code MapperFeature.USE_STD_BEAN_NAMING} off) lower-cases the leading run of capitals,
     * {@code getSSN} → {@code ssn}, {@code getURLValue} → {@code urlvalue} ({@code DefaultAccessorNamingStrategy
     * .legacyManglePropertyName}).
     */
    @Supports(Feature.RESPONSE_FIELDS)
    public static Optional<String> property(String getterName, boolean jackson2) {
        String rest = getterName.startsWith("get") && getterName.length() > 3 && !getterName.equals("getClass")
                ? getterName.substring(3)
                : getterName.startsWith("is") && getterName.length() > 2 ? getterName.substring(2) : null;
        return Optional.ofNullable(rest).filter(name -> Character.isUpperCase(name.charAt(0)))
                .map(name -> jackson2 ? legacyName(name) : Introspector.decapitalize(name));
    }

    private static String legacyName(String name) {
        StringBuilder lowered = new StringBuilder();
        int i = 0;
        while (i < name.length() && Character.isUpperCase(name.charAt(i))) {
            lowered.append(Character.toLowerCase(name.charAt(i)));
            i++;
        }
        return lowered.append(name.substring(i)).toString();
    }

    /**
     * The parameter names the method's {@code MethodParameters} attribute gives (javac's {@code -parameters}, kotlinc's
     * {@code -java-parameters}), which is where Spring's {@code StandardReflectionParameterNameDiscoverer} reads them;
     * empty when the class file has none. A {@code LocalVariableTable} doesn't count: Spring Framework 7 doesn't read
     * it.
     */
    @Supports(Feature.METHOD_SECURITY)
    public Optional<List<String>> declaredParameterNames(MethodSignature method) {
        return methodModel(method).flatMap(model -> model.findAttribute(Attributes.methodParameters()))
                .map(attribute -> attribute.parameters().stream()
                        .map(parameter -> parameter.name().map(name -> name.stringValue()).orElse("")).toList());
    }

    /**
     * The annotations on a parameter, by class name.
     */
    public Set<String> parameterAnnotations(MethodSignature method, int parameter) {
        return parameterAnnotationList(method, parameter).stream()
                .map(annotation -> typeName(annotation.classSymbol())).collect(Collectors.toSet());
    }

    /**
     * The {@code value} of an annotation on a parameter, e.g. {@code @Value("${x}")}.
     */
    public Optional<String> parameterAnnotationValue(MethodSignature method, int parameter, String annotationName) {
        return parameterAnnotation(method, parameter, annotationName).flatMap(ClassFileMetadata::valueElement);
    }

    /**
     * An element of an annotation on a parameter, as text (an enum constant by its name), e.g.
     * {@code @Selector(match = ALL_REMAINING)}.
     */
    public Optional<String> parameterAnnotationElement(MethodSignature method, int parameter, String annotationName,
            String element) {
        return parameterAnnotation(method, parameter, annotationName)
                .flatMap(annotation -> annotation.elements().stream()
                        .filter(found -> found.name().stringValue().equals(element)).findFirst())
                .map(found -> found.value() instanceof AnnotationValue.OfEnum constant
                        ? constant.constantName().stringValue() : text(found.value()));
    }

    /**
     * An annotation type's element defaults, as text: arrays joined with {@code ,}.
     */
    public Map<String, String> annotationDefaults(String annotationName) {
        Map<String, String> defaults = new LinkedHashMap<>();
        classModel(annotationName).ifPresent(model -> model.methods().forEach(method -> method
                .findAttribute(Attributes.annotationDefault())
                .ifPresent(attribute -> defaults.put(method.methodName().stringValue(),
                        text(attribute.defaultValue())))));
        return defaults;
    }

    private static String text(AnnotationValue value) {
        return switch (value) {
            case AnnotationValue.OfString string -> string.stringValue();
            case AnnotationValue.OfArray array -> String.join(",", array.values().stream()
                    .map(ClassFileMetadata::text).toList());
            case AnnotationValue.OfConstant constant -> String.valueOf(constant.resolvedValue());
            case AnnotationValue.OfEnum constant -> constant.constantName().stringValue();
            case AnnotationValue.OfClass type -> typeName(type.classSymbol());
            default -> "";
        };
    }

    private static Map<String, String> annotations(FieldModel field) {
        return field.findAttribute(Attributes.runtimeVisibleAnnotations())
                .map(ClassFileMetadata::annotations).orElse(Map.of());
    }

    private static Map<String, String> annotations(MethodModel method) {
        return method.findAttribute(Attributes.runtimeVisibleAnnotations())
                .map(ClassFileMetadata::annotations).orElse(Map.of());
    }

    /**
     * Each annotation's {@code value} by its name, and its other elements as {@code name.element}, e.g.
     * {@code com.fasterxml.jackson.annotation.JsonProperty.access} is {@code WRITE_ONLY}.
     */
    private static Map<String, String> annotations(RuntimeVisibleAnnotationsAttribute attribute) {
        return annotations(attribute.annotations());
    }

    private static Map<String, String> annotations(List<Annotation> all) {
        Map<String, String> annotations = new LinkedHashMap<>();
        for (Annotation annotation : all) {
            String name = typeName(annotation.classSymbol());
            annotations.put(name, valueElement(annotation).orElse(""));
            annotation.elements().forEach(element -> annotations.put(name + "." + element.name().stringValue(),
                    text(element.value())));
        }
        return annotations;
    }

    private static Optional<String> valueElement(Annotation annotation) {
        return annotation.elements().stream()
                .filter(element -> element.name().stringValue().equals("value"))
                .map(element -> element.value())
                .filter(AnnotationValue.OfString.class::isInstance)
                .map(value -> ((AnnotationValue.OfString) value).stringValue())
                .findFirst();
    }

    private static GenericType generic(Signature signature) {
        if (signature instanceof Signature.ClassTypeSig classType) {
            List<GenericType> arguments = new ArrayList<>();
            for (Signature.TypeArg argument : classType.typeArgs()) {
                // An unbounded ? is Object, and keeps its place: Map<?, Owner>'s values are still Owner.
                arguments.add(argument instanceof Signature.TypeArg.Bounded bounded ? generic(bounded.boundType())
                        : new GenericType(OBJECT, List.of()));
            }
            return new GenericType(typeName(classType.classDesc()), arguments);
        }
        if (signature instanceof Signature.ArrayTypeSig array) {
            return new GenericType(generic(array.componentSignature()).name() + "[]", List.of());
        }
        if (signature instanceof Signature.TypeVarSig variable) {
            return GenericType.variable(variable.identifier());
        }
        if (signature instanceof Signature.BaseTypeSig base) {
            return new GenericType(typeName(ClassDesc.ofDescriptor(String.valueOf(base.baseType()))), List.of());
        }
        return new GenericType(signature.signatureString(), List.of());
    }

    private static void collect(GenericType type, List<String> names) {
        names.add(type.name());
        type.arguments().forEach(argument -> collect(argument, names));
    }

    private static String typeName(ClassDesc desc) {
        if (desc.isArray()) {
            return typeName(desc.componentType()) + "[]";
        }
        if (desc.isPrimitive()) {
            return desc.displayName();
        }
        String descriptor = desc.descriptorString();
        return descriptor.substring(1, descriptor.length() - 1).replace('/', '.');
    }

    private Optional<MethodModel> methodModel(MethodSignature method) {
        return methodModel(method.getDeclClassType().getFullyQualifiedName(), method);
    }

    /**
     * The method with the signature's name and descriptor as {@code className} declares it.
     */
    private Optional<MethodModel> methodModel(String className, MethodSignature method) {
        String descriptor = descriptor(method);
        return anyClassModel(className)
                .flatMap(model -> model.methods().stream()
                        .filter(candidate -> candidate.methodName().stringValue().equals(method.getName()))
                        .filter(candidate -> candidate.methodType().stringValue().equals(descriptor))
                        .findFirst());
    }

    private List<Annotation> parameterAnnotationList(MethodSignature method, int parameter) {
        return methodModel(method)
                .flatMap(model -> model.findAttribute(Attributes.runtimeVisibleParameterAnnotations()))
                .map(RuntimeVisibleParameterAnnotationsAttribute::parameterAnnotations)
                .filter(all -> parameter < all.size())
                .map(all -> all.get(parameter))
                .orElse(List.of());
    }

    private Optional<Annotation> parameterAnnotation(MethodSignature method, int parameter, String annotationName) {
        String descriptor = "L" + annotationName.replace('.', '/') + ";";
        return parameterAnnotationList(method, parameter).stream()
                .filter(annotation -> annotation.className().stringValue().equals(descriptor)).findFirst();
    }

    /**
     * The application's class, else a library's or the JDK's.
     */
    private Optional<ClassModel> anyClassModel(String className) {
        Optional<ClassModel> own = classModel(className);
        if (own.isPresent()) {
            return own;
        }
        return libraryModels.computeIfAbsent(className, name -> {
            String file = name.replace('.', '/') + ".class";
            Path jar = libraryIndex().get(file);
            try {
                if (jar != null) {
                    try (ZipFile zip = new ZipFile(jar.toFile())) {
                        ZipEntry entry = zip.getEntry(file);
                        try (InputStream in = zip.getInputStream(entry)) {
                            return Optional.of(ClassFile.of().parse(in.readAllBytes()));
                        }
                    }
                }
                try (InputStream in = ClassLoader.getPlatformClassLoader().getResourceAsStream(file)) {
                    return in == null ? Optional.empty() : Optional.of(ClassFile.of().parse(in.readAllBytes()));
                }
            }
            catch (IOException | IllegalArgumentException ex) {
                log.warn("Class file {} can't be read ({}): its annotations and generics stay unknown", file,
                        ex.toString());
                return Optional.empty();
            }
        });
    }

    /**
     * Each library class file's jar, built on the first library lookup.
     */
    private Map<String, Path> libraryIndex() {
        Map<String, Path> index = libraryIndex;
        if (index == null) {
            synchronized (this) {
                if (libraryIndex == null) {
                    Map<String, Path> built = new HashMap<>();
                    for (Path jar : libraries) {
                        try (ZipFile zip = new ZipFile(jar.toFile())) {
                            zip.stream().map(ZipEntry::getName).filter(name -> name.endsWith(".class"))
                                    .forEach(name -> built.putIfAbsent(name, jar));
                        }
                        catch (IOException ex) {
                            log.warn("Library {} can't be read ({}): its classes stay unknown", jar, ex.toString());
                        }
                    }
                    libraryIndex = built;
                }
                index = libraryIndex;
            }
        }
        return index;
    }

    private Optional<ClassModel> classModel(String className) {
        return models.computeIfAbsent(className, name -> {
            String file = name.replace('.', '/') + ".class";
            for (Path dir : classDirs) {
                Path path = dir.resolve(file);
                if (Files.isRegularFile(path)) {
                    try {
                        return Optional.of(ClassFile.of().parse(Files.readAllBytes(path)));
                    }
                    catch (IOException ex) {
                        throw new UncheckedIOException(ex);
                    }
                }
            }
            return Optional.empty();
        });
    }

    static String descriptor(MethodSignature method) {
        StringBuilder descriptor = new StringBuilder("(");
        method.getParameterTypes().forEach(type -> descriptor.append(descriptor(type)));
        return descriptor.append(')').append(descriptor(method.getType())).toString();
    }

    private static String descriptor(Type type) {
        if (type instanceof VoidType) {
            return "V";
        }
        if (type instanceof PrimitiveType primitive) {
            return switch (primitive.getName()) {
                case "boolean" -> "Z";
                case "byte" -> "B";
                case "char" -> "C";
                case "short" -> "S";
                case "int" -> "I";
                case "long" -> "J";
                case "float" -> "F";
                case "double" -> "D";
                default -> throw new IllegalArgumentException("Unknown primitive " + primitive);
            };
        }
        if (type instanceof ArrayType array) {
            return "[".repeat(array.getDimension()) + descriptor(array.getBaseType());
        }
        if (type instanceof ClassType classType) {
            return "L" + classType.getFullyQualifiedName().replace('.', '/') + ";";
        }
        throw new IllegalArgumentException("Unsupported type " + type);
    }
}
