package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.FieldSignature;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0056: {@code webServiceTemplate.marshalSendAndReceive([uri,] request)} is a SOAP call to the operation
 * the request names: its class's {@code @XmlRootElement(name)}, by default the class's simple name decapitalized,
 * as JAXB names it, or a {@code JAXBElement}'s name. Its other sends (XML as it is, a message a callback writes) are calls to an operation AuthTracer
 * doesn't read (decision 0082). Its endpoint is the {@code uri} argument, else the {@code setDefaultUri(..)} in the calling class or
 * a {@code @Bean} method. The linker links it to the SOAP Ingress of that name.
 */
@Supports(Feature.SERVICE_CALLS)
final class SoapCalls {

    static final String CLIENT = "WebServiceTemplate";
    private static final Set<String> TEMPLATES = Set.of("org.springframework.ws.client.core.WebServiceTemplate",
            "org.springframework.ws.client.core.WebServiceOperations");
    private static final String GATEWAY_SUPPORT = "org.springframework.ws.client.core.support.WebServiceGatewaySupport";
    private static final String ROOT_ELEMENT = "jakarta.xml.bind.annotation.XmlRootElement";
    private static final String MARSHAL = "marshalSendAndReceive";
    private static final String ELEMENT = "jakarta.xml.bind.JAXBElement";
    private static final String ELEMENT_DECL = "jakarta.xml.bind.annotation.XmlElementDecl";
    private static final String XML_SCHEMA = "jakarta.xml.bind.annotation.XmlSchema";
    private static final Set<String> ACTION_CALLBACKS = Set.of("org.springframework.ws.soap.client.core.SoapActionCallback",
            "org.springframework.ws.soap.addressing.client.ActionCallback");
    /**
     * {@code WebServiceOperations}' sends: of an object the marshaller writes, of XML, or of a message a callback
     * writes.
     */
    private static final Set<String> SENDS = Set.of(MARSHAL, "sendSourceAndReceive", "sendSourceAndReceiveToResult",
            "sendAndReceive");

    private final ScanContext context;
    private final UnreadCalls unread;
    private final ConfiguredValues configured;

    SoapCalls(ScanContext context, UnreadCalls unread, ConfiguredValues configured) {
        this.context = context;
        this.unread = unread;
        this.configured = configured;
    }

    Optional<Egress> detect(JavaSootMethod caller, Stmt stmt, AbstractInvokeExpr invoke) {
        String name = invoke.getMethodSignature().getName();
        if (!TEMPLATES.contains(invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName())
                || !SENDS.contains(name)) {
            return Optional.empty();
        }
        // Each takes the URI first, or doesn't take one: (Object request[, callback]), (String uri, Object request
        // [, callback]), (Source[, ..]), (String uri, Source[, ..]), (callback, ..), (String uri, callback, ..).
        boolean withUri = invoke.getMethodSignature().getParameterTypes().getFirst().toString()
                .equals("java.lang.String");
        Value request = invoke.getArg(withUri ? 1 : 0);
        Optional<String> uri = withUri ? uri(caller, invoke.getArg(0)) : defaultUri(caller);
        String base = uri.flatMap(AbsoluteUrl::parse).map(AbsoluteUrl::base).orElse(null);
        Optional<String> operation = name.equals(MARSHAL) ? elementName(caller, request)
                .or(() -> requestType(caller, request).flatMap(this::rootElement)) : Optional.empty();
        Optional<String> action = action(caller, invoke);
        if (operation.isEmpty() && action.isEmpty()) {
            // Decision 0082: the request's type names the operation, which XML sent as it is doesn't.
            return Optional.of(unread.egress(CLIENT, SoapEndpoints.SOAP, "request", base, null, caller, stmt,
                    name.equals(MARSHAL) ? "a request from " + UnreadCalls.origin(caller, request)
                            : name.startsWith("sendSource") ? "XML sent as it is" : "a message a callback writes",
                    null));
        }
        // The operation its payload's root names, which Spring WS maps first, in its namespace, and the action it
        // names, which the SOAP action mappings take when no payload root mapping does.
        List<String> conditions = new ArrayList<>();
        // Only a marshalled request of a type names an operation, through a local.
        operation.flatMap(found -> namespace(caller, (Local) request))
                .ifPresent(namespace -> conditions.add(SoapEndpoints.NAMESPACE + namespace));
        action.ifPresent(found -> conditions.add(SoapEndpoints.ACTION + found));
        return Optional.of(Egress.of(CLIENT, SoapEndpoints.SOAP, operation.or(() -> action).orElseThrow(), base, null,
                MethodNames.codeRef(caller.getSignature(), stmt), null).withQuery(String.join("&", conditions)));
    }

    /**
     * The SOAP action the call's callback names: {@code new SoapActionCallback("..")}, or WS-Addressing's
     * {@code new ActionCallback("..")}, made at the call.
     */
    private static Optional<String> action(JavaSootMethod caller, AbstractInvokeExpr invoke) {
        for (Value argument : invoke.getArgs()) {
            if (argument instanceof Local local && Locals.created(caller.getBody(), local)
                    .filter(type -> ACTION_CALLBACKS.contains(type.getFullyQualifiedName())).isPresent()) {
                // Each takes the action first, a String or (ActionCallback) a URI, which isn't read.
                return constructor(caller, local).flatMap(init -> HttpClientEgress.constant(caller, init.getArg(0)));
            }
        }
        return Optional.empty();
    }

    /**
     * The namespace of the request's root element: a {@code JAXBElement}'s {@code QName}, an {@code ObjectFactory}
     * method's {@code @XmlElementDecl(namespace)}, else the class's {@code @XmlRootElement(namespace)}, else its
     * package's {@code @XmlSchema(namespace)}, as xjc generates them.
     */
    private Optional<String> namespace(JavaSootMethod caller, Local local) {
        Value definition = Locals.definition(caller.getBody(), local).orElse(null);
        if (definition instanceof AbstractInvokeExpr call && context.isApplication(call.getMethodSignature()
                .getDeclClassType())) {
            return context.findMethod(call.getMethodSignature())
                    .flatMap(factory -> context.findAnnotation(factory, ELEMENT_DECL))
                    .flatMap(annotation -> Annotations.string(annotation, "namespace")).filter(SoapCalls::declared);
        }
        if (definition instanceof JNewExpr created && created.getType().getFullyQualifiedName().equals(ELEMENT)) {
            return constructor(caller, local).flatMap(init -> qName(caller, init.getArg(0), true))
                    .filter(SoapCalls::declared);
        }
        Optional<ClassType> type = requestType(caller, local);
        Optional<String> own = type.flatMap(context::findClass).flatMap(cls -> context.findAnnotation(cls,
                ROOT_ELEMENT)).flatMap(annotation -> Annotations.string(annotation, "namespace"))
                .filter(SoapCalls::declared);
        return own.or(() -> type.flatMap(found -> context.findClass(found.getPackageName().getName()
                + ".package-info")).flatMap(info -> context.findAnnotation(info, XML_SCHEMA))
                .flatMap(annotation -> Annotations.string(annotation, "namespace")).filter(SoapCalls::declared));
    }

    private static boolean declared(String namespace) {
        return !namespace.isEmpty() && !namespace.equals("##default");
    }

    private Optional<ClassType> requestType(JavaSootMethod caller, Value request) {
        if (!(request instanceof Local local)) {
            return Optional.empty();
        }
        if (local.getType() instanceof ClassType type && context.isApplication(type)) {
            return Optional.of(type);
        }
        return Locals.created(caller.getBody(), local).filter(context::isApplication);
    }

    private Optional<String> rootElement(ClassType type) {
        Optional<JavaSootClass> cls = context.findClass(type);
        if (cls.isEmpty()) {
            return Optional.empty();
        }
        Optional<String> named = context.findAnnotation(cls.get(), ROOT_ELEMENT)
                .flatMap(annotation -> Annotations.string(annotation, "name"))
                .filter(name -> !name.isEmpty() && !name.equals("##default"));
        String simple = type.getClassName().substring(type.getClassName().lastIndexOf('$') + 1);
        return named.or(() -> Optional.of(Character.toLowerCase(simple.charAt(0)) + simple.substring(1)));
    }

    /**
     * A template's or client's {@code setDefaultUri("http://..")}, or {@code setDefaultUri(uri)} with a
     * {@code @Value} or a {@code @ConfigurationProperties} getter: in the calling class (a
     * {@code WebServiceGatewaySupport}), else in the {@code @Bean} method that builds it, else in one that builds a
     * {@code WebServiceTemplate}. The first of them to set one decides, also when what it sets can't be read: it is no
     * other template's.
     */
    private Optional<String> defaultUri(JavaSootMethod caller) {
        ClassType client = caller.getDeclaringClassType();
        List<JavaSootMethod> beans = SpringBeans.beanMethods(context);
        List<List<JavaSootMethod>> places = List.of(
                context.findClass(client).map(cls -> List.copyOf(cls.getMethods())).orElse(List.of()),
                beans.stream().filter(method -> method.getReturnType().equals(client)).toList(),
                beans.stream().filter(method -> method.getReturnType() instanceof ClassType type
                        && TEMPLATES.contains(type.getFullyQualifiedName())).toList());
        for (List<JavaSootMethod> methods : places) {
            List<Optional<String>> set = defaultUris(methods);
            if (!set.isEmpty()) {
                return set.stream().flatMap(Optional::stream).findFirst();
            }
        }
        return Optional.empty();
    }

    /**
     * The default URIs the methods set, each empty when it can't be read.
     */
    private List<Optional<String>> defaultUris(List<JavaSootMethod> methods) {
        List<Optional<String>> uris = new ArrayList<>();
        for (JavaSootMethod method : methods) {
            if (!method.hasBody()) {
                continue;
            }
            for (Stmt stmt : method.getBody().getStmts()) {
                Optional<AbstractInvokeExpr> call = Locals.invoke(stmt);
                if (call.isPresent() && call.get().getMethodSignature().getName().equals("setDefaultUri")
                        && call.get().getArgCount() == 1
                        && template(call.get().getMethodSignature().getDeclClassType())) {
                    uris.add(uri(method, call.get().getArg(0)));
                }
            }
        }
        return uris;
    }

    /**
     * A URI the configuration gives: a constant, a {@code @Value}, a {@code @ConfigurationProperties} getter.
     */
    private Optional<String> uri(JavaSootMethod method, Value argument) {
        return Optional.ofNullable(configured.of(method, argument).value());
    }

    /**
     * A {@code JAXBElement} request's element name: the {@code QName} it is created with
     * ({@code new JAXBElement<>(new QName(ns, "getCountryRequest"), Type.class, request)}, also a {@code QName}
     * constant), or the {@code @XmlElementDecl} name of the {@code ObjectFactory} method that creates it, as xjc
     * generates them for elements whose types have no {@code @XmlRootElement}.
     */
    private Optional<String> elementName(JavaSootMethod caller, Value request) {
        if (!(request instanceof Local local)) {
            return Optional.empty();
        }
        Value definition = Locals.definition(caller.getBody(), local).orElse(null);
        if (definition instanceof AbstractInvokeExpr call && context.isApplication(call.getMethodSignature()
                .getDeclClassType())) {
            return context.findMethod(call.getMethodSignature())
                    .flatMap(factory -> context.findAnnotation(factory, ELEMENT_DECL))
                    .flatMap(annotation -> Annotations.string(annotation, "name"));
        }
        if (!(definition instanceof JNewExpr created) || !created.getType().getFullyQualifiedName().equals(ELEMENT)) {
            return Optional.empty();
        }
        // JAXBElement(QName, Class, value) and JAXBElement(QName, Class, Class scope, value): the name first.
        return constructor(caller, local).flatMap(init -> qName(caller, init.getArg(0), false));
    }

    private static Optional<AbstractInvokeExpr> constructor(JavaSootMethod method, Local created) {
        return method.getBody().getStmts().stream().flatMap(stmt -> Locals.invoke(stmt).stream())
                .filter(invoke -> invoke instanceof AbstractInstanceInvokeExpr instance
                        && instance.getBase().equals(created) && invoke.getMethodSignature().getName().equals("<init>"))
                .findFirst();
    }

    /**
     * A {@code QName}'s local part, or with {@code namespace} its namespace: {@code new QName(ns, local[, prefix])}
     * or {@code new QName(local)}, made where it is used or held in a field (an {@code ObjectFactory}'s
     * {@code static final QName}).
     */
    private Optional<String> qName(JavaSootMethod method, Value name, boolean namespace) {
        if (!(name instanceof Local local)) {
            return Optional.empty();
        }
        Value definition = Locals.definition(method.getBody(), local).orElse(null);
        if (definition instanceof JNewExpr) {
            return constructor(method, local).filter(init -> !namespace || init.getArgCount() > 1)
                    .flatMap(init -> HttpClientEgress.constant(method, init.getArg(namespace
                            || init.getArgCount() == 1 ? 0 : 1)));
        }
        if (definition instanceof JFieldRef field) {
            FieldSignature signature = field.getFieldSignature();
            for (JavaSootMethod initializer : context.findClass(signature.getDeclClassType())
                    .map(JavaSootClass::getMethods).orElse(Set.of())) {
                for (Stmt stmt : initializer.hasBody() ? initializer.getBody().getStmts() : List.<Stmt>of()) {
                    if (stmt instanceof AbstractDefinitionStmt assign && assign.getLeftOp() instanceof JFieldRef target
                            && target.getFieldSignature().equals(signature)) {
                        return qName(initializer, assign.getRightOp(), namespace);
                    }
                }
            }
        }
        return Optional.empty();
    }

    /**
     * A {@code WebServiceTemplate}, or a {@code WebServiceGatewaySupport} client, whose default URI it sets.
     */
    private boolean template(ClassType type) {
        return Stream.concat(Stream.of(type), context.superClassesOf(type).stream())
                .map(ClassType::getFullyQualifiedName)
                .anyMatch(name -> TEMPLATES.contains(name) || name.equals(GATEWAY_SUPPORT));
    }
}
