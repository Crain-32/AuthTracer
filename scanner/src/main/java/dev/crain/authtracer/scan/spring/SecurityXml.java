package dev.crain.authtracer.scan.spring;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import org.xml.sax.Attributes;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.AttributesImpl;
import org.xml.sax.helpers.DefaultHandler;

/**
 * Decision 0036: Spring Security's XML namespace configuration (HTTP-21, METHOD-15, METHOD-16), read from the XML
 * files in the application's resources and its {@code src/main/webapp} that use the security namespace, and the
 * beans the XML defines. Each
 * {@code <http>} is a chain: its {@code pattern} (or {@code security="none"}) and its {@code <intercept-url>}s, in
 * order; {@code <method-security>} and the legacy {@code <global-method-security>} enable method security; the login
 * elements are authentication mechanisms. Decision 0097: the rest of the namespace's authorization, the bean
 * references (matchers and managers), {@code <protect-pointcut>}, {@code <intercept-methods>}, and the WebSocket
 * message rules (MSG-06) with the WebSocket namespace's broker; a file AuthTracer can't parse is listed.
 */
@Supports({Feature.REQUEST_RULES, Feature.METHOD_SECURITY, Feature.WEBSOCKET_MESSAGES, Feature.VIEW_FIELDS,
        Feature.AUTHORITY_SOURCE})
final class SecurityXml {

    static final String NAMESPACE = "http://www.springframework.org/schema/security";
    static final String WEBSOCKET_NAMESPACE = "http://www.springframework.org/schema/websocket";

    /**
     * @param access the SpEL the request must satisfy
     * @param regex whether the chain matches with regular expressions ({@code request-matcher="regex"})
     * @param matcherRef decision 0097: the {@code RequestMatcher} bean ({@code request-matcher-ref}) that matches
     *        instead of the pattern, else {@code null}
     */
    record InterceptUrl(String pattern, String method, String access, boolean regex, int line, String matcherRef) {
    }

    /**
     * @param file the file's path relative to its resource directory, e.g. {@code WEB-INF/spring/security.xml}
     * @param pattern the requests the chain handles, {@code null} for all
     * @param none {@code security="none"}: these requests skip Spring Security
     * @param matcherRef decision 0097: the {@code RequestMatcher} bean that picks the chain's requests
     *        ({@code request-matcher-ref}), else {@code null}
     * @param managerRef decision 0097: the {@code AuthorizationManager} bean that decides every request of the chain
     *        instead of its {@code <intercept-url>}s ({@code authorization-manager-ref}), else {@code null}
     * @param legacy {@code use-authorization-manager="false"}: a {@code FilterSecurityInterceptor} decides
     * @param expressions whether {@code access} is SpEL ({@code use-expressions}, true by default), else
     *        configuration attributes for the voters
     */
    record Http(String file, int line, String pattern, boolean regex, boolean none, List<InterceptUrl> rules,
            String matcherRef, String managerRef, boolean legacy, boolean expressions) {
    }

    /**
     * Which annotations method security reads.
     *
     * @param permissionEvaluator EXPR-06: whether its {@code <expression-handler ref>} bean can be given a
     *        {@code PermissionEvaluator} (it sets the {@code permissionEvaluator} property, or is a class of the
     *        application's own); without one, {@code hasPermission(..)} always denies
     */
    record MethodSecurityConfig(boolean prePost, boolean secured, boolean jsr250, boolean permissionEvaluator) {

        MethodSecurityConfig(boolean prePost, boolean secured, boolean jsr250) {
            this(prePost, secured, jsr250, false);
        }
    }

    /**
     * Decision 0097: a {@code <protect-pointcut expression access>} of {@code <method-security>}, or of the legacy
     * {@code <global-method-security>} ({@code legacy}), whose {@code access} is configuration attributes.
     */
    record ProtectPointcut(String expression, String access, boolean legacy, String file, int line) {
    }

    /**
     * Decision 0097: a {@code <protect method access>} of {@code <intercept-methods>}.
     */
    record Protect(String method, String access, int line) {
    }

    /**
     * Decision 0097: the {@code <intercept-methods>} of a {@code <bean>}, which wraps that bean in a proxy of its own.
     *
     * @param beanClass the bean's class
     * @param managerRef the {@code AuthorizationManager} bean that decides every protected method
     *        ({@code authorization-manager-ref}), else {@code null}
     * @param legacy {@code use-authorization-manager="false"}: a {@code MethodSecurityInterceptor} decides, with
     *        configuration attributes
     */
    record InterceptMethods(String beanClass, String managerRef, boolean legacy, String file, int line,
            List<Protect> protects) {
    }

    /**
     * MSG-06: an {@code <intercept-message pattern type access>}; {@code pattern} or {@code type} may be
     * {@code null}.
     */
    record InterceptMessage(String pattern, String type, String access, int line) {
    }

    /**
     * MSG-06: a {@code <websocket-message-broker>}.
     *
     * @param id its {@code id}: then the inbound channel must be given it explicitly, else {@code null}
     * @param managerRef the {@code AuthorizationManager<Message<?>>} bean that decides every message instead of the
     *        rules, else {@code null}
     * @param expressionHandler its {@code <expression-handler ref>}, else {@code null}
     */
    record MessageBroker(String file, int line, String id, String managerRef, String expressionHandler,
            List<InterceptMessage> rules) {
    }

    /**
     * The WebSocket namespace's {@code <websocket:message-broker>}: what {@code @EnableWebSocketMessageBroker} and a
     * {@code WebSocketMessageBrokerConfigurer} set in Java.
     *
     * @param prefixes its {@code application-destination-prefix}es
     * @param endpoints its {@code <stomp-endpoint path>}s
     * @param inboundInterceptors the beans its {@code <client-inbound-channel>} is given as interceptors
     */
    record StompBroker(List<String> prefixes, List<String> endpoints, List<String> inboundInterceptors) {
    }

    /**
     * A {@code <bean id class>}, the properties it sets and the values of its {@code <constructor-arg>}s
     * ({@code null} for one that isn't a value).
     */
    record Bean(String className, Set<String> properties, List<String> arguments) {
    }

    private static final String DEFAULT_EXPRESSION_HANDLER =
            "org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler";

    /**
     * Where an XML-defined JSP view resolver looks for views ({@code InternalResourceViewResolver}'s or
     * {@code <mvc:jsp>}'s {@code prefix} and {@code suffix}).
     */
    record ViewResolver(String prefix, String suffix) {
    }

    /**
     * @param beans the classes of the {@code <bean class="..">} definitions in the application's XML
     * @param beansById the {@code <bean id class>} definitions, by id
     * @param unread the files that use the security namespace but AuthTracer can't parse
     */
    record Config(List<Http> chains, Optional<MethodSecurityConfig> methodSecurity, Set<String> mechanisms,
            Set<String> beans, Optional<ViewResolver> viewResolver, List<ProtectPointcut> pointcuts,
            List<InterceptMethods> interceptMethods, List<MessageBroker> messageBrokers, Optional<StompBroker> stomp,
            Map<String, Bean> beansById, List<String> unread) {

        static final Config NONE = new Config(List.of(), Optional.empty(), Set.of(), Set.of(), Optional.empty(),
                List.of(), List.of(), List.of(), Optional.empty(), Map.of(), List.of());
    }

    static final String BEANS_NAMESPACE = "http://www.springframework.org/schema/beans";
    static final String MVC_NAMESPACE = "http://www.springframework.org/schema/mvc";
    static final Set<String> JSP_VIEW_RESOLVERS = Set.of(
            "org.springframework.web.servlet.view.InternalResourceViewResolver",
            "org.springframework.web.servlet.view.UrlBasedViewResolver");

    private SecurityXml() {
    }

    static Config load(List<Path> resourceDirs) {
        List<Http> chains = new ArrayList<>();
        Optional<MethodSecurityConfig> methodSecurity = Optional.empty();
        Set<String> mechanisms = new LinkedHashSet<>();
        Set<String> beans = new LinkedHashSet<>();
        Optional<ViewResolver> viewResolver = Optional.empty();
        Map<String, Bean> beansById = new LinkedHashMap<>();
        String expressionHandler = null;
        List<ProtectPointcut> pointcuts = new ArrayList<>();
        List<InterceptMethods> interceptMethods = new ArrayList<>();
        List<MessageBroker> messageBrokers = new ArrayList<>();
        Optional<StompBroker> stomp = Optional.empty();
        List<String> unread = new ArrayList<>();
        for (Path dir : resourceDirs) {
            if (!Files.isDirectory(dir)) {
                continue;
            }
            List<Path> files;
            try (Stream<Path> walk = Files.walk(dir, 6)) {
                files = walk.filter(Files::isRegularFile).filter(file -> file.toString().endsWith(".xml")).sorted()
                        .toList();
            }
            catch (IOException ex) {
                continue;
            }
            for (Path file : files) {
                String name = dir.relativize(file).toString().replace('\\', '/');
                Handler handler = new Handler(name);
                Parsed parsed = parse(file, handler);
                if (parsed == Parsed.UNREAD) {
                    unread.add(name);
                }
                if (parsed != Parsed.READ) {
                    continue;
                }
                chains.addAll(handler.chains);
                mechanisms.addAll(handler.mechanisms);
                beans.addAll(handler.beans);
                if (handler.methodSecurity != null) {
                    methodSecurity = Optional.of(handler.methodSecurity);
                    expressionHandler = handler.expressionHandler;
                }
                beansById.putAll(handler.beansById);
                if (handler.viewResolver != null) {
                    viewResolver = Optional.of(handler.viewResolver);
                }
                pointcuts.addAll(handler.pointcuts);
                interceptMethods.addAll(handler.interceptMethods);
                messageBrokers.addAll(handler.messageBrokers);
                if (handler.stomp != null) {
                    stomp = Optional.of(handler.stomp);
                }
            }
        }
        if (methodSecurity.isPresent() && expressionHandler != null) {
            Bean bean = beansById.get(expressionHandler);
            boolean evaluates = bean == null || !bean.className().equals(DEFAULT_EXPRESSION_HANDLER)
                    || bean.properties().contains("permissionEvaluator");
            MethodSecurityConfig found = methodSecurity.get();
            methodSecurity = Optional.of(new MethodSecurityConfig(found.prePost(), found.secured(), found.jsr250(),
                    evaluates));
        }
        return new Config(chains, methodSecurity, mechanisms, beans, viewResolver, pointcuts, interceptMethods,
                messageBrokers, stomp, beansById, unread);
    }

    private enum Parsed {
        READ,
        /**
         * Neither namespace is used: not Spring configuration.
         */
        OTHER,
        /**
         * It uses the security namespace, but doesn't parse.
         */
        UNREAD,
        /**
         * Only the beans namespace, and it doesn't parse.
         */
        SKIPPED
    }

    /**
     * Parses the file as bytes, so the parser honors the encoding it declares ({@code ISO-8859-1} as well as UTF-8).
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private static Parsed parse(Path file, Handler handler) {
        boolean security = false;
        try {
            byte[] content = Files.readAllBytes(file);
            // The namespaces are ASCII, the same bytes in any encoding a Spring XML file has.
            String text = new String(content, StandardCharsets.ISO_8859_1);
            security = text.contains(NAMESPACE);
            if (!security && !text.contains(BEANS_NAMESPACE)) {
                return Parsed.OTHER;
            }
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setNamespaceAware(true);
            // Configuration files, not documents from outside: still, no external entities.
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            SAXParser parser = factory.newSAXParser();
            parser.parse(new ByteArrayInputStream(content), handler);
            return Parsed.READ;
        }
        catch (IOException | SAXException | ParserConfigurationException ex) {
            return security ? Parsed.UNREAD : Parsed.SKIPPED;
        }
    }

    /**
     * A comma-separated attribute's values, as Spring's {@code StringUtils.tokenizeToStringArray(value, ",")} reads
     * them.
     */
    private static List<String> tokens(String value) {
        return value == null ? List.of() : Arrays.stream(value.split(",")).map(String::trim)
                .filter(token -> !token.isEmpty()).toList();
    }

    private static String text(Attributes attributes, String name) {
        String value = attributes.getValue(name);
        return value == null || value.isBlank() ? null : value;
    }

    private static final class Handler extends DefaultHandler {

        private final String file;
        private final List<Http> chains = new ArrayList<>();
        private final Set<String> mechanisms = new LinkedHashSet<>();
        private final Set<String> beans = new LinkedHashSet<>();
        private MethodSecurityConfig methodSecurity;
        private String expressionHandler;
        private final Map<String, Bean> beansById = new LinkedHashMap<>();
        /**
         * The {@code <bean>}s being read, innermost first: their classes, properties and constructor arguments.
         */
        private final Deque<String> beanClasses = new ArrayDeque<>();
        private final Deque<Set<String>> beanProperties = new ArrayDeque<>();
        private final Deque<List<String>> beanArguments = new ArrayDeque<>();
        private ViewResolver viewResolver;
        /**
         * The JSP view resolver bean being read, until its end.
         */
        private ViewResolver resolving;
        private Locator locator;
        private String pattern;
        private boolean regex;
        private boolean none;
        private int line;
        private List<InterceptUrl> rules;
        private Attributes http;
        /**
         * Inside {@code <method-security>} ({@code false}) or {@code <global-method-security>} ({@code true}).
         */
        private Boolean methodElement;
        private final List<ProtectPointcut> pointcuts = new ArrayList<>();
        private final List<InterceptMethods> interceptMethods = new ArrayList<>();
        private InterceptMethods intercepting;
        private final List<MessageBroker> messageBrokers = new ArrayList<>();
        private MessageBroker broker;
        private StompBroker stomp;
        private boolean inboundChannel;
        private boolean inboundInterceptors;

        Handler(String file) {
            this.file = file;
        }

        @Override
        public void setDocumentLocator(Locator locator) {
            this.locator = locator;
        }

        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) {
            if (BEANS_NAMESPACE.equals(uri)) {
                beansElement(localName, attributes);
            }
            // <mvc:view-resolvers><mvc:jsp/>: /WEB-INF/ and .jsp unless given.
            if (MVC_NAMESPACE.equals(uri) && localName.equals("jsp")) {
                viewResolver = new ViewResolver(Optional.ofNullable(attributes.getValue("prefix")).orElse("/WEB-INF/"),
                        Optional.ofNullable(attributes.getValue("suffix")).orElse(".jsp"));
            }
            if (WEBSOCKET_NAMESPACE.equals(uri)) {
                websocketElement(localName, attributes);
            }
            if (NAMESPACE.equals(uri)) {
                securityElement(localName, attributes);
            }
        }

        private void beansElement(String localName, Attributes attributes) {
            switch (localName) {
                case "bean" -> {
                    Set<String> properties = new HashSet<>();
                    List<String> arguments = new ArrayList<>();
                    String className = attributes.getValue("class");
                    beanClasses.push(className == null ? "" : className);
                    beanProperties.push(properties);
                    beanArguments.push(arguments);
                    if (attributes.getValue("id") != null && className != null) {
                        beansById.put(attributes.getValue("id"), new Bean(className, properties, arguments));
                    }
                    if (className != null) {
                        beans.add(className);
                        if (JSP_VIEW_RESOLVERS.contains(className)) {
                            resolving = new ViewResolver("", "");
                        }
                    }
                }
                case "property" -> {
                    if (!beanProperties.isEmpty() && attributes.getValue("name") != null) {
                        beanProperties.peek().add(attributes.getValue("name"));
                    }
                    if (resolving != null && attributes.getValue("value") != null) {
                        switch (String.valueOf(attributes.getValue("name"))) {
                            case "prefix" -> resolving = new ViewResolver(attributes.getValue("value"),
                                    resolving.suffix());
                            case "suffix" -> resolving = new ViewResolver(resolving.prefix(),
                                    attributes.getValue("value"));
                            default -> {
                            }
                        }
                    }
                }
                case "constructor-arg" -> {
                    if (!beanArguments.isEmpty()) {
                        beanArguments.peek().add(attributes.getValue("value"));
                    }
                }
                case "ref" -> {
                    if (inboundInterceptors && attributes.getValue("bean") != null) {
                        stomp.inboundInterceptors().add(attributes.getValue("bean"));
                    }
                }
                default -> {
                }
            }
        }

        private void websocketElement(String localName, Attributes attributes) {
            switch (localName) {
                case "message-broker" -> stomp = new StompBroker(
                        new ArrayList<>(tokens(attributes.getValue("application-destination-prefix"))),
                        new ArrayList<>(), new ArrayList<>());
                case "stomp-endpoint" -> {
                    if (stomp != null) {
                        stomp.endpoints().addAll(tokens(attributes.getValue("path")));
                    }
                }
                case "client-inbound-channel" -> inboundChannel = stomp != null;
                case "interceptors" -> inboundInterceptors = inboundChannel;
                default -> {
                }
            }
        }

        private void securityElement(String localName, Attributes attributes) {
            switch (localName) {
                case "http" -> {
                    pattern = attributes.getValue("pattern");
                    regex = "regex".equals(attributes.getValue("request-matcher"));
                    none = "none".equals(attributes.getValue("security"));
                    line = locator.getLineNumber();
                    rules = new ArrayList<>();
                    http = new AttributesImpl(attributes);
                }
                case "intercept-url" -> {
                    String matcherRef = text(attributes, "request-matcher-ref");
                    if (rules != null && (attributes.getValue("pattern") != null || matcherRef != null)) {
                        String access = attributes.getValue("access");
                        // filters="none" is the legacy way to skip security.
                        boolean skipped = "none".equals(attributes.getValue("filters"));
                        rules.add(new InterceptUrl(attributes.getValue("pattern"), attributes.getValue("method"),
                                skipped ? "permitAll" : access == null ? "authenticated" : access, regex,
                                locator.getLineNumber(), matcherRef));
                    }
                }
                case "method-security" -> {
                    methodElement = false;
                    methodSecurity = new MethodSecurityConfig(
                            !"false".equals(attributes.getValue("pre-post-enabled")),
                            "true".equals(attributes.getValue("secured-enabled")),
                            "true".equals(attributes.getValue("jsr250-enabled")));
                }
                case "global-method-security" -> {
                    methodElement = true;
                    methodSecurity = new MethodSecurityConfig(
                            "enabled".equals(attributes.getValue("pre-post-annotations")),
                            "enabled".equals(attributes.getValue("secured-annotations")),
                            "enabled".equals(attributes.getValue("jsr250-annotations")));
                }
                case "expression-handler" -> {
                    if (methodElement != null) {
                        expressionHandler = attributes.getValue("ref");
                    }
                    else if (broker != null) {
                        broker = new MessageBroker(broker.file(), broker.line(), broker.id(), broker.managerRef(),
                                attributes.getValue("ref"), broker.rules());
                    }
                }
                case "protect-pointcut" -> {
                    if (methodElement != null && attributes.getValue("expression") != null) {
                        pointcuts.add(new ProtectPointcut(attributes.getValue("expression"),
                                Optional.ofNullable(attributes.getValue("access")).orElse(""), methodElement, file,
                                locator.getLineNumber()));
                    }
                }
                case "intercept-methods" -> {
                    if (!beanClasses.isEmpty() && !beanClasses.peek().isEmpty()) {
                        intercepting = new InterceptMethods(beanClasses.peek(),
                                text(attributes, "authorization-manager-ref"),
                                text(attributes, "authorization-manager-ref") == null
                                        && "false".equals(attributes.getValue("use-authorization-manager")),
                                file, locator.getLineNumber(), new ArrayList<>());
                    }
                }
                case "protect" -> {
                    if (intercepting != null && attributes.getValue("method") != null) {
                        intercepting.protects().add(new Protect(attributes.getValue("method"),
                                Optional.ofNullable(attributes.getValue("access")).orElse(""),
                                locator.getLineNumber()));
                    }
                }
                case "websocket-message-broker" -> broker = new MessageBroker(file, locator.getLineNumber(),
                        text(attributes, "id"), text(attributes, "authorization-manager-ref"), null,
                        new ArrayList<>());
                case "intercept-message" -> {
                    if (broker != null) {
                        broker.rules().add(new InterceptMessage(text(attributes, "pattern"),
                                text(attributes, "type"), attributes.getValue("access"), locator.getLineNumber()));
                    }
                }
                case "form-login", "http-basic", "x509", "oauth2-login", "saml2-login", "jwt", "opaque-token",
                        "remember-me", "jee" -> mechanisms.add(localName);
                default -> {
                }
            }
        }

        @Override
        public void endElement(String uri, String localName, String qName) {
            if (BEANS_NAMESPACE.equals(uri) && localName.equals("bean") && !beanProperties.isEmpty()) {
                beanClasses.pop();
                beanProperties.pop();
                beanArguments.pop();
            }
            if (BEANS_NAMESPACE.equals(uri) && localName.equals("bean") && resolving != null) {
                viewResolver = resolving;
                resolving = null;
            }
            if (WEBSOCKET_NAMESPACE.equals(uri) && localName.equals("interceptors")) {
                inboundInterceptors = false;
            }
            if (WEBSOCKET_NAMESPACE.equals(uri) && localName.equals("client-inbound-channel")) {
                inboundChannel = false;
            }
            if (!NAMESPACE.equals(uri)) {
                return;
            }
            switch (localName) {
                case "http" -> {
                    if (rules != null) {
                        chains.add(new Http(file, line, pattern, regex, none, List.copyOf(rules),
                                text(http, "request-matcher-ref"), text(http, "authorization-manager-ref"),
                                text(http, "authorization-manager-ref") == null
                                        && "false".equals(http.getValue("use-authorization-manager")),
                                !"false".equals(http.getValue("use-expressions"))));
                        rules = null;
                    }
                }
                case "method-security", "global-method-security" -> methodElement = null;
                case "intercept-methods" -> {
                    if (intercepting != null) {
                        interceptMethods.add(new InterceptMethods(intercepting.beanClass(), intercepting.managerRef(),
                                intercepting.legacy(), intercepting.file(), intercepting.line(),
                                List.copyOf(intercepting.protects())));
                        intercepting = null;
                    }
                }
                case "websocket-message-broker" -> {
                    if (broker != null) {
                        messageBrokers.add(new MessageBroker(broker.file(), broker.line(), broker.id(),
                                broker.managerRef(), broker.expressionHandler(), List.copyOf(broker.rules())));
                        broker = null;
                    }
                }
                default -> {
                }
            }
        }
    }
}
