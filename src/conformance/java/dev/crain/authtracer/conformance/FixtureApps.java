package dev.crain.authtracer.conformance;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import javax.xml.parsers.DocumentBuilderFactory;

import org.aopalliance.intercept.MethodInterceptor;
import org.springframework.aop.ProxyMethodInvocation;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.SpringApplicationRunListener;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.context.annotation.ImportCandidates;
import org.springframework.boot.web.context.reactive.GenericReactiveWebApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.ClassPathBeanDefinitionScanner;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.cloud.stream.binder.kafka.provisioning.KafkaTopicProvisioner;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.retry.RetryPolicy;
import org.springframework.core.retry.RetryTemplate;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.server.MatcherSecurityWebFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ott.ServerOneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.PlaceholderResolutionException;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.GenericWebApplicationContext;
import org.w3c.dom.Element;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Hooks;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Boots a fixture in a mock web environment, as the scanner reads it. A fixture with an application class runs as that
 * Spring Boot application, started by its main method when it has one. One without is a package of configuration the
 * scanner reads without Boot: it is hosted in a Boot application that scans the package, and when the package
 * configures no security of its own (no chain, no {@code @EnableWebSecurity} or {@code @EnableWebFluxSecurity}, no
 * XML), Boot's default chains are kept out, since nothing would secure it without Boot. So is Boot's auto-proxying
 * (AopAutoConfiguration), which applies every advisor bean: without Boot only what the package enables does. Every
 * Spring XML file under its resources is loaded too, as the scanner reads them all (SecurityXml).
 *
 * <p>The fixtures share one classpath, so what a fixture can't start without there, though it would in an application
 * of its own, is filled in ({@link Gaps}), and listeners and servers that would reach for the network don't start.
 */
final class FixtureApps {

    record App(ConfigurableApplicationContext context, Clients.Client client, String how) implements AutoCloseable {

        @Override
        public void close() {
            try {
                context.close();
            } catch (RuntimeException ignored) {
                // A fixture that fails to stop has still been probed.
            }
        }
    }

    static final class NotBooted extends Exception {

        NotBooted(String reason) {
            super(reason);
        }
    }

    /**
     * Auto-configuration no fixture needs that breaks on the shared classpath: the WebFlux gateway (Boot's WebFlux
     * module isn't the fixtures'), the MVC gateway's catch-all function route, and RSocket security, which needs an
     * authentication manager only RSocket fixtures declare.
     */
    private static final List<String> EXCLUDED = List.of(
            "org.springframework.boot.security.autoconfigure.rsocket.RSocketSecurityAutoConfiguration",
            "org.springframework.cloud.gateway.server.mvc.config.DefaultFunctionConfiguration",
            "org.springframework.cloud.gateway.config.GatewayClassPathWarningAutoConfiguration",
            "org.springframework.cloud.gateway.config.GatewayAutoConfiguration",
            "org.springframework.cloud.gateway.config.GatewayResilience4JCircuitBreakerAutoConfiguration",
            "org.springframework.cloud.gateway.config.GatewayNoLoadBalancerClientAutoConfiguration",
            "org.springframework.cloud.gateway.config.GatewayFunctionAutoConfiguration",
            "org.springframework.cloud.gateway.config.GatewayMetricsAutoConfiguration",
            "org.springframework.cloud.gateway.config.GatewayRedisAutoConfiguration",
            "org.springframework.cloud.gateway.config.GatewayStreamAutoConfiguration",
            "org.springframework.cloud.gateway.discovery.GatewayDiscoveryClientAutoConfiguration",
            "org.springframework.cloud.gateway.config.SimpleUrlHandlerMappingGlobalCorsAutoConfiguration",
            "org.springframework.cloud.gateway.config.GatewayReactiveLoadBalancerClientAutoConfiguration",
            "org.springframework.cloud.gateway.config.LocalResponseCacheAutoConfiguration");

    /**
     * Boot's servlet security, left out when XML configuration builds the filter chain itself.
     */
    private static final List<String> BOOT_SERVLET_SECURITY = List.of(
            "org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration",
            "org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterAutoConfiguration",
            "org.springframework.boot.security.autoconfigure.actuate.web.servlet.ManagementWebSecurityAutoConfiguration",
            "org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration");

    /**
     * Boot's auto-proxy creator, which a package of configuration doesn't have without Boot (AutoProxyCreators).
     */
    private static final String BOOT_AOP = "org.springframework.boot.autoconfigure.aop.AopAutoConfiguration";
    /**
     * What makes Boot's default {@code taskScheduler} on the shared classpath, a second {@code TaskExecutor} beside
     * {@code applicationTaskExecutor}, as packages ({@code a/b/}, as class files write them): Spring Integration's
     * auto-configuration (Spring Cloud Stream brings it) and the gRPC server's health checks import it.
     */
    /**
     * Libraries on the shared classpath, by the packages that name them, and the auto-configuration (by its names'
     * beginnings) that brings them to every fixture: Spring Integration with Spring Cloud Stream and Function, which
     * need it; Spring Data REST.
     */
    private static final Map<List<String>, List<String>> LIBRARIES = Map.of(
            List.of("org.springframework.integration.", "org.springframework.cloud.stream.",
                    "org.springframework.cloud.function."),
            List.of("org.springframework.boot.integration.", "org.springframework.cloud.stream.",
                    "org.springframework.cloud.function."),
            List.of("org.springframework.data.rest."), List.of("org.springframework.boot.data.rest."));
    private static final List<String> SCHEDULER_USERS = List.of("org/springframework/integration/",
            "org/springframework/cloud/stream/", "io/grpc/", "org/springframework/grpc/",
            "org/springframework/scheduling/annotation/EnableScheduling");

    /**
     * An auto-configuration that fails to load on the shared classpath, whose bean clashes with one another module's
     * auto-configuration already defined (a second embedded server's, say), or whose lambda bean AspectJ can't read
     * as it matches a fixture's pointcut against every bean.
     */
    private static final Pattern FAILED_CONDITION = Pattern.compile(
            "(?:Error processing condition on|Failed to introspect Class \\[|missing type )([\\w.$]+)"
                    + "|Invalid bean definition with name '[^']*' defined in class path resource \\[([\\w/$]+)\\.class]");
    private static final String BEANS_NAMESPACE = "http://www.springframework.org/schema/beans";
    private static final int BOOT_SECONDS = 30;
    private static List<String> autoConfigurations;

    /**
     * Configuration for a hosted fixture: Boot's auto-configuration, and the fixture's package added by an
     * initializer.
     */
    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class Host {
    }

    private FixtureApps() {
    }

    /**
     * Puts back what a fixture sets for the whole JVM, as it is before an application sets it, so no fixture runs under
     * another's: the SecurityContextHolder's strategy ({@code threadhopsinherited} makes it inheritable, so threads a
     * later fixture hands work to would carry a caller) and Reactor's hooks ({@code threadhopsreactorpropagation}
     * turns on automatic context propagation).
     */
    static void resetJvmState() {
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);
        Hooks.resetOnEachOperator();
        Hooks.resetOnLastOperator();
        Hooks.resetOnOperatorError();
        Hooks.disableAutomaticContextPropagation();
        Schedulers.resetOnScheduleHooks();
    }

    static App boot(String fixture, Path resourcesRoot) throws NotBooted {
        resetJvmState();
        Path resources = resourcesRoot.resolve(fixture);
        Class<?> application = applicationClass(fixture);
        boolean hosted = application == null;
        List<File> xml = hosted ? xmlConfiguration(resources) : List.of();
        // The web stack is the one Boot picks on the fixtures' classpath (Servlet, unless the main method or
        // spring.main.web-application-type says otherwise), as the scanner reads it (WebStack); its security
        // configuration doesn't choose.
        Options options = new Options(fixture, resources, hosted ? Host.class : application, hosted, xml, false);
        Gaps gaps = new Gaps(options);
        ConfigurableApplicationContext context = bootFilling(options, gaps);
        String how = hosted ? "hosted" : "as " + application.getSimpleName();
        boolean bootsDefaults = context instanceof WebApplicationContext
                ? onlyBootsDefaultChains(context, SecurityFilterChain.class)
                        && !annotated(fixture, EnableWebSecurity.class)
                // Boot's actuator chain, or Spring Security's default, which Boot's @EnableWebFluxSecurity makes when
                // there is no chain.
                : !annotated(fixture, EnableWebFluxSecurity.class)
                        && (context.getBeanNamesForType(SecurityWebFilterChain.class).length == 0
                                || onlyBootsDefaultChains(context, SecurityWebFilterChain.class));
        if (hosted && xml.isEmpty() && bootsDefaults) {
            context.close();
            context = bootFilling(options.withoutSecurity(), gaps);
            how += " without security";
        }
        if (!xml.isEmpty()) {
            how += " with " + xml.size() + " XML files";
        }
        how += gaps.describe();
        Clients.Client client = context instanceof WebApplicationContext web ? Clients.servlet(web)
                : Clients.reactive(context);
        Collection<StandInStore> stores = context.getBeansOfType(StandInStore.class).values();
        if (!stores.isEmpty()) {
            Clients.Client sending = client;
            client = (endpoint, probe) -> {
                stores.forEach(StandInStore::reset);
                return sending.send(endpoint, probe);
            };
        }
        return new App(context, client, how);
    }

    private record Options(String fixture, Path resources, Class<?> source, boolean hosted, List<File> xml,
            boolean noSecurity) {

        Options withoutSecurity() {
            return new Options(fixture, resources, source, hosted, xml, true);
        }
    }

    /**
     * Boots, filling in what the shared classpath leaves the fixture without, one gap at a time.
     */
    private static ConfigurableApplicationContext bootFilling(Options options, Gaps gaps) throws NotBooted {
        while (true) {
            try {
                return boot(options, gaps);
            } catch (NotBooted e) {
                throw e;
            } catch (Throwable e) {
                if (!gaps.fill(e)) {
                    throw new NotBooted("boot failed: " + Clients.root(e));
                }
            }
        }
    }

    /**
     * What a fixture can't start without on the shared classpath, though it would in an application of its own:
     * <ul>
     * <li>auto-configuration that fails to load here, left out, and a library's ({@link #LIBRARIES}) that a failure
     * names when the fixture doesn't use it; and Boot's scheduler, which the shared classpath
     * makes a second executor beside Boot's executor: a fixture that asks for one executor and uses nothing that would
     * make the scheduler ({@link #SCHEDULER_USERS}) gets Boot's executor, its only one in an application of its
     * own;</li>
     * <li>a bean another part of its application would declare (a repository, a client, a template), from the
     * failure that names its type: a stand-in that does nothing and answers empty values. Never a Spring Security
     * type but the OAuth2 client's authorized client managers, which only get tokens for calls out, and a token's
     * decoders and introspectors, which a probe (it carries its Authentication) never reaches, and a one-time token's
     * delivery, which only sends the token out; nor an executor or task decorator: those decide what is checked and
     * for whom, so a fixture missing one doesn't boot. A JWT decoder that asks its issuer as it is made (Boot's, or
     * the fixture's own) is replaced by a stand-in, under its name, when the issuer can't be reached;</li>
     * <li>a store for the Spring Data repositories none backs, so that Spring Data REST serves them
     * ({@link StandInStore});</li>
     * <li>Boot's default user (and, for the XML namespace, a global {@code <authentication-manager>} that knows
     * it): its {@code UserDetailsServiceAutoConfiguration} backs off when an OAuth2 client or
     * resource server is on the classpath, as on the fixtures', which leaves a form login or remember-me without
     * users;</li>
     * <li>a placeholder for a URL, a path, a port or a message destination, which no check reads, an OAuth2 client
     * registration's {@code client-id}, which the deployment gives, and {@code server.http2.enabled}, which a
     * container serving gRPC would have.</li>
     * </ul>
     */
    static final class Gaps {

        private static final String XML_AUTHENTICATION_MANAGER = "org.springframework.security.authenticationManager";
        private static final String EXECUTOR = "applicationTaskExecutor";
        private static final String SCHEDULER = "taskScheduler";
        private static final String STORE = "conformanceStore";
        private static final Pattern WHERE = Pattern.compile("(?i).*(url|uri|path|port|topic|queue|destination)$");
        private static final Pattern CLIENT_ID = Pattern.compile("Client id of registration '([^']+)' must not be empty");
        private static final Pattern TOKEN_DELIVERY = Pattern.compile(
                "A (Server)?OneTimeTokenGenerationSuccessHandler is required");
        private static final Set<String> CALLS_OUT = Set.of(
                "org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager",
                "org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager",
                // A probe carries its Authentication and sends no bearer token, so a token's decoder or
                // introspector never decides it.
                "org.springframework.security.oauth2.jwt.JwtDecoder",
                "org.springframework.security.oauth2.jwt.ReactiveJwtDecoder",
                "org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector",
                "org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector",
                // It sends the one-time token to the user (a mail, a message); the login checks the token.
                "org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler",
                "org.springframework.security.web.server.authentication.ott.ServerOneTimeTokenGenerationSuccessHandler");
        private static final Pattern REQUIRED = Pattern.compile(
                "Configuration property '(server\\.http2\\.enabled)' should be set to true");
        private static final List<String> DECIDING = List.of("org.springframework.security.",
                "org.springframework.core.task.", "org.springframework.scheduling.");

        final Set<String> excluded = new LinkedHashSet<>(EXCLUDED);
        final Set<Class<?>> standIns = new LinkedHashSet<>();
        /**
         * Beans whose definitions are replaced by a stand-in of the type, by name.
         */
        final Map<String, Class<?>> replaced = new LinkedHashMap<>();
        final Map<String, String> properties = new LinkedHashMap<>();
        boolean defaultUser;
        boolean xmlAuthenticationManager;
        boolean executorFirst;
        /**
         * Whether the repositories no store backs get Spring Data's map store ({@link StandInStore}); dropped when
         * Spring Data can't make one of them there (a query it can't derive), for stand-ins.
         */
        boolean store = true;
        final List<String> stored = new ArrayList<>();

        private final String fixture;

        Gaps(Options options) {
            fixture = options.fixture();
            if (!options.xml().isEmpty()) {
                excluded.addAll(BOOT_SERVLET_SECURITY);
            }
            if (options.hosted()) {
                excluded.add(BOOT_AOP);
            }
        }

        /**
         * Fills the gap the failure names, if it is one that can be filled and isn't yet.
         */
        boolean fill(Throwable thrown) {
            String failing = failingAutoConfiguration(thrown);
            if (failing != null) {
                return excluded.add(failing);
            }
            for (Throwable cause = thrown; store && cause != null; cause = cause.getCause()) {
                if (String.valueOf(cause.getMessage()).contains(STORE)) {
                    return !(store = false);
                }
            }
            for (Throwable cause = thrown; cause != null; cause = cause.getCause()) {
                String message = String.valueOf(cause.getMessage());
                if (cause instanceof BeanCreationException creating && creating.getBeanName() != null
                        && creating.getBeanName().toLowerCase(Locale.ROOT).contains("jwtdecoder")
                        && root(cause) instanceof java.net.UnknownHostException) {
                    // A decoder that asks its issuer as it is made: Boot's, or one of the fixture's own.
                    Class<?> decoder = creating.getBeanName().toLowerCase(Locale.ROOT).contains("reactive")
                            ? ReactiveJwtDecoder.class : JwtDecoder.class;
                    return replaced.putIfAbsent(creating.getBeanName(), decoder) == null;
                }
                Matcher delivery = TOKEN_DELIVERY.matcher(message);
                if (delivery.find()) {
                    return standIns.add(delivery.group(1) != null ? ServerOneTimeTokenGenerationSuccessHandler.class
                            : OneTimeTokenGenerationSuccessHandler.class);
                }
                Matcher clientId = CLIENT_ID.matcher(message);
                if (clientId.find()) {
                    return properties.putIfAbsent("spring.security.oauth2.client.registration." + clientId.group(1)
                            + ".client-id", "conformance") == null;
                }
                if (cause instanceof NoUniqueBeanDefinitionException ambiguous
                        && ambiguous.getBeanNamesFound() != null
                        && Set.copyOf(ambiguous.getBeanNamesFound()).equals(Set.of(EXECUTOR, SCHEDULER))
                        && !executorFirst && !references(fixture, SCHEDULER_USERS)) {
                    return executorFirst = true;
                }
                Optional<List<String>> library = unusedLibrary(message.replace('/', '.'));
                if (library.isPresent()) {
                    return excluded.addAll(autoConfigurations().stream().filter(name -> library.get().stream()
                            .anyMatch(name::startsWith)).toList());
                }
                // Two beans of a type where one is asked for: no stand-in makes that one.
                if (cause instanceof NoSuchBeanDefinitionException missing
                        && !(cause instanceof NoUniqueBeanDefinitionException) && missing.getBeanType() != null) {
                    Class<?> type = missing.getBeanType();
                    if (type == UserDetailsService.class || type == ReactiveUserDetailsService.class) {
                        return !defaultUser && (defaultUser = true);
                    }
                    return standable(type) && standIns.add(type);
                }
                if (message.contains("authenticationManager cannot be null")
                        || message.contains("userDetailsService cannot be null")
                        || message.contains("No UserDetailsService registered")) {
                    return !defaultUser && (defaultUser = true);
                }
                // The XML namespace's checks ask for the global <authentication-manager> a fixture about something
                // else leaves out.
                if (cause instanceof NoSuchBeanDefinitionException missing
                        && XML_AUTHENTICATION_MANAGER.equals(missing.getBeanName())) {
                    return !xmlAuthenticationManager && (xmlAuthenticationManager = true);
                }
                if (cause instanceof PlaceholderResolutionException unresolved
                        && WHERE.matcher(unresolved.getPlaceholder()).matches()) {
                    String name = unresolved.getPlaceholder().toLowerCase(Locale.ROOT);
                    return properties.putIfAbsent(unresolved.getPlaceholder(), name.endsWith("path") ? "/conformance"
                            : name.endsWith("url") || name.endsWith("uri") ? "http://localhost:1"
                            : name.endsWith("port") ? "0" : "conformance") == null;
                }
                // Spring gRPC served through the servlet container asks for server.http2.enabled, which a
                // container would have set.
                Matcher required = REQUIRED.matcher(message);
                if (required.find()) {
                    return properties.putIfAbsent(required.group(1), "true") == null;
                }
            }
            return false;
        }

        /**
         * The auto-configuration of a library the message names and the fixture doesn't use.
         */
        private Optional<List<String>> unusedLibrary(String message) {
            for (Map.Entry<List<String>, List<String>> library : LIBRARIES.entrySet()) {
                if (library.getKey().stream().anyMatch(message::contains) && !references(fixture, library.getKey()
                        .stream().map(name -> name.replace('.', '/')).toList())) {
                    return Optional.of(library.getValue());
                }
            }
            return Optional.empty();
        }

        /**
         * Whether a class of the fixture's package names a type in one of the packages ({@code a/b/}, as class files
         * write them).
         */
        private static boolean references(String fixture, List<String> packages) {
            try {
                Enumeration<URL> roots = FixtureApps.class.getClassLoader().getResources("fixtures/" + fixture);
                while (roots.hasMoreElements()) {
                    URL root = roots.nextElement();
                    if (!root.getProtocol().equals("file")) {
                        continue;
                    }
                    try (Stream<Path> files = Files.walk(Path.of(root.toURI()))) {
                        for (Path file : files.filter(f -> f.toString().endsWith(".class")).toList()) {
                            String bytes = new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1);
                            if (packages.stream().anyMatch(bytes::contains)) {
                                return true;
                            }
                        }
                    }
                }
                return false;
            } catch (IOException | URISyntaxException e) {
                throw new IllegalStateException(e);
            }
        }

        private static Throwable root(Throwable thrown) {
            Throwable root = thrown;
            while (root.getCause() != null && root.getCause() != root) {
                root = root.getCause();
            }
            return root;
        }

        private static boolean standable(Class<?> type) {
            return !type.isPrimitive() && !type.isArray() && !Modifier.isFinal(type.getModifiers())
                    && (CALLS_OUT.contains(type.getName()) || DECIDING.stream().noneMatch(type.getName()::startsWith));
        }

        @SuppressWarnings({"unchecked", "rawtypes"})
        void apply(SpringApplication application, ClassLoader loader) {
            application.addInitializers(context -> {
                GenericApplicationContext registry = (GenericApplicationContext) context;
                stored.clear();
                if (store) {
                    registry.registerBean(STORE, StandInStore.class, () -> new StandInStore(fixture, stored));
                }
                for (Class<?> type : standIns) {
                    registerStandIn(registry, type, loader);
                }
                if (executorFirst) {
                    registry.addBeanFactoryPostProcessor(beanFactory -> {
                        if (registry.containsBeanDefinition(EXECUTOR)) {
                            registry.getBeanDefinition(EXECUTOR).setPrimary(true);
                        }
                    });
                }
                if (!replaced.isEmpty()) {
                    // After the configuration classes and auto-configuration have defined their beans.
                    registry.addBeanFactoryPostProcessor(beanFactory -> replaced.forEach((name, type) -> {
                        if (registry.containsBeanDefinition(name)) {
                            registry.removeBeanDefinition(name);
                        }
                        registry.registerBean(name, (Class) type, () -> standIn(type, loader));
                    }));
                }
                if (xmlAuthenticationManager) {
                    UserDetails user = User.withUsername("user").password("{noop}" + UUID.randomUUID()).build();
                    registry.registerBean(XML_AUTHENTICATION_MANAGER, AuthenticationManager.class,
                            () -> new ProviderManager(new DaoAuthenticationProvider(
                                    new InMemoryUserDetailsManager(user))));
                }
                if (defaultUser) {
                    UserDetails user = User.withUsername("user").password("{noop}" + UUID.randomUUID()).build();
                    if (context instanceof WebApplicationContext) {
                        registry.registerBean("conformanceDefaultUser", UserDetailsService.class,
                                () -> new InMemoryUserDetailsManager(user));
                    } else {
                        registry.registerBean("conformanceDefaultUser", ReactiveUserDetailsService.class,
                                () -> new MapReactiveUserDetailsService(user));
                    }
                }
            });
        }

        @SuppressWarnings({"unchecked", "rawtypes"})
        private static void registerStandIn(GenericApplicationContext registry, Class<?> type, ClassLoader loader) {
            registry.registerBean("conformanceStandIn" + type.getSimpleName(), (Class) type,
                    () -> standIn(type, loader));
        }

        void addArguments(List<String> args) {
            properties.forEach((name, value) -> args.add("--" + name + "=" + value));
        }

        /**
         * For the report: what was filled in besides the auto-configuration left out.
         */
        String describe() {
            List<String> filled = new ArrayList<>();
            standIns.forEach(type -> filled.add(type.getSimpleName()));
            replaced.forEach((name, type) -> filled.add(type.getSimpleName() + " " + name));
            if (defaultUser) {
                filled.add("Boot's default user");
            }
            if (xmlAuthenticationManager) {
                filled.add("a global <authentication-manager> with Boot's default user");
            }
            if (executorFirst) {
                filled.add("Boot's executor before the shared classpath's scheduler");
            }
            properties.keySet().forEach(name -> filled.add(name));
            return (stored.isEmpty() ? "" : ", with Spring Data's map store for " + String.join(", ", stored))
                    + (filled.isEmpty() ? "" : ", with stand-ins for " + String.join(", ", filled));
        }
    }

    /**
     * A bean that does nothing: each method answers an empty value, itself when it returns its own type (a builder),
     * or a stand-in for what it returns.
     */
    private static Object standIn(Class<?> type, ClassLoader loader) {
        ProxyFactory factory = new ProxyFactory();
        if (type.isInterface()) {
            factory.addInterface(type);
        } else {
            factory.setTargetClass(type);
            factory.setProxyTargetClass(true);
        }
        factory.addAdvice((MethodInterceptor) invocation -> {
            Class<?> returned = invocation.getMethod().getReturnType();
            if (returned.isInstance(((ProxyMethodInvocation) invocation).getProxy())) {
                return ((ProxyMethodInvocation) invocation).getProxy();
            }
            return empty(returned, loader);
        });
        // In the loader that defined the type: a package-private interface can only be proxied there.
        return factory.getProxy(type.getClassLoader() != null ? type.getClassLoader() : loader);
    }

    /**
     * An empty value of the type: nothing, zero, an empty collection or stream, or a stand-in.
     */
    static Object empty(Class<?> type, ClassLoader loader) {
        if (type == void.class) {
            return null;
        }
        if (type.isPrimitive()) {
            return type == boolean.class ? Boolean.FALSE : type == char.class ? Character.valueOf('\0')
                    : type == long.class ? Long.valueOf(0) : type == double.class ? Double.valueOf(0)
                    : type == float.class ? Float.valueOf(0) : type == short.class ? Short.valueOf((short) 0)
                    : type == byte.class ? Byte.valueOf((byte) 0) : Integer.valueOf(0);
        }
        if (type.isArray()) {
            return Array.newInstance(type.getComponentType(), 0);
        }
        if (type == String.class) {
            return "";
        }
        if (type == Optional.class) {
            return Optional.empty();
        }
        if (type.isAssignableFrom(List.class)) {
            return List.of();
        }
        if (type.isAssignableFrom(Set.class)) {
            return Set.of();
        }
        if (type.isAssignableFrom(Map.class)) {
            return Map.of();
        }
        if (type == Stream.class) {
            return Stream.empty();
        }
        if (type == Mono.class) {
            return Mono.empty();
        }
        if (type == Flux.class) {
            return Flux.empty();
        }
        return Gaps.standable(type) && !type.getName().startsWith("java.") ? standIn(type, loader) : null;
    }

    private static List<String> autoConfigurations() {
        if (autoConfigurations == null) {
            List<String> names = new ArrayList<>();
            ImportCandidates.load(AutoConfiguration.class, FixtureApps.class.getClassLoader()).forEach(names::add);
            autoConfigurations = names;
        }
        return autoConfigurations;
    }

    private static String failingAutoConfiguration(Throwable thrown) {
        List<String> autoConfigurations = autoConfigurations();
        for (Throwable cause = thrown; cause != null; cause = cause.getCause()) {
            Matcher matcher = FAILED_CONDITION.matcher(String.valueOf(cause.getMessage()));
            while (matcher.find()) {
                // a.b.SomeAutoConfiguration, its $Nested class or its .someBean method: the auto-configuration
                String found = matcher.group(1) != null ? matcher.group(1) : matcher.group(2).replace('/', '.');
                for (String name = found.replaceAll("\\$.*", ""); name.contains(".");
                        name = name.substring(0, name.lastIndexOf('.'))) {
                    if (autoConfigurations.contains(name)) {
                        return name;
                    }
                }
            }
        }
        return null;
    }

    private static ConfigurableApplicationContext boot(Options options, Gaps gaps) throws Exception {
        ClassLoader parent = FixtureApps.class.getClassLoader();
        // The fixture's resources sit under its own directory; its META-INF/spring.factories must be at a root.
        ClassLoader loader = Files.isDirectory(options.resources())
                ? new URLClassLoader(new URL[] {options.resources().toUri().toURL()}, parent) : parent;
        Consumer<SpringApplication> setUp = application -> {
            application.setResourceLoader(new DefaultResourceLoader(loader));
            application.setApplicationContextFactory(type -> type == WebApplicationType.REACTIVE
                    ? new GenericReactiveWebApplicationContext()
                    : new GenericWebApplicationContext(new MockServletContext()));
            if (options.hosted()) {
                application.addInitializers(context -> {
                    BeanDefinitionRegistry registry = (BeanDefinitionRegistry) context;
                    new ClassPathBeanDefinitionScanner(registry).scan("fixtures." + options.fixture());
                    XmlBeanDefinitionReader reader = new XmlBeanDefinitionReader(registry);
                    options.xml().forEach(file -> reader.loadBeanDefinitions(new FileSystemResource(file)));
                });
            }
            if (options.noSecurity()) {
                // A chain that matches nothing keeps Boot's default chains out and secures nothing.
                application.addInitializers(context -> {
                    if (context instanceof GenericWebApplicationContext servlet) {
                        servlet.registerBean("conformanceNoSecurity", SecurityFilterChain.class,
                                () -> new DefaultSecurityFilterChain(request -> false));
                    } else {
                        ((GenericApplicationContext) context).registerBean("conformanceNoSecurity",
                                SecurityWebFilterChain.class, () -> new MatcherSecurityWebFilterChain(
                                        exchange -> ServerWebExchangeMatcher.MatchResult.notMatch(),
                                        List.of((exchange, chain) -> chain.filter(exchange))));
                    }
                });
            }
            // Spring Cloud Stream's Kafka binder looks its topic up as a send binds, with no broker to answer: once.
            application.addInitializers(context -> context.getBeanFactory().addBeanPostProcessor(
                    new BeanPostProcessor() {

                        @Override
                        public Object postProcessBeforeInitialization(Object bean, String name) {
                            if (bean instanceof KafkaTopicProvisioner provisioner) {
                                provisioner.setMetadataRetryOperations(
                                        new RetryTemplate(RetryPolicy.builder().maxRetries(0).build()));
                            }
                            return bean;
                        }
                    }));
            // Each context is closed when its probes are done; one that never finished starting must not hold up
            // the JVM's exit.
            application.setRegisterShutdownHook(false);
            gaps.apply(application, loader);
        };
        Method main = options.hosted() ? null : mainMethod(options.source());
        List<String> args = new ArrayList<>(List.of(
                "--spring.config.location=optional:file:" + options.resources().toAbsolutePath() + "/",
                "--spring.main.banner-mode=off",
                "--logging.level.root=ERROR",
                "--spring.jmx.enabled=false",
                "--spring.kafka.listener.auto-startup=false",
                "--spring.rabbitmq.listener.simple.auto-startup=false",
                "--spring.rabbitmq.listener.direct.auto-startup=false",
                // Spring Cloud Stream's Kafka binder asks a broker about its topics as it binds: no function is
                // bound at startup, and a send (StreamBridge binds on the first) gives up soon.
                "--spring.cloud.function.definition=",
                "--spring.cloud.stream.function.autodetect=false",
                "--spring.cloud.stream.kafka.binder.auto-create-topics=false",
                "--spring.cloud.stream.kafka.binder.producer-properties.max.block.ms=100",
                // A KafkaTemplate's send would wait a minute for the broker that isn't there, for each caller let in.
                "--spring.kafka.producer.properties.max.block.ms=100",
                "--spring.cloud.stream.kafka.binder.configuration.default.api.timeout.ms=100",
                "--spring.cloud.stream.kafka.binder.configuration.request.timeout.ms=100",
                "--spring.grpc.server.port=0",
                "--eureka.client.enabled=false",
                "--springdoc.enable-data-rest=false",
                "--springdoc.enable-hateoas=false",
                "--spring.cloud.compatibility-verifier.enabled=false",
                "--spring.autoconfigure.exclude=" + String.join(",", gaps.excluded)));
        gaps.addArguments(args);
        Thread[] booting = new Thread[1];
        ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "boot-" + options.fixture());
            thread.setDaemon(true);
            booting[0] = thread;
            return thread;
        });
        Future<ConfigurableApplicationContext> booted = executor.submit(() -> {
            Thread.currentThread().setContextClassLoader(loader);
            String[] arguments = args.toArray(String[]::new);
            if (main != null) {
                return runMain(main, setUp, arguments);
            }
            SpringApplication application = new SpringApplication(options.source());
            setUp.accept(application);
            return application.run(arguments);
        });
        try {
            return booted.get(BOOT_SECONDS, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            throw e.getCause() instanceof Exception cause ? cause : e;
        } catch (TimeoutException e) {
            String waiting = waitingIn(booting[0]);
            booted.cancel(true);
            throw new NotBooted("boot took longer than " + BOOT_SECONDS + " s" + waiting);
        } finally {
            executor.shutdown();
        }
    }

    /**
     * Where a boot that takes too long is waiting: the first frames outside the JDK, for the report.
     */
    private static String waitingIn(Thread thread) {
        List<String> frames = new ArrayList<>();
        for (StackTraceElement frame : thread == null ? new StackTraceElement[0] : thread.getStackTrace()) {
            if (!frame.getClassName().matches("(java|javax|jdk|sun)\\..*") && frames.size() < 3) {
                frames.add(frame.getClassName().replaceAll(".*\\.", "") + "." + frame.getMethodName());
            }
        }
        return frames.isEmpty() ? "" : ", waiting in " + String.join(" < ", frames);
    }

    private static Method mainMethod(Class<?> application) {
        try {
            Method main = application.getDeclaredMethod("main", String[].class);
            if (!Modifier.isStatic(main.getModifiers())) {
                return null;
            }
            // The fixtures' application classes are often package-private.
            main.setAccessible(true);
            return main;
        } catch (NoSuchMethodException e) {
            return null;
        }
    }

    /**
     * Starts the application as its main method does, so what that sets on its {@code SpringApplication} (the web
     * application type, say, which the scanner reads too) applies: the first {@code SpringApplication} it runs gets
     * the harness's set-up on top, and its context is the one probed.
     */
    private static ConfigurableApplicationContext runMain(Method main, Consumer<SpringApplication> setUp,
            String[] args) {
        AtomicReference<ConfigurableApplicationContext> started = new AtomicReference<>();
        AtomicBoolean first = new AtomicBoolean(true);
        SpringApplication.withHook(application -> {
            if (!first.getAndSet(false)) {
                return null;
            }
            setUp.accept(application);
            return new SpringApplicationRunListener() {

                @Override
                public void started(ConfigurableApplicationContext context, Duration timeTaken) {
                    started.set(context);
                }
            };
        }, () -> {
            try {
                return main.invoke(null, (Object) args);
            } catch (InvocationTargetException e) {
                throw e.getCause() instanceof Exception cause ? cause : e;
            }
        });
        if (started.get() == null) {
            throw new IllegalStateException(main.getDeclaringClass().getSimpleName()
                    + ".main returned without starting an application");
        }
        return started.get();
    }

    private static Class<?> applicationClass(String fixture) {
        ClassPathScanningCandidateComponentProvider scanner = new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AnnotationTypeFilter(EnableAutoConfiguration.class));
        for (BeanDefinition candidate : scanner.findCandidateComponents("fixtures." + fixture)) {
            try {
                return Class.forName(candidate.getBeanClassName());
            } catch (ClassNotFoundException ignored) {
                // Listed by the scan, so it is there.
            }
        }
        return null;
    }

    private static boolean annotated(String fixture, Class<? extends java.lang.annotation.Annotation> annotation) {
        ClassPathScanningCandidateComponentProvider scanner = new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AnnotationTypeFilter(annotation));
        return !scanner.findCandidateComponents("fixtures." + fixture).isEmpty();
    }

    /**
     * Whether every chain is one of Boot's own defaults (the application's would be declared outside Boot).
     */
    private static boolean onlyBootsDefaultChains(ConfigurableApplicationContext context, Class<?> chainType) {
        ConfigurableListableBeanFactory factory = context.getBeanFactory();
        String[] chains = factory.getBeanNamesForType(chainType);
        if (chains.length == 0) {
            return false;
        }
        for (String chain : chains) {
            BeanDefinition definition = factory.getMergedBeanDefinition(chain);
            String declaredBy = definition.getFactoryBeanName() != null
                    ? factory.getMergedBeanDefinition(definition.getFactoryBeanName()).getBeanClassName()
                    : definition.getBeanClassName();
            if (declaredBy == null || !declaredBy.startsWith("org.springframework.boot.")) {
                return false;
            }
        }
        return true;
    }

    /**
     * The Spring XML files (a {@code beans} root in Spring's beans namespace) under the fixture's resources.
     */
    private static List<File> xmlConfiguration(Path resources) throws NotBooted {
        if (!Files.isDirectory(resources)) {
            return List.of();
        }
        try (Stream<Path> walk = Files.walk(resources, 6)) {
            List<File> files = new ArrayList<>();
            for (Path file : walk.filter(path -> path.toString().endsWith(".xml")).sorted().toList()) {
                var factory = DocumentBuilderFactory.newInstance();
                factory.setNamespaceAware(true);
                Element root = factory.newDocumentBuilder().parse(file.toFile()).getDocumentElement();
                if ("beans".equals(root.getLocalName()) && BEANS_NAMESPACE.equals(root.getNamespaceURI())) {
                    files.add(file.toFile());
                }
            }
            return files;
        } catch (Exception e) {
            throw new NotBooted("XML configuration unreadable: " + Clients.root(e));
        }
    }
}
