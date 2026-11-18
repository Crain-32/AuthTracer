package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SecurityXmlTests {

    private static final String HEADER = """
            <b:beans xmlns="http://www.springframework.org/schema/security"
                     xmlns:b="http://www.springframework.org/schema/beans">
            """;

    @TempDir
    Path resources;

    @Test
    void anExpressionHandlerGivenAPermissionEvaluator() throws IOException {
        Files.writeString(resources.resolve("security.xml"), HEADER + """
                <method-security><expression-handler ref="handler"/></method-security>
                <b:bean id="handler"
                        class="org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler">
                    <b:property name="permissionEvaluator" ref="evaluator"/>
                </b:bean>
                </b:beans>
                """);
        assertThat(SecurityXml.load(List.of(resources)).methodSecurity()).hasValueSatisfying(config ->
                assertThat(config.permissionEvaluator()).isTrue());
    }

    @Test
    void withoutOneHasPermissionDenies() throws IOException {
        Files.writeString(resources.resolve("security.xml"), HEADER + """
                <method-security><expression-handler ref="handler"/></method-security>
                <b:bean id="handler"
                        class="org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler"/>
                </b:beans>
                """);
        assertThat(SecurityXml.load(List.of(resources)).methodSecurity()).hasValueSatisfying(config ->
                assertThat(config.permissionEvaluator()).isFalse());
        Files.writeString(resources.resolve("security.xml"), HEADER + "<global-method-security/></b:beans>");
        assertThat(SecurityXml.load(List.of(resources)).methodSecurity()).hasValueSatisfying(config ->
                assertThat(config.permissionEvaluator()).isFalse());
    }

    @Test
    void anExpressionHandlerDefinedElsewhereOrTheApplicationsOwnCanEvaluate() throws IOException {
        Files.writeString(resources.resolve("security.xml"), HEADER + """
                <method-security><expression-handler ref="javaConfigured"/></method-security>
                </b:beans>
                """);
        assertThat(SecurityXml.load(List.of(resources)).methodSecurity()).hasValueSatisfying(config ->
                assertThat(config.permissionEvaluator()).isTrue());
        Files.writeString(resources.resolve("security.xml"), HEADER + """
                <method-security><expression-handler ref="handler"/></method-security>
                <b:bean id="handler" class="com.acme.security.TenantExpressionHandler"/>
                </b:beans>
                """);
        assertThat(SecurityXml.load(List.of(resources)).methodSecurity()).hasValueSatisfying(config ->
                assertThat(config.permissionEvaluator()).isTrue());
    }

    @Test
    void eachMethodSecurityElementSaysWhichAnnotationsAreRead() throws IOException {
        Files.writeString(resources.resolve("security.xml"), HEADER + """
                <method-security pre-post-enabled="false" secured-enabled="true" jsr250-enabled="true"/>
                </b:beans>
                """);
        assertThat(SecurityXml.load(List.of(resources)).methodSecurity())
                .contains(new SecurityXml.MethodSecurityConfig(false, true, true));
        Files.writeString(resources.resolve("security.xml"), HEADER + """
                <global-method-security pre-post-annotations="enabled" secured-annotations="enabled"
                        jsr250-annotations="disabled"/>
                </b:beans>
                """);
        assertThat(SecurityXml.load(List.of(resources)).methodSecurity())
                .contains(new SecurityXml.MethodSecurityConfig(true, true, false));
    }

    @Test
    void anInterceptUrlWithoutAccessNeedsAnAuthenticatedCaller() throws IOException {
        Files.writeString(resources.resolve("security.xml"), HEADER + """
                <http request-matcher="regex">
                    <intercept-url pattern="/static/.*" filters="none"/>
                    <intercept-url pattern="/admin/.*" method="POST" access="hasRole('ADMIN')"/>
                    <intercept-url pattern="/.*"/>
                </http>
                <!-- A custom FilterSecurityInterceptor's rules: not a chain of their own. -->
                <filter-security-metadata-source id="legacy">
                    <intercept-url pattern="/legacy/**" access="ROLE_LEGACY"/>
                </filter-security-metadata-source>
                </b:beans>
                """);

        SecurityXml.Config config = SecurityXml.load(List.of(resources));

        assertThat(config.chains()).singleElement().satisfies(chain -> {
            assertThat(chain.regex()).isTrue();
            assertThat(chain.rules()).extracting(SecurityXml.InterceptUrl::pattern, SecurityXml.InterceptUrl::method,
                    SecurityXml.InterceptUrl::access).containsExactly(
                            tuple("/static/.*", null, "permitAll"),
                            tuple("/admin/.*", "POST", "hasRole('ADMIN')"),
                            tuple("/.*", null, "authenticated"));
        });
    }

    @Test
    void aJspViewResolverBeanSaysWhereTheViewsAre() throws IOException {
        Files.writeString(resources.resolve("mvc.xml"), """
                <beans xmlns="http://www.springframework.org/schema/beans">
                    <bean id="viewResolver" class="org.springframework.web.servlet.view.InternalResourceViewResolver">
                        <property name="viewClass" ref="jstlView"/>
                        <property name="prefix" value="/WEB-INF/views/"/>
                        <property name="suffix" value=".jsp"/>
                        <property name="order" value="1"/>
                    </bean>
                    <bean id="child" parent="viewResolver"/>
                </beans>
                """);

        SecurityXml.Config config = SecurityXml.load(List.of(resources));

        assertThat(config.viewResolver()).contains(new SecurityXml.ViewResolver("/WEB-INF/views/", ".jsp"));
        assertThat(config.beans()).containsExactly("org.springframework.web.servlet.view.InternalResourceViewResolver");
        assertThat(config.chains()).isEmpty();
    }

    @Test
    void mvcJspIsUnderWebInfUnlessItSaysOtherwise() throws IOException {
        Files.writeString(resources.resolve("mvc.xml"), """
                <beans xmlns="http://www.springframework.org/schema/beans"
                       xmlns:mvc="http://www.springframework.org/schema/mvc">
                    <mvc:annotation-driven/>
                    <mvc:view-resolvers><mvc:jsp/></mvc:view-resolvers>
                </beans>
                """);
        assertThat(SecurityXml.load(List.of(resources)).viewResolver())
                .contains(new SecurityXml.ViewResolver("/WEB-INF/", ".jsp"));
        Files.writeString(resources.resolve("mvc.xml"), """
                <beans xmlns="http://www.springframework.org/schema/beans"
                       xmlns:mvc="http://www.springframework.org/schema/mvc">
                    <mvc:view-resolvers><mvc:jsp prefix="/WEB-INF/pages/" suffix=".jspx"/></mvc:view-resolvers>
                </beans>
                """);
        assertThat(SecurityXml.load(List.of(resources)).viewResolver())
                .contains(new SecurityXml.ViewResolver("/WEB-INF/pages/", ".jspx"));
    }

    @Test
    void otherXmlFilesBrokenOnesAndMissingDirectoriesAreSkipped() throws IOException {
        Files.writeString(resources.resolve("logback.xml"), """
                <configuration><appender name="console" class="ch.qos.logback.core.ConsoleAppender"/></configuration>
                """);
        // Cut short mid-edit, and an old DTD, which the parser refuses rather than resolving.
        Files.writeString(resources.resolve("broken.xml"), HEADER + "<http pattern=\"/broken/**\">");
        Files.writeString(resources.resolve("legacy.xml"), """
                <!DOCTYPE beans SYSTEM "https://www.springframework.org/dtd/spring-beans-2.0.dtd">
                """ + HEADER + "<http pattern=\"/legacy/**\"/></b:beans>");
        Files.writeString(resources.resolve("security.xml"), HEADER + "<http pattern=\"/api/**\"/></b:beans>");

        SecurityXml.Config config = SecurityXml.load(List.of(resources.resolve("missing"), resources));

        assertThat(config.chains()).extracting(SecurityXml.Http::pattern).containsExactly("/api/**");
        assertThat(config.beans()).isEmpty();
    }

    @Test
    void aFileInTheEncodingItDeclaresIsRead() throws IOException {
        Files.writeString(resources.resolve("security.xml"), """
                <?xml version="1.0" encoding="ISO-8859-1"?>
                <!-- Zugriff für Administratoren -->
                """ + HEADER + """
                <http pattern="/admin/**">
                    <intercept-url pattern="/admin/**" access="hasRole('ADMIN')"/>
                </http>
                </b:beans>
                """, StandardCharsets.ISO_8859_1);

        SecurityXml.Config config = SecurityXml.load(List.of(resources));

        assertThat(config.chains()).singleElement().satisfies(chain -> {
            assertThat(chain.pattern()).isEqualTo("/admin/**");
            assertThat(chain.rules()).extracting(SecurityXml.InterceptUrl::access).containsExactly("hasRole('ADMIN')");
        });
    }

    @Test
    void aSecurityFileThatDoesntParseIsListedAndABeansFileIsNot() throws IOException {
        Files.writeString(resources.resolve("security.xml"), HEADER + "<http pattern=\"/broken/**\">");
        Files.writeString(resources.resolve("beans.xml"), """
                <beans xmlns="http://www.springframework.org/schema/beans"><bean class="a.B">
                """);

        assertThat(SecurityXml.load(List.of(resources)).unread()).containsExactly("security.xml");
    }

    @Test
    void theBeanReferencesAndTheLegacyAttributesOfAChain() throws IOException {
        Files.writeString(resources.resolve("security.xml"), HEADER + """
                <http request-matcher-ref="partners" use-authorization-manager="false" use-expressions="false">
                    <intercept-url request-matcher-ref="exports" access="ROLE_A"/>
                    <intercept-url method="GET"/>
                </http>
                <http authorization-manager-ref="tenants" use-authorization-manager="false"/>
                <b:bean id="exports" class="org.springframework.security.web.util.matcher.RegexRequestMatcher">
                    <b:constructor-arg value="/export/.*"/>
                    <b:constructor-arg ref="method"/>
                </b:bean>
                <b:constructor-arg value="outside a bean"/>
                </b:beans>
                """);

        SecurityXml.Config config = SecurityXml.load(List.of(resources));

        assertThat(config.chains()).hasSize(2);
        SecurityXml.Http partners = config.chains().getFirst();
        assertThat(partners.matcherRef()).isEqualTo("partners");
        assertThat(partners.legacy()).isTrue();
        assertThat(partners.expressions()).isFalse();
        // An intercept-url with neither a pattern nor a matcher isn't a rule.
        assertThat(partners.rules()).singleElement().satisfies(rule -> assertThat(rule.matcherRef())
                .isEqualTo("exports"));
        // A manager bean is an AuthorizationFilter's, whatever use-authorization-manager says.
        assertThat(config.chains().getLast().managerRef()).isEqualTo("tenants");
        assertThat(config.chains().getLast().legacy()).isFalse();
        assertThat(config.beansById().get("exports").arguments()).containsExactly("/export/.*", null);
    }

    @Test
    void theMethodChecksAndMessageRulesWithoutAnnotations() throws IOException {
        Files.writeString(resources.resolve("security.xml"), HEADER + """
                <protect-pointcut expression="execution(* *(..))" access="denyAll"/>
                <intercept-message pattern="/outside/**" access="denyAll"/>
                <global-method-security>
                    <protect-pointcut expression="execution(* a.B.*(..))" access="ROLE_A"/>
                    <protect-pointcut access="ROLE_B"/>
                </global-method-security>
                <b:bean id="reports" class="a.Reports">
                    <intercept-methods authorization-manager-ref="manager" use-authorization-manager="false">
                        <protect method="find*" access="ROLE_C"/>
                        <protect access="ROLE_D"/>
                    </intercept-methods>
                </b:bean>
                <b:bean>
                    <intercept-methods><protect method="x" access="ROLE_E"/></intercept-methods>
                </b:bean>
                <protect method="outside" access="ROLE_F"/>
                <websocket-message-broker id="inbound" authorization-manager-ref="messages">
                    <intercept-message type="CONNECT" access="permitAll"/>
                    <expression-handler ref="handler"/>
                </websocket-message-broker>
                </b:beans>
                """);

        SecurityXml.Config config = SecurityXml.load(List.of(resources));

        assertThat(config.pointcuts()).singleElement().satisfies(pointcut -> {
            assertThat(pointcut.legacy()).isTrue();
            assertThat(pointcut.access()).isEqualTo("ROLE_A");
        });
        assertThat(config.interceptMethods()).singleElement().satisfies(methods -> {
            assertThat(methods.beanClass()).isEqualTo("a.Reports");
            assertThat(methods.managerRef()).isEqualTo("manager");
            assertThat(methods.legacy()).isFalse();
            assertThat(methods.protects()).extracting(SecurityXml.Protect::method).containsExactly("find*");
        });
        assertThat(config.messageBrokers()).singleElement().satisfies(broker -> {
            assertThat(broker.id()).isEqualTo("inbound");
            assertThat(broker.managerRef()).isEqualTo("messages");
            assertThat(broker.expressionHandler()).isEqualTo("handler");
            assertThat(broker.rules()).extracting(SecurityXml.InterceptMessage::type).containsExactly("CONNECT");
        });
    }

    @Test
    void theWebSocketNamespacesBroker() throws IOException {
        Files.writeString(resources.resolve("websocket.xml"), """
                <beans xmlns="http://www.springframework.org/schema/beans"
                       xmlns:websocket="http://www.springframework.org/schema/websocket">
                    <websocket:stomp-endpoint path="/before"/>
                    <websocket:client-inbound-channel><websocket:interceptors><ref bean="early"/>
                    </websocket:interceptors></websocket:client-inbound-channel>
                    <websocket:message-broker application-destination-prefix="/app, /api">
                        <websocket:stomp-endpoint path="/ws,/sockjs"/>
                        <websocket:client-inbound-channel>
                            <websocket:executor core-pool-size="2"/>
                            <websocket:interceptors>
                                <ref bean="inbound"/>
                                <bean class="a.Logging"/>
                            </websocket:interceptors>
                        </websocket:client-inbound-channel>
                        <websocket:client-outbound-channel>
                            <websocket:interceptors><ref bean="outbound"/></websocket:interceptors>
                        </websocket:client-outbound-channel>
                    </websocket:message-broker>
                </beans>
                """);

        assertThat(SecurityXml.load(List.of(resources)).stomp()).hasValueSatisfying(broker -> {
            assertThat(broker.prefixes()).containsExactly("/app", "/api");
            assertThat(broker.endpoints()).containsExactly("/ws", "/sockjs");
            assertThat(broker.inboundInterceptors()).containsExactly("inbound");
        });
    }
}
