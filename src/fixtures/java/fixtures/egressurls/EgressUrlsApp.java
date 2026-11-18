package fixtures.egressurls;

import java.net.URI;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import feign.auth.BasicAuthRequestInterceptor;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.annotation.XmlElementDecl;
import jakarta.xml.bind.annotation.XmlRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.restclient.RestTemplateBuilder;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.ws.client.core.WebServiceTemplate;

/**
 * The other ways applications write where a call goes: base URLs from {@code @ConfigurationProperties} (a record with
 * a {@code @DefaultValue}, nested JavaBeans with defaults, a class a {@code @Bean} method binds), {@code pathSegment},
 * a host given as a URI variable, URLs built with {@code StringBuilder} and {@code String.format}, HTTP interfaces a
 * generic helper creates, method references to HTTP interface and Feign methods, Feign's basic auth interceptor, a
 * {@code RequestEntity} made with {@code new}, and SOAP requests wrapped in a {@code JAXBElement}.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
class EgressUrlsApp {

    @Bean
    @ConfigurationProperties("clients.ledger")
    LedgerProperties ledgerProperties() {
        return new LedgerProperties();
    }

    @Bean
    WebServiceTemplate webServiceTemplate(LedgerProperties ledger) {
        WebServiceTemplate template = new WebServiceTemplate();
        template.setDefaultUri(ledger.getUri());
        return template;
    }
}

record Order(Long id) {
}

record Receipt(Long orderId) {
}

@ConfigurationProperties("clients.orders")
record OrdersProperties(String baseUrl, @DefaultValue("http://localhost:8070") String fallbackUrl) {
}

@ConfigurationProperties("clients")
class ClientsProperties {

    private final Service payments = new Service();

    private final Service inventory = new Service();

    public Service getPayments() {
        return payments;
    }

    public Service getInventory() {
        return inventory;
    }

    public static class Service {

        private String url = "http://localhost:8099";

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }
    }
}

/**
 * Bound by the {@code @Bean} method that creates it.
 */
class LedgerProperties {

    private String uri;

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }
}

@Component
class OrdersClient {

    private final RestClient client;

    private final RestClient fallback;

    OrdersClient(RestClient.Builder builder, OrdersProperties orders) {
        this.client = builder.clone().baseUrl(orders.baseUrl()).build();
        this.fallback = RestClient.create(orders.fallbackUrl());
    }

    Order order(long id) {
        return client.get().uri("/orders/{id}", id).retrieve().body(Order.class);
    }

    Order fallbackOrder(long id) {
        return fallback.get().uri("/orders/{id}", id).retrieve().body(Order.class);
    }

    Order lines(long id) {
        return client.get().uri(builder -> builder.pathSegment("orders", String.valueOf(id), "lines").build())
                .retrieve().body(Order.class);
    }
}

@Component
class PaymentsClient {

    private final RestTemplate template;

    PaymentsClient(RestTemplateBuilder builder, ClientsProperties clients) {
        this.template = builder.rootUri(clients.getPayments().getUrl()).build();
    }

    String payment(long id) {
        return template.getForObject("/payments/{id}", String.class, id);
    }
}

@Component
class InventoryClient {

    private final RestTemplate rest = new RestTemplate();

    private final ClientsProperties clients;

    InventoryClient(ClientsProperties clients) {
        this.clients = clients;
    }

    String stock(String sku) {
        return rest.getForObject(clients.getInventory().getUrl() + "/stock/" + sku, String.class);
    }
}

@Component
class UrlForms {

    private final RestTemplate rest = new RestTemplate();

    @Value("${orders.host}")
    private String ordersHost;

    @Value("${gateway.url}")
    private String gatewayUrl;

    private String ordersUrl = "http://orders:8080";

    String segments(long id) {
        URI uri = UriComponentsBuilder.fromUriString("http://orders:8080")
                .pathSegment("orders", String.valueOf(id), "lines").build().toUri();
        return rest.getForObject(uri, String.class);
    }

    String byHost(long id) {
        return rest.getForObject("http://{host}:8080/orders/{id}", String.class, ordersHost, id);
    }

    String viaGateway(long id) {
        return rest.getForObject("{gateway}/orders/{id}", String.class, gatewayUrl, id);
    }

    String byNamedHost(long id) {
        return rest.getForObject("http://{host}:8080/orders/{id}/notes", String.class,
                Map.of("host", ordersHost, "id", id));
    }

    String anyHost(String host, long id) {
        return rest.getForObject("http://{host}:8080/orders/{id}/audit", String.class, host, id);
    }

    String built(long id) {
        return rest.getForObject(new StringBuilder(ordersUrl).append("/orders/").append(id).append('/')
                .append("history").toString(), String.class);
    }

    String appended(long id) {
        StringBuilder url = new StringBuilder();
        url.append(ordersUrl);
        url.append("/orders/");
        url.append(id);
        url.append("/status");
        return rest.getForObject(url.toString(), String.class);
    }

    String formatted(long id) {
        return rest.getForObject(String.format("%s/orders/%d/items", ordersUrl, id), String.class);
    }

    String formattedText(long id) {
        return rest.getForObject("%s/orders/%d/totals".formatted(ordersUrl, id), String.class);
    }

    String indexed(long id) {
        return rest.getForObject(String.format("%1$s/orders/%2$d/refunds?rate=5%%", ordersUrl, id), String.class);
    }

    Receipt create(Order order) {
        return rest.exchange(new RequestEntity<>(order, HttpMethod.POST, URI.create(ordersUrl + "/orders")),
                Receipt.class).getBody();
    }
}

interface StockApi {

    @GetExchange("/stock/{sku}")
    String stock(@PathVariable("sku") String sku);
}

interface PricesApi {

    @GetExchange("/prices/{sku}")
    String price(@PathVariable("sku") String sku);
}

@Configuration
class ApiClients {

    @Bean
    StockApi stockApi(RestClient.Builder builder) {
        return create(StockApi.class, builder, "http://stock:8080");
    }

    @Bean
    PricesApi pricesApi(RestClient.Builder builder, @Value("${prices.url}") String url) {
        return create(PricesApi.class, builder, url);
    }

    private static <T> T create(Class<T> type, RestClient.Builder builder, String baseUrl) {
        RestClient client = builder.clone().baseUrl(baseUrl).build();
        return HttpServiceProxyFactory.builderFor(RestClientAdapter.create(client)).build().createClient(type);
    }
}

@FeignClient(name = "catalog", url = "http://catalog:8085", configuration = CatalogFeignConfig.class)
interface CatalogClient {

    @GetMapping("/products/{id}")
    String product(@PathVariable("id") Long id);
}

class CatalogFeignConfig {

    @Bean
    BasicAuthRequestInterceptor catalogCredentials() {
        return new BasicAuthRequestInterceptor("catalog", "secret");
    }
}

/**
 * xjc's shape for elements whose types have no {@code @XmlRootElement}.
 */
class GetCountryRequest {
}

class GetCapitalRequest {
}

class GetBalanceRequest {
}

class GetRegionRequest {
}

@XmlRegistry
class ObjectFactory {

    private static final QName COUNTRY = new QName("http://example.com/countries", "getCountryRequest");

    @XmlElementDecl(namespace = "http://example.com/countries", name = "getCountryRequest")
    public JAXBElement<GetCountryRequest> createGetCountryRequest(GetCountryRequest value) {
        return new JAXBElement<>(COUNTRY, GetCountryRequest.class, null, value);
    }

    @XmlElementDecl(namespace = "http://example.com/ledger", name = "getBalanceRequest")
    public JAXBElement<GetBalanceRequest> createGetBalanceRequest(GetBalanceRequest value) {
        return new JAXBElement<>(new QName("http://example.com/ledger", "getBalanceRequest"),
                GetBalanceRequest.class, null, value);
    }
}

@Component
class SoapClients {

    private static final QName REGION = new QName("http://example.com/countries", "getRegionRequest");

    private final WebServiceTemplate template;

    SoapClients(WebServiceTemplate template) {
        this.template = template;
    }

    Object country(GetCountryRequest request) {
        return template.marshalSendAndReceive("http://countries:8080/ws",
                new ObjectFactory().createGetCountryRequest(request));
    }

    Object capital(GetCapitalRequest request) {
        return template.marshalSendAndReceive("http://countries:8080/ws", new JAXBElement<>(
                new QName("http://example.com/countries", "getCapitalRequest"), GetCapitalRequest.class, request));
    }

    Object balance(GetBalanceRequest request) {
        return template.marshalSendAndReceive(new ObjectFactory().createGetBalanceRequest(request));
    }

    Object region(GetRegionRequest request) {
        return template.marshalSendAndReceive("http://countries:8080/ws",
                new JAXBElement<>(REGION, GetRegionRequest.class, request));
    }
}

@RestController
class UrlsController {

    private final OrdersClient orders;
    private final PaymentsClient payments;
    private final InventoryClient inventory;
    private final UrlForms forms;
    private final StockApi stock;
    private final PricesApi prices;
    private final CatalogClient catalog;
    private final SoapClients soap;

    UrlsController(OrdersClient orders, PaymentsClient payments, InventoryClient inventory, UrlForms forms,
            StockApi stock, PricesApi prices, CatalogClient catalog, SoapClients soap) {
        this.orders = orders;
        this.payments = payments;
        this.inventory = inventory;
        this.forms = forms;
        this.stock = stock;
        this.prices = prices;
        this.catalog = catalog;
        this.soap = soap;
    }

    @GetMapping("/orders/{id}")
    Order order(@PathVariable("id") long id) {
        return orders.order(id) != null ? orders.lines(id) : orders.fallbackOrder(id);
    }

    @GetMapping("/payments/{id}")
    String payment(@PathVariable("id") long id) {
        return payments.payment(id);
    }

    @GetMapping("/stock/{sku}")
    String stock(@PathVariable("sku") String sku) {
        return inventory.stock(sku);
    }

    @GetMapping("/forms/{id}")
    String forms(@PathVariable("id") long id, @RequestParam String host) {
        return forms.segments(id) + forms.byHost(id) + forms.viaGateway(id) + forms.byNamedHost(id)
                + forms.anyHost(host, id) + forms.built(id) + forms.appended(id) + forms.formatted(id)
                + forms.formattedText(id) + forms.indexed(id);
    }

    @PostMapping("/orders")
    Receipt create(@RequestBody Order order) {
        return forms.create(order);
    }

    @GetMapping("/stock")
    List<String> stock(@RequestParam List<String> skus) {
        return skus.stream().map(stock::stock).toList();
    }

    @GetMapping("/prices")
    List<String> prices(@RequestParam List<String> skus) {
        return skus.stream().map(prices::price).toList();
    }

    @GetMapping("/products")
    List<String> products(@RequestParam List<Long> ids) {
        return ids.stream().map(catalog::product).toList();
    }

    @GetMapping("/countries")
    Object countries() {
        return soap.country(new GetCountryRequest()).toString() + soap.capital(new GetCapitalRequest())
                + soap.balance(new GetBalanceRequest()) + soap.region(new GetRegionRequest());
    }
}
