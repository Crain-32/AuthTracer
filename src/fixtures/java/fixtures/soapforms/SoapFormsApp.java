package fixtures.soapforms;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import jakarta.xml.bind.annotation.XmlRootElement;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.ws.client.core.WebServiceTemplate;
import org.springframework.ws.client.core.support.WebServiceGatewaySupport;

/**
 * Decision 0056, the other ways a SOAP call is made: a URI passed with the request, a {@code WebServiceTemplate}
 * bean with its default URI, a client whose default URI is a property and one whose URI is a configuration
 * properties getter's, a request element named by its class, a helper that sends whatever it is given, and XML sent
 * as it is.
 */
@SpringBootApplication
class SoapFormsApp {

    @Bean
    Jaxb2Marshaller marshaller() {
        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        marshaller.setPackagesToScan("fixtures.soapforms");
        return marshaller;
    }

    @Bean
    WebServiceTemplate webServiceTemplate(Jaxb2Marshaller marshaller) {
        WebServiceTemplate template = new WebServiceTemplate(marshaller);
        template.setDefaultUri("http://rates:8080/ws");
        return template;
    }

    @Bean
    HolidayClient holidayClient(Jaxb2Marshaller marshaller, @Value("${holidays.uri}") String uri) {
        HolidayClient client = new HolidayClient();
        client.setMarshaller(marshaller);
        client.setUnmarshaller(marshaller);
        client.setDefaultUri(uri);
        return client;
    }

    @Bean
    PaymentClient paymentClient(Jaxb2Marshaller marshaller, PaymentProperties properties) {
        PaymentClient client = new PaymentClient();
        client.setMarshaller(marshaller);
        client.setUnmarshaller(marshaller);
        client.setDefaultUri(properties.uri());
        return client;
    }
}

@ConfigurationProperties("payments")
record PaymentProperties(String uri) {
}

/**
 * JAXB names the element after the class: getQuoteRequest.
 */
@XmlRootElement
class GetQuoteRequest {
}

@XmlRootElement(name = "getRatesRequest")
class RatesRequest {
}

@Component
class MarketClient {

    private final WebServiceTemplate template;

    MarketClient(WebServiceTemplate template) {
        this.template = template;
    }

    Object quote() {
        return template.marshalSendAndReceive("http://quotes:8080/ws", new GetQuoteRequest());
    }

    Object rates() {
        return template.marshalSendAndReceive(new RatesRequest());
    }

    /**
     * Its callers choose the request: here it is any object.
     */
    Object send(Object request) {
        return template.marshalSendAndReceive(request);
    }

    /**
     * XML as it is, not a request object a marshaller names.
     */
    boolean raw() {
        return template.sendSourceAndReceiveToResult(new StreamSource(new StringReader("<getRatesRequest/>")),
                new StreamResult(new StringWriter()));
    }
}

@XmlRootElement(name = "getHolidaysRequest")
class HolidaysRequest {
}

class HolidayClient extends WebServiceGatewaySupport {

    Object holidays() {
        return getWebServiceTemplate().marshalSendAndReceive(new HolidaysRequest());
    }
}

@XmlRootElement(name = "getPaymentsRequest")
class PaymentsRequest {
}

class PaymentClient extends WebServiceGatewaySupport {

    Object payments() {
        return getWebServiceTemplate().marshalSendAndReceive(new PaymentsRequest());
    }
}

@RestController
class MarketController {

    private final MarketClient client;

    MarketController(MarketClient client) {
        this.client = client;
    }

    @GetMapping("/quote")
    Object quote() {
        return client.quote();
    }

    @GetMapping("/rates")
    Object rates() {
        return client.rates();
    }

    @GetMapping("/forward")
    Object forward() {
        return client.send(new RatesRequest());
    }

    @GetMapping("/raw")
    boolean raw() {
        return client.raw();
    }
}

@RestController
class HolidayController {

    private final HolidayClient client;

    HolidayController(HolidayClient client) {
        this.client = client;
    }

    @GetMapping("/holidays")
    Object holidays() {
        return client.holidays();
    }
}

@RestController
class PaymentController {

    private final PaymentClient client;

    PaymentController(PaymentClient client) {
        this.client = client;
    }

    @GetMapping("/payments")
    Object payments() {
        return client.payments();
    }
}
