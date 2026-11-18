package fixtures.soapactionclient;

import javax.xml.namespace.QName;

import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.ws.client.core.support.WebServiceGatewaySupport;
import org.springframework.ws.soap.addressing.client.ActionCallback;
import org.springframework.ws.soap.client.core.SoapActionCallback;

/**
 * Decision 0056: calls to the soapactions fixture: one naming its SOAP action beside a request whose element no
 * operation maps, one naming only its WS-Addressing action, and one whose element is in its package's namespace.
 */
@SpringBootApplication
class SoapActionClientApp {

    @Bean
    OrderClient orderClient() {
        OrderClient client = new OrderClient();
        client.setDefaultUri("http://localhost:8080/services");
        return client;
    }
}

@XmlRootElement
class CancelOrder {
}

class Status {
}

class OrderClient extends WebServiceGatewaySupport {

    Object cancel() {
        return getWebServiceTemplate().marshalSendAndReceive(new CancelOrder(),
                new SoapActionCallback("http://example.com/orders/Cancel"));
    }

    Object track(Object request) throws Exception {
        return getWebServiceTemplate().marshalSendAndReceive(request,
                new ActionCallback("http://example.com/orders/Track"));
    }

    Object status() {
        return getWebServiceTemplate().marshalSendAndReceive(new JAXBElement<>(
                new QName("http://example.com/orders", "statusRequest"), Status.class, new Status()));
    }
}

@RestController
class OrderController {

    private final OrderClient client;

    OrderController(OrderClient client) {
        this.client = client;
    }

    @GetMapping("/cancel")
    Object cancel() {
        return client.cancel();
    }

    @GetMapping("/track")
    Object track() throws Exception {
        return client.track(new Object());
    }

    @GetMapping("/status")
    Object status() {
        return client.status();
    }
}
