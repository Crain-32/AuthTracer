package fixtures.soapclient;

import jakarta.xml.bind.annotation.XmlRootElement;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.ws.client.core.support.WebServiceGatewaySupport;

/**
 * Decision 0056: a SOAP client, as Spring's guide writes one, calling the soap fixture's getCountryRequest; and a
 * second one, and a bean that isn't a client, each with its own default URI.
 */
@SpringBootApplication
class SoapClientApp {

    @Bean
    Feed feed() {
        Feed feed = new Feed();
        feed.setDefaultUri("http://feeds.example.com");
        return feed;
    }

    @Bean
    WeatherClient weatherClient() {
        WeatherClient client = new WeatherClient();
        client.setDefaultUri("http://localhost:9090/weather");
        return client;
    }

    @Bean
    CountryClient countryClient() {
        CountryClient client = new CountryClient();
        client.setDefaultUri("http://localhost:8080/ws");
        return client;
    }
}

@XmlRootElement(name = "getCountryRequest", namespace = "http://example.com/countries")
class GetCountryRequest {
}

class CountryClient extends WebServiceGatewaySupport {

    Object getCountry() {
        return getWebServiceTemplate().marshalSendAndReceive(new GetCountryRequest());
    }
}

class Feed {

    void setDefaultUri(String uri) {
    }
}

@XmlRootElement(name = "getWeatherRequest")
class GetWeatherRequest {
}

class WeatherClient extends WebServiceGatewaySupport {

    Object getWeather() {
        return getWebServiceTemplate().marshalSendAndReceive(new GetWeatherRequest());
    }
}

@RestController
class CountryController {

    private final CountryClient client;

    private final WeatherClient weather;

    CountryController(CountryClient client, WeatherClient weather) {
        this.client = client;
        this.weather = weather;
    }

    @GetMapping("/countries")
    Object countries() {
        return client.getCountry();
    }

    @GetMapping("/weather")
    Object weather() {
        return weather.getWeather();
    }
}
