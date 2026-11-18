package fixtures.clients;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
class TemplateCatalog {

    private final RestTemplate restTemplate = new RestTemplate();
    private final String baseUrl;

    TemplateCatalog(@Value("${catalog.base-url}") String baseUrl) {
        this.baseUrl = baseUrl;
    }

    Product product(String id) {
        return restTemplate.getForObject(baseUrl + "/catalog/products/" + id, Product.class);
    }

    void archive(String id) {
        restTemplate.exchange("http://archive:9090/archive/{id}", HttpMethod.PUT, HttpEntity.EMPTY, Void.class, id);
    }

    void touch(String id) {
        restTemplate.delete("/cache/{id}", id);
    }
}
