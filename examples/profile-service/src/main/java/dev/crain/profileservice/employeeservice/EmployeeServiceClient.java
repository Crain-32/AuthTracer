package dev.crain.profileservice.employeeservice;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * employee-service's REST API, for one employee's compensation; profiles come over GraphQL
 * ({@link EmployeeGraphQlClient}).
 */
@Component
public class EmployeeServiceClient {

    private final RestClient restClient;

    /**
     * Uses Boot's {@link RestClient.Builder} so outbound calls are traced.
     */
    public EmployeeServiceClient(RestClient.Builder builder, @Value("${employee-service.base-url}") String baseUrl) {
        this.restClient = builder.baseUrl(baseUrl).requestInterceptor(new BearerTokenRelayInterceptor()).build();
    }

    public EmployeeDto getEmployee(long id) {
        return restClient.get().uri("/employees/{id}", id).retrieve().body(EmployeeDto.class);
    }
}
