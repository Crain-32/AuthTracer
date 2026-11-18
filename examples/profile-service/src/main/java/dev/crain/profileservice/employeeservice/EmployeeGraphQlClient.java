package dev.crain.profileservice.employeeservice;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.graphql.client.HttpSyncGraphQlClient;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * employee-service's GraphQL API, for the fields a profile shows. The queries are in {@code graphql-documents/}.
 */
@Component
public class EmployeeGraphQlClient {

    private final HttpSyncGraphQlClient graphQl;

    /**
     * Over Boot's {@link RestClient.Builder}, so the calls are traced, relaying the caller's bearer token.
     */
    public EmployeeGraphQlClient(RestClient.Builder builder, @Value("${employee-service.base-url}") String baseUrl) {
        RestClient restClient = builder.requestInterceptor(new BearerTokenRelayInterceptor()).build();
        this.graphQl = HttpSyncGraphQlClient.builder(restClient).url(baseUrl + "/graphql").build();
    }

    public EmployeeDto employee(long id) {
        return graphQl.documentName("employee").variable("id", id).retrieveSync("employee").toEntity(EmployeeDto.class);
    }

    public List<EmployeeDto> employees() {
        return graphQl.documentName("employees").retrieveSync("employees").toEntityList(EmployeeDto.class);
    }
}
