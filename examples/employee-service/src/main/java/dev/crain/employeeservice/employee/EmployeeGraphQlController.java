package dev.crain.employeeservice.employee;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;

/**
 * The GraphQL API (schema in {@code graphql/schema.graphqls}). It returns the {@link EmployeeService}'s proxies as they
 * are, so the field checks on {@link Employee}'s getters apply to each field a query selects.
 */
@Controller
public class EmployeeGraphQlController {

    private static final Logger log = LoggerFactory.getLogger(EmployeeGraphQlController.class);

    private final EmployeeService employeeService;

    public EmployeeGraphQlController(EmployeeService employeeService) {
        this.employeeService = employeeService;
    }

    @QueryMapping
    public Employee employee(@Argument long id, Authentication authentication) {
        log.info("GraphQL employee({}) by {}", id, authentication.getName());
        return employeeService.find(id);
    }

    @QueryMapping
    public List<Employee> employees(Authentication authentication) {
        log.info("GraphQL employees by {}", authentication.getName());
        return employeeService.list();
    }
}
