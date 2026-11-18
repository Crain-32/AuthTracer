package dev.crain.employeeservice.employee;

import java.util.List;
import java.util.NoSuchElementException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/employees")
public class EmployeeController {

    private static final Logger log = LoggerFactory.getLogger(EmployeeController.class);

    private final EmployeeService employeeService;

    public EmployeeController(EmployeeService employeeService) {
        this.employeeService = employeeService;
    }

    @GetMapping("/{id}")
    public EmployeeResponse get(@PathVariable long id, Authentication authentication) {
        log.info("GET /employees/{} by {}", id, authentication.getName());
        return EmployeeResponse.from(employeeService.find(id));
    }

    @GetMapping
    public List<EmployeeResponse> list(Authentication authentication) {
        log.info("GET /employees by {}", authentication.getName());
        return employeeService.list().stream().map(EmployeeResponse::from).toList();
    }

    @ExceptionHandler(NoSuchElementException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    void notFound(NoSuchElementException exception) {
        log.info("Not found: {}", exception.getMessage());
    }
}
