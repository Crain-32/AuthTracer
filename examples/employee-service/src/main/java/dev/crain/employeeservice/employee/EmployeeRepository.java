package dev.crain.employeeservice.employee;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Repository;

/**
 * In-memory store, seeded with fixed employees so traces and tests are deterministic.
 */
@Repository
public class EmployeeRepository {

    private final Map<Long, Employee> employees = new ConcurrentHashMap<>();

    public EmployeeRepository() {
        save(new Employee(1, "Alice", "Anders", "alice@example.com", "123-45-6789", new BigDecimal("85000"), "bob"));
        save(new Employee(2, "Bob", "Brown", "bob@example.com", "234-56-7890", new BigDecimal("120000"), "admin"));
        save(new Employee(3, "Carol", "Chen", "carol@example.com", "345-67-8901", new BigDecimal("95000"), "admin"));
        save(new Employee(4, "Dan", "Diaz", "dan@example.com", "456-78-9012", new BigDecimal("70000"), "bob"));
    }

    public Optional<Employee> findById(long id) {
        return Optional.ofNullable(employees.get(id));
    }

    public List<Employee> findAll() {
        return employees.values().stream().sorted((a, b) -> Long.compare(a.getId(), b.getId())).toList();
    }

    public Employee save(Employee employee) {
        employees.put(employee.getId(), employee);
        return employee;
    }
}
