package dev.crain.employeeservice.directory;

import java.math.BigDecimal;
import java.util.NoSuchElementException;

import dev.crain.employees.v1.EmployeeDirectoryGrpc;
import dev.crain.employees.v1.EmployeeRecord;
import dev.crain.employees.v1.GetEmployeeRequest;
import dev.crain.employeeservice.employee.Employee;
import dev.crain.employeeservice.employee.EmployeeService;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.grpc.server.service.GrpcService;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * The gRPC directory (src/main/proto/employee_directory.proto), on its own port. The employee comes from
 * {@link EmployeeService}, so the caller's token decides the salary here as on the REST and GraphQL APIs.
 */
@GrpcService
public class EmployeeDirectoryService extends EmployeeDirectoryGrpc.EmployeeDirectoryImplBase {

    private static final Logger log = LoggerFactory.getLogger(EmployeeDirectoryService.class);

    private final EmployeeService employeeService;

    public EmployeeDirectoryService(EmployeeService employeeService) {
        this.employeeService = employeeService;
    }

    @Override
    public void getEmployee(GetEmployeeRequest request, StreamObserver<EmployeeRecord> responseObserver) {
        log.info("gRPC GetEmployee({}) by {}", request.getId(),
                SecurityContextHolder.getContext().getAuthentication().getName());
        Employee employee;
        try {
            employee = employeeService.find(request.getId());
        }
        catch (NoSuchElementException ex) {
            responseObserver.onError(Status.NOT_FOUND.withDescription(ex.getMessage()).asRuntimeException());
            return;
        }
        EmployeeRecord.Builder record = EmployeeRecord.newBuilder()
                .setId(employee.getId())
                .setFirstName(employee.getFirstName())
                .setLastName(employee.getLastName())
                .setEmail(employee.getEmail())
                .setManagerUsername(employee.getManagerUsername());
        // Null when the caller may not see it: the field stays unset.
        BigDecimal salary = employee.getSalary();
        if (salary != null) {
            record.setSalary(salary.toPlainString());
        }
        responseObserver.onNext(record.build());
        responseObserver.onCompleted();
    }
}
