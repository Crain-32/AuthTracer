package dev.crain.payrollservice.team;

import java.math.BigDecimal;

import dev.crain.payrollservice.employeeservice.EmployeeDto;
import dev.crain.payrollservice.employeeservice.EmployeeServiceClient;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive method security: every method returns a {@code Mono} or {@code Flux}.
 */
@Service
public class TeamService {

    private final TeamRepository teams;
    private final EmployeeServiceClient employeeService;

    public TeamService(TeamRepository teams, EmployeeServiceClient employeeService) {
        this.teams = teams;
        this.employeeService = employeeService;
    }

    @PreAuthorize("hasAuthority('SCOPE_employees.read')")
    public Mono<TeamView> find(long id) {
        return teams.findById(id).flatMap(team -> employeeService.employee(team.leadId())
                .map(lead -> new TeamView(team.id(), team.name(), lead.firstName() + " " + lead.lastName(),
                        lead.email(), team.memberIds().size())));
    }

    @PreAuthorize("hasRole('ADMIN')")
    public Mono<PayrollView> payroll(long id) {
        return teams.findById(id).flatMap(team -> Flux.fromIterable(team.memberIds())
                .flatMap(employeeService::employee)
                .map(EmployeeDto::salary)
                .reduce(BigDecimal.ZERO, BigDecimal::add)
                .map(total -> new PayrollView(team.id(), total, team.memberIds().size())));
    }

    @PreAuthorize("hasRole('ADMIN')")
    public Mono<TeamSummary> addMember(long id, long employeeId) {
        return teams.findById(id).flatMap(team -> teams.save(team.withMember(employeeId))).map(TeamSummary::of);
    }

    @PostFilter("filterObject.visibility() == 'PUBLIC' or hasRole('ADMIN')")
    public Flux<TeamSummary> directory() {
        return teams.findAll().map(TeamSummary::of);
    }
}
