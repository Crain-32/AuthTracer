package dev.crain.payrollservice.team;

import java.security.Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/teams")
public class TeamController {

    private static final Logger log = LoggerFactory.getLogger(TeamController.class);

    private final TeamService teamService;

    public TeamController(TeamService teamService) {
        this.teamService = teamService;
    }

    @GetMapping("/{id}")
    public Mono<TeamView> get(@PathVariable long id, Principal principal) {
        log.info("GET /teams/{} by {}", id, principal.getName());
        return teamService.find(id);
    }

    @GetMapping("/{id}/payroll")
    public Mono<PayrollView> payroll(@PathVariable long id, Principal principal) {
        log.info("GET /teams/{}/payroll by {}", id, principal.getName());
        return teamService.payroll(id);
    }

    @PostMapping("/{id}/members/{employeeId}")
    public Mono<TeamSummary> addMember(@PathVariable long id, @PathVariable long employeeId, Principal principal) {
        log.info("POST /teams/{}/members/{} by {}", id, employeeId, principal.getName());
        return teamService.addMember(id, employeeId);
    }
}
