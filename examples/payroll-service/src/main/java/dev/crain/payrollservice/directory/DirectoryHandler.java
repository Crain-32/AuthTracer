package dev.crain.payrollservice.directory;

import dev.crain.payrollservice.team.TeamService;
import dev.crain.payrollservice.team.TeamSummary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
public class DirectoryHandler {

    private static final Logger log = LoggerFactory.getLogger(DirectoryHandler.class);

    private final TeamService teamService;

    public DirectoryHandler(TeamService teamService) {
        this.teamService = teamService;
    }

    public Mono<ServerResponse> teams(ServerRequest request) {
        log.info("GET /directory/teams");
        return ServerResponse.ok().body(teamService.directory(), TeamSummary.class);
    }
}
