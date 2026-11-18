package dev.crain.payrollservice.team;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * In memory; the ids refer to employee-service's seeded employees.
 */
@Repository
public class TeamRepository {

    private final Map<Long, Team> teams = new ConcurrentHashMap<>();

    public TeamRepository() {
        save(new Team(1, "Platform", 2, List.of(1L, 4L), "PUBLIC"));
        save(new Team(2, "Finance", 3, List.of(2L, 3L), "PUBLIC"));
        save(new Team(3, "Board", 2, List.of(2L, 3L), "PRIVATE"));
    }

    public Mono<Team> findById(long id) {
        return Mono.justOrEmpty(teams.get(id));
    }

    public Flux<Team> findAll() {
        return Flux.fromIterable(teams.values()).sort(Comparator.comparingLong(Team::id));
    }

    public Mono<Team> save(Team team) {
        teams.put(team.id(), team);
        return Mono.just(team);
    }
}
