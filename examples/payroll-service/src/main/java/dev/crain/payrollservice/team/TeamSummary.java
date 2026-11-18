package dev.crain.payrollservice.team;

public record TeamSummary(long teamId, String name, String visibility) {

    static TeamSummary of(Team team) {
        return new TeamSummary(team.id(), team.name(), team.visibility());
    }
}
