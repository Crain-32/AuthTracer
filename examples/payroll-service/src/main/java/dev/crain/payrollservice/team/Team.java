package dev.crain.payrollservice.team;

import java.util.List;
import java.util.stream.Stream;

/**
 * A team of employee-service employees; {@code PRIVATE} teams are listed to admins only.
 */
public record Team(long id, String name, long leadId, List<Long> memberIds, String visibility) {

    Team withMember(long employeeId) {
        return memberIds.contains(employeeId) ? this
                : new Team(id, name, leadId, Stream.concat(memberIds.stream(), Stream.of(employeeId)).toList(),
                        visibility);
    }
}
