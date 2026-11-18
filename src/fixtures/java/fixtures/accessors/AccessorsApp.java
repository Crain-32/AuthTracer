package fixtures.accessors;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Getters whose names don't follow from their types: a {@code boolean getActive()} (as Kotlin compiles
 * {@code val active: Boolean}) and an {@code isVerified()} that returns a String.
 */
class Member {

    private final boolean active;

    private final String verified;

    private final int level;

    Member(boolean active, String verified, int level) {
        this.active = active;
        this.verified = verified;
        this.level = level;
    }

    public int getLevel() {
        return level;
    }

    public boolean getActive() {
        return active;
    }

    public String isVerified() {
        return verified;
    }
}

record MemberView(boolean active, String verified) {
}

/**
 * Constants only, but which one depends on the level: an implicit flow through a {@code switch}.
 */
record Tier(String name) {

    static String of(int level) {
        switch (level) {
            case 0:
                return "BRONZE";
            case 1:
                return "SILVER";
            default:
                return "GOLD";
        }
    }
}

@RestController
class MemberController {

    @GetMapping("/member")
    MemberView member() {
        Member member = load();
        return new MemberView(member.getActive(), member.isVerified());
    }

    @GetMapping("/members")
    MemberView[] members() {
        Member member = load();
        return new MemberView[] { new MemberView(member.getActive(), member.isVerified()) };
    }

    @GetMapping("/members/index")
    Map<?, MemberView> index() {
        return Map.of();
    }

    @GetMapping("/tier")
    Tier tier() {
        return new Tier(Tier.of(load().getLevel()));
    }

    private Member load() {
        return new Member(true, "yes", 2);
    }
}
