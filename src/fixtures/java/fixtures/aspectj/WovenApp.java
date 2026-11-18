package fixtures.aspectj;

import jakarta.annotation.security.RolesAllowed;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Method security left to AspectJ. Woven (AspectJModeFixtureTests weaves these classes with AspectJ's weaver), a call
 * on this still runs the check; as compiled, nothing does: no advisor is made for a proxy to apply. JSR-250's
 * annotations have no aspect, so never run.
 */
@SpringBootApplication
public class WovenApp {

    public static void main(String[] args) {
        SpringApplication.run(WovenApp.class, args);
    }
}

@Configuration
@EnableMethodSecurity(mode = AdviceMode.ASPECTJ, jsr250Enabled = true)
class WovenConfig {

    @Bean
    SecurityFilterChain open(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.anyRequest().permitAll()).build();
    }
}

@Service
class Archive {

    @PreAuthorize("hasRole('ARCHIVIST')")
    public String fetch() {
        return "archived";
    }
}

@Service
class Reports {

    private final Archive archive;

    Reports(Archive archive) {
        this.archive = archive;
    }

    public String summary() {
        return detail();
    }

    @PreAuthorize("hasRole('ANALYST')")
    public String detail() {
        return archive.fetch();
    }

    public String overview() {
        return audit();
    }

    @RolesAllowed("AUDITOR")
    public String audit() {
        return "audit";
    }
}

@RestController
class ReportController {

    private final Reports reports;

    ReportController(Reports reports) {
        this.reports = reports;
    }

    @GetMapping("/summary")
    String summary() {
        return reports.summary();
    }

    @GetMapping("/detail")
    String detail() {
        return reports.detail();
    }

    @GetMapping("/overview")
    String overview() {
        return reports.overview();
    }

    @GetMapping("/audit")
    String audit() {
        return reports.audit();
    }
}
