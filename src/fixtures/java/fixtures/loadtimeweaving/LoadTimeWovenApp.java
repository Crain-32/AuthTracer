package fixtures.loadtimeweaving;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableLoadTimeWeaving;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * AspectJ method security woven as classes load: the application starts only with a weaver, and then a call on this
 * runs the check too.
 */
@SpringBootApplication
public class LoadTimeWovenApp {

    public static void main(String[] args) {
        SpringApplication.run(LoadTimeWovenApp.class, args);
    }
}

@Configuration
@EnableLoadTimeWeaving
@EnableMethodSecurity(mode = AdviceMode.ASPECTJ)
class WeavingConfig {
}

@Service
class Payslips {

    public String latest() {
        return payslip();
    }

    @PreAuthorize("hasRole('PAYROLL')")
    public String payslip() {
        return "payslip";
    }
}

@RestController
class PayslipController {

    private final Payslips payslips;

    PayslipController(Payslips payslips) {
        this.payslips = payslips;
    }

    @GetMapping("/latest")
    String latest() {
        return payslips.latest();
    }
}
