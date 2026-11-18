package fixtures.customadvisors;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Pointcut;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Role;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * FIELD-06: AuthorizationAdvisor beans of the application's own in a Boot application without method security, so
 * without a proxy factory. With AspectJ on the classpath, Boot's auto-proxy creator applies every advisor to the beans
 * its pointcut matches; without it, Boot's infrastructure auto-proxy creator applies only those with the
 * infrastructure role. Their pointcuts as applications build them: an AspectJ expression set in the constructor, a
 * class annotation, a method annotation with no class annotation, an expression from the environment, and one in the
 * part of the AspectJ language AuthTracer doesn't read.
 */
@SpringBootApplication
class CustomAdvisorsApp {

    /**
     * Created behind its interface, with the infrastructure role.
     */
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    AuthorizationAdvisor exportAdvisor() {
        return new ExportAdvisor();
    }

    /**
     * A supporting role, not the infrastructure one.
     */
    @Bean
    @Role(BeanDefinition.ROLE_SUPPORT)
    BeanNameAdvisor beanNameAdvisor() {
        return new BeanNameAdvisor();
    }
}

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@interface Audited {
}

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@interface Exported {
}

/**
 * Its base: what it decides isn't read.
 */
abstract class AdvisorSupport implements AuthorizationAdvisor {

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        return invocation.proceed();
    }

    @Override
    public Advice getAdvice() {
        return this;
    }
}

@Component
class PayrollAdvisor extends AdvisorSupport {

    private final AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
    private final int order;

    PayrollAdvisor() {
        pointcut.setExpression("execution(* fixtures.customadvisors.Payroll.*(..))");
        order = 300;
    }

    @Override
    public Pointcut getPointcut() {
        return pointcut;
    }

    @Override
    public int getOrder() {
        return order;
    }
}

@Component
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
class AuditAdvisor extends AdvisorSupport {

    @Override
    public Pointcut getPointcut() {
        return AnnotationMatchingPointcut.forClassAnnotation(Audited.class);
    }

    @Override
    public int getOrder() {
        return 100;
    }
}

class ExportAdvisor extends AdvisorSupport {

    @Override
    public Pointcut getPointcut() {
        return new AnnotationMatchingPointcut(null, Exported.class);
    }

    @Override
    public int getOrder() {
        return 200;
    }
}

@Component
class ConfiguredAdvisor extends AdvisorSupport {

    private final AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();

    ConfiguredAdvisor() {
        pointcut.setExpression(System.getProperty("advisor.pointcut", "execution(* fixtures..*(..))"));
    }

    @Override
    public Pointcut getPointcut() {
        return pointcut;
    }

    @Override
    public int getOrder() {
        return 0;
    }
}

class BeanNameAdvisor extends AdvisorSupport {

    @Override
    public Pointcut getPointcut() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("bean(payroll)");
        return pointcut;
    }

    @Override
    public int getOrder() {
        return 0;
    }
}

@Service
class Payroll {

    public String run() {
        return "run";
    }
}

@Audited
@Service
class Ledger {

    public String entries() {
        return "entries";
    }
}

@Service
class Reports {

    @Exported
    public String export() {
        return "export";
    }

    public String summary() {
        return "summary";
    }
}

@RestController
class CustomAdvisorsController {

    private final Payroll payroll;
    private final Ledger ledger;
    private final Reports reports;

    CustomAdvisorsController(Payroll payroll, Ledger ledger, Reports reports) {
        this.payroll = payroll;
        this.ledger = ledger;
        this.reports = reports;
    }

    @GetMapping("/payroll")
    String payroll() {
        return payroll.run();
    }

    @GetMapping("/ledger")
    String ledger() {
        return ledger.entries();
    }

    @GetMapping("/reports/export")
    String export() {
        return reports.export();
    }

    @GetMapping("/reports/summary")
    String summary() {
        return reports.summary();
    }
}
