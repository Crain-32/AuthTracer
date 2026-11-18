package fixtures.permissionfactory;

import java.io.Serializable;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.DenyAllPermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * EXPR-06: the expression handler bean is given the evaluator by calling the evaluator's bean method. The evaluator
 * extends Spring's DenyAllPermissionEvaluator and overrides only the target form, so the id form is Spring's.
 */
@Configuration
@EnableMethodSecurity
class PermissionFactoryConfig {

    @Bean
    static PermissionEvaluator projectPermissions() {
        return new ProjectPermissions();
    }

    @Bean
    static MethodSecurityExpressionHandler expressionHandler() {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(projectPermissions());
        return handler;
    }
}

record Project(long id, String name) {
}

class ProjectPermissions extends DenyAllPermissionEvaluator {

    @Override
    public boolean hasPermission(Authentication authentication, Object target, Object permission) {
        return authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_MEMBER"));
    }
}

@Service
class Projects {

    @PreAuthorize("hasPermission(#project, 'read')")
    String read(Project project) {
        return project.name();
    }

    @PreAuthorize("hasPermission(#id, 'Project', 'write')")
    void write(Serializable id) {
    }

    @PreAuthorize("hasPermission(#project, 'archive') or @archive.isOpen()")
    void archive(Project project) {
    }
}

@RestController
class ProjectController {

    private final Projects projects;

    ProjectController(Projects projects) {
        this.projects = projects;
    }

    @GetMapping("/projects/{id}")
    String read(@PathVariable long id) {
        return projects.read(new Project(id, "p"));
    }

    @GetMapping("/projects/{id}/write")
    String write(@PathVariable long id) {
        projects.write(id);
        return "ok";
    }

    @GetMapping("/projects/{id}/archive")
    String archive(@PathVariable long id) {
        projects.archive(new Project(id, "p"));
        return "ok";
    }
}
