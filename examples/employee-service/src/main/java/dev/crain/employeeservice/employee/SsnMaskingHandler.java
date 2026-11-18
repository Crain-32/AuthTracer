package dev.crain.employeeservice.employee;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedHandler;
import org.springframework.stereotype.Component;

@Component
public class SsnMaskingHandler implements MethodAuthorizationDeniedHandler {

    static final String MASK = "***-**-****";

    @Override
    public Object handleDeniedInvocation(MethodInvocation methodInvocation, AuthorizationResult authorizationResult) {
        return MASK;
    }
}
