package dev.crain.profileservice.profile;

import java.util.List;

import dev.crain.profileservice.employeeservice.EmployeeGraphQlClient;
import org.springframework.stereotype.Service;

@Service
public class ProfileService {

    private final EmployeeGraphQlClient employees;

    public ProfileService(EmployeeGraphQlClient employees) {
        this.employees = employees;
    }

    public ProfileView getProfile(long id) {
        return ProfileView.from(employees.employee(id));
    }

    public List<ProfileView> listProfiles() {
        return employees.employees().stream().map(ProfileView::from).toList();
    }
}
