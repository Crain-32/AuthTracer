package fixtures.datarestlinks;

import java.util.List;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.annotation.Reference;
import org.springframework.data.rest.core.annotation.RestResource;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;
import org.springframework.data.rest.core.mapping.RepositoryDetectionStrategy.RepositoryDetectionStrategies;
import org.springframework.data.rest.webmvc.config.RepositoryRestConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.CorsRegistry;

/**
 * Decision 0114: an account's transactions and branch are resources of their own under the account, read through the
 * account repository; the transaction repository's checks guard only its own resources. A configurer moves the base
 * path and changes what is exported.
 */
@SpringBootApplication
@EnableMethodSecurity
class DataRestLinksApp {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return http.build();
    }
}

@Component
class RestConfig implements RepositoryRestConfigurer {

    @Override
    public void configureRepositoryRestConfiguration(RepositoryRestConfiguration config, CorsRegistry cors) {
        config.setBasePath("/api");
        config.exposeIdsFor(Account.class);
        // Every repository here is public: what this sets changes nothing, but AuthTracer can't tell.
        config.setRepositoryDetectionStrategy(RepositoryDetectionStrategies.ALL);
    }
}

class Account {

    private Long id;
    private String owner;
    @Reference
    private List<Transaction> transactions;
    @Reference
    private Branch branch;
    @Reference
    @RestResource(path = "home")
    private Branch homeBranch;
    @Reference
    @RestResource(exported = false)
    private Branch formerBranch;

    public Long getId() {
        return id;
    }

    public String getOwner() {
        return owner;
    }

    public List<Transaction> getTransactions() {
        return transactions;
    }

    public Branch getBranch() {
        return branch;
    }

    public Branch getHomeBranch() {
        return homeBranch;
    }
}

class Transaction {

    private Long id;
    private long amount;

    public Long getId() {
        return id;
    }

    public long getAmount() {
        return amount;
    }
}

class Branch {

    private Long id;
    private String name;

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }
}
