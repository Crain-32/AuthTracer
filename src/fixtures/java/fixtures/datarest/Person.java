package fixtures.datarest;

/**
 * Public, as the public PersonRepository's own methods name it: a repository's proxy is made outside the package.
 */
public class Person {

    private Long id;
    private String name;
    private String ssn;

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getSsn() {
        return ssn;
    }
}
