package fixtures.accessors;

/**
 * A getter narrowed by an override: javac adds a bridge with the base return type after it.
 */
class BaseDetails {

    public String getName() {
        return "";
    }
}

class AdminDetails extends BaseDetails {

    public String getClearance() {
        return "";
    }
}

class BaseDto {

    public BaseDetails getDetails() {
        return new BaseDetails();
    }
}

class AdminDto extends BaseDto {

    @Override
    public AdminDetails getDetails() {
        return new AdminDetails();
    }
}
