package fixtures.jaxrspackages.internal;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

/**
 * Outside the scanned package: not registered with Jersey.
 */
@Path("/debug")
public class DebugResource {

    @GET
    public String dump() {
        return "state";
    }
}
