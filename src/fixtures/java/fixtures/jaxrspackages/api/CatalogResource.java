package fixtures.jaxrspackages.api;

import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;

@Path("/catalog")
@RolesAllowed("EDITOR")
public class CatalogResource {

    /**
     * The method's @PermitAll before the class's @RolesAllowed.
     */
    @GET
    @PermitAll
    public String list() {
        return "[]";
    }

    @DELETE
    @Path("/{id}")
    public void delete(@PathParam("id") long id) {
    }
}
