package fixtures.groovymaps

import groovy.transform.CompileStatic
import groovy.transform.MapConstructor
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RestController

/**
 * Objects built with named arguments through a constructor that takes the map: @MapConstructor's, and one
 * written by hand.
 */
class Employee {
    long id
    String name
    String ssn
}

@MapConstructor
class EmployeeView {
    String name
    String taxId
}

class BadgeView {
    final String holder
    final String code

    BadgeView(Map args) {
        holder = args.holder
        code = args.getOrDefault('code', 'none')
    }
}

@CompileStatic
@MapConstructor
class StaticView {
    String name
    String taxId
}

@RestController
class GroovyMapsController {

    private Employee load(long id) {
        new Employee(id: id, name: 'Ada', ssn: '123')
    }

    @GetMapping('/employees/{id}')
    EmployeeView employee(@PathVariable('id') long id) {
        Employee employee = load(id)
        new EmployeeView(name: employee.name, taxId: employee.ssn)
    }

    @GetMapping('/badges/{id}')
    BadgeView badge(@PathVariable('id') long id) {
        Employee employee = load(id)
        new BadgeView(holder: employee.name, code: employee.id)
    }

    /**
     * A key that isn't a constant: the map is all its values together.
     */
    @GetMapping('/badges/{id}/{key}')
    BadgeView keyed(@PathVariable('id') long id, @PathVariable('key') String key) {
        Employee employee = load(id)
        new BadgeView([(key): employee.name])
    }

    @CompileStatic
    @GetMapping('/static/{id}')
    StaticView statically(@PathVariable('id') long id) {
        Employee employee = load(id)
        new StaticView(name: employee.name, taxId: employee.ssn)
    }
}
