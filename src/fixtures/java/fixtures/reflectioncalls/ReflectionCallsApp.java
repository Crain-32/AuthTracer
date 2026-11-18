package fixtures.reflectioncalls;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Constructor;

import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Work chosen at run time: a plugin class instantiated by name and a task method found by name. What they call is not
 * in the graph; what the code only asks of a Constructor or a MethodHandle doesn't call anything.
 */
@RestController
class PluginController {

    private final Tasks tasks;

    PluginController(Tasks tasks) {
        this.tasks = tasks;
    }

    @GetMapping("/plugins/{name}")
    String plugin(@PathVariable String name) throws Exception {
        Constructor<?> constructor = Class.forName("fixtures.reflectioncalls." + name).getDeclaredConstructor();
        if (constructor.getParameterCount() != 0) {
            throw new IllegalArgumentException(name);
        }
        return ((Plugin) constructor.newInstance()).run();
    }

    @GetMapping("/tasks/{task}")
    String task(@PathVariable String task) throws Throwable {
        MethodHandle handle = MethodHandles.lookup().findVirtual(Tasks.class, task, MethodType.methodType(String.class));
        if (handle.type().parameterCount() != 1) {
            throw new IllegalArgumentException(task);
        }
        return (String) handle.invoke(tasks);
    }
}

interface Plugin {

    String run();
}

class ReportPlugin implements Plugin {

    @Override
    public String run() {
        return "report";
    }
}

@Component
class Tasks {

    public String cleanup() {
        return "cleaned";
    }
}
