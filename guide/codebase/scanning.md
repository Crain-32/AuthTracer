# Scanning

How one service becomes one `ApplicationGraph`. This page follows a scan in the order it runs: building the project
(or unpacking the jar it built) to get its classes and libraries, loading them into SootUp with the helpers every
detector shares, recording what
the detectors find in a `GraphBuilder`, and writing the result as JSON. Then it describes the graph model itself,
record by record, since every other page refers to it, and ends with how dynamic Groovy calls (and Kotlin's
compiled forms) are made readable to everything downstream.

What the scan finds is decided by [`SpringSecurityModule.scan`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L79)
and the call-path walk, which [call-paths.md](call-paths.md) covers. This page stops at the module's door and picks
up again when it hands its findings back.

```
 project directory, or the Boot jar or war it built
     │  ProjectScans.project: the revision, Builds.resolve (Gradle or Maven), the service's name, Provided facts
     │  ArtifactScans.artifact: unpacked into a work directory, named from what the build recorded, Provided facts
     ▼
 ScanInput  (or straight from --classes, --libraries, --resources)
     │  ApplicationScanner.scan: a SootUp JavaView, a ScanContext, a GraphBuilder
     ▼
 FrameworkModule.scan  (SpringSecurityModule: call-paths.md)
     │  field facts, finding names, GraphBuilder.build
     ▼
 ApplicationGraph ──GraphJson.write──▶ <service>.json
```

## Scanning a project

Feature: [`PROJECT_BUILDS`](features.md#project_builds)

`authtracer scan --project <dir>` scans a Gradle or Maven project by its directory: AuthTracer runs the project's own
build to compile it and to learn its runtime classpath, names the service and its revision, and reads its Provided
facts. The result is a [`ScanInput`](../../scanner/src/main/java/dev/crain/authtracer/scan/ScanInput.java#L20): the class
directories, the library jars, the resource directories, the package prefixes to keep, and the facts.

### How it works

1. **Entry.** [`CliRunner.scan`](../../src/main/java/dev/crain/authtracer/cli/CliRunner.java#L122) calls
   [`ProjectScans.project`](../../scanner/src/main/java/dev/crain/authtracer/scan/ProjectScans.java#L42) when `--project` is
   given; without it, it builds the `ScanInput` straight from `--classes`, `--libraries` and `--resources`, and no
   build runs. [`DiffCommands`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L40) does the same for
   `diff --project`.
2. **Revision first.** `ProjectScans.project` takes the revision before building, because the build's outputs would
   make the tree look changed. [`ProjectScans.gitRevision`](../../scanner/src/main/java/dev/crain/authtracer/scan/ProjectScans.java#L81)
   asks git for the short `HEAD`, adds `-dirty` when `git status --porcelain -- .` lists anything in the project's
   directory (changes elsewhere in a monorepo don't count) or git can't tell, and returns `working-tree`
   (`ProjectScans.WORKING_TREE`) when the directory has no commits or is among another repository's ignored files.
3. **Which build.** [`Builds.resolve`](../../scanner/src/main/java/dev/crain/authtracer/scan/build/Builds.java#L20) picks Gradle
   when the directory has an executable `gradlew`, or a Gradle build file and a wrapper further up the tree (a
   subproject); else Maven when it has `mvnw` or a `pom.xml`; else it stops with a `UsageException`.
4. **Gradle.** [`GradleProject.resolve`](../../scanner/src/main/java/dev/crain/authtracer/scan/build/GradleProject.java#L49) runs
   the nearest wrapper ([`GradleProject.wrapper`](../../scanner/src/main/java/dev/crain/authtracer/scan/build/GradleProject.java#L39))
   in the project's directory with AuthTracer's init script,
   [`classpath.init.gradle`](../../src/main/resources/authtracer/classpath.init.gradle), and its task
   `authtracerClasspath`. The script registers the task only in the project Gradle starts from; it depends on
   `classes` and on the runtime classpath, so a sibling module's jar is built rather than read stale, and prints
   `AUTHTRACER_CLASSES=`, `AUTHTRACER_RESOURCES=` (the processed resources and `src/main/webapp`) and
   `AUTHTRACER_LIBRARIES=` (jars only). A directory that isn't a Java project, such as a multi-project root, prints
   `AUTHTRACER_SUBPROJECT=` lines instead, and
   [`GradleProject.subproject`](../../scanner/src/main/java/dev/crain/authtracer/scan/build/GradleProject.java#L111) scans its only
   Spring Boot application, else its only Java project, else asks to be told which, listing them.
5. **Maven.** [`MavenProject.resolve`](../../scanner/src/main/java/dev/crain/authtracer/scan/build/MavenProject.java#L49) runs
   the nearest `mvnw` ([`MavenProject.wrapper`](../../scanner/src/main/java/dev/crain/authtracer/scan/build/MavenProject.java#L36)
   walks up only while each directory has a `pom.xml`), else `mvn`, with `compile dependency:build-classpath` for the
   runtime scope into a temporary file. Classes and resources are both `target/classes`, plus `src/main/webapp` when
   there is one.
6. **Running tools.** Every build and git call goes through
   [`Processes.run`](../../scanner/src/main/java/dev/crain/authtracer/scan/Processes.java#L48): standard input is closed at once,
   output and errors are read together by a virtual thread while the tool runs, and a tool still running at the
   timeout is killed with everything it started. Builds get ten minutes; git gets thirty seconds, two minutes to add or
   remove a checkout.
7. **Naming.** The service is the `--service` option, else `spring.application.name` from the resources
   ([`ConfigurationProperties.load`](../../scanner/src/main/java/dev/crain/authtracer/scan/ConfigurationProperties.java#L101)),
   else the directory's name in lower case.
8. **Facts.** [`ProvidedFacts.load`](../../scanner/src/main/java/dev/crain/authtracer/provided/ProvidedFacts.java#L47) reads the
   project's `authtracer.yaml` and the organisation's file given with `--org-facts`.
9. **Another revision.** For `diff --project <dir> --base <ref>`,
   [`DiffCommands.scanRevision`](../../src/main/java/dev/crain/authtracer/cli/DiffCommands.java#L204) checks the ref out
   with [`GitWorktree.checkout`](../../scanner/src/main/java/dev/crain/authtracer/scan/GitWorktree.java#L41): a detached
   `git worktree add` into a temporary directory. A project in a monorepo is the same subdirectory of the checkout
   ([`GitWorktree.project`](../../scanner/src/main/java/dev/crain/authtracer/scan/GitWorktree.java#L77), from
   `git rev-parse --show-prefix`). The checkout is scanned as the same service, named after the original directory,
   with the revision `<ref>@<commit>`, and [`GitWorktree.close`](../../scanner/src/main/java/dev/crain/authtracer/scan/GitWorktree.java#L82)
   removes it.

### Relies on, relied on by

- Hands its `ScanInput` to the scan itself ([`APPLICATION_GRAPH`](features.md#application_graph), next section) and
  reads facts for [`PROVIDED_FACTS`](features.md#provided_facts) ([requirements.md](requirements.md) covers how they
  apply).
- Relied on by [`COMMAND_LINE`](features.md#command_line) (`scan --project`) and [`DIFF`](features.md#diff), whose
  `--base` ref is checked out and scanned here ([delivery.md](delivery.md), [analysis.md](analysis.md)).

### Tests

- [`BuildsTests`](../../src/test/java/dev/crain/authtracer/scan/build/BuildsTests.java#L23),
  [`GradleProjectTests`](../../src/test/java/dev/crain/authtracer/scan/build/GradleProjectTests.java#L26) and
  [`MavenProjectTests`](../../src/test/java/dev/crain/authtracer/scan/build/MavenProjectTests.java#L25): which build is
  chosen, what is read from it, and the errors, with stand-in wrapper scripts.
- [`ProjectScansTests`](../../src/test/java/dev/crain/authtracer/scan/ProjectScansTests.java#L25): revisions (dirty,
  ignored copies, no repository), naming, and `GitWorktree` checkouts including one that fails partway.
- [`ProcessesTests`](../../src/test/java/dev/crain/authtracer/scan/ProcessesTests.java#L12): timeouts, no input, a tool
  that isn't installed, interruption.
- [`ProjectDiffTests`](../../src/test/java/dev/crain/authtracer/cli/ProjectDiffTests.java#L36): a project diffed against
  a checked-out base.
- Integration: [`GradleBuildsTests`](../../src/integrationTest/java/dev/crain/authtracer/scan/GradleBuildsTests.java#L20)
  runs real multi-project builds with AuthTracer's own wrapper, and
  [`DiffProjectTests`](../../src/integrationTest/java/dev/crain/authtracer/cli/DiffProjectTests.java#L24) diffs a
  subdirectory against its base.

### Before changing it

- **The revision is read before the build.** Moving `gitRevision` after `Builds.resolve` makes every project scan
  `-dirty` when the build writes into the tree.
- **Gradle runs in the project's directory**, and the init script compares each project with
  `gradle.startParameter.currentDir`: a task selected by name would otherwise run in every subproject too.
- **Gradle prints real paths** (`/private/var` for macOS's `/var`), so `subproject` relativizes against
  `toRealPath()`.
- **Nothing may wait for input.** A wrapper that downloads or prompts would hang a scan if standard input stayed open;
  `Processes.run` closes it and drains output so a full pipe can't block either.
- **A failed checkout is cleaned up.** A worktree killed partway is left locked, which `git worktree prune` won't
  remove, so `GitWorktree.checkout` removes it with `--force --force` before rethrowing.

## Scanning a built artifact

Feature: [`BUILT_ARTIFACTS`](features.md#built_artifacts)

The [scanner image](delivery.md#the-scanner-image) scans what a build produced rather than its project: a Spring Boot
jar or a war. [`ArtifactScans.artifact`](../../scanner/src/main/java/dev/crain/authtracer/scan/ArtifactScans.java#L102)
unpacks it into a work directory as the same three things a project scan reads from a build's outputs (classes,
libraries, resources), so the scan after it can't tell the difference: each example service's Boot jar scans to the
golden graph its project does.

### How it works

1. **Which layout.** [`ArtifactScans.scannable`](../../scanner/src/main/java/dev/crain/authtracer/scan/ArtifactScans.java#L93)
   and [`ArtifactScans.layout`](../../scanner/src/main/java/dev/crain/authtracer/scan/ArtifactScans.java#L150): entries
   under `BOOT-INF/` make a Boot jar, under `WEB-INF/` a war. Anything else, such as the `-plain.jar` a Gradle build
   writes next to its Boot jar, has no libraries to resolve the framework's types with, and is refused with a
   `UsageException`; the image passes it over.
2. **Unpacking.** [`ArtifactScans.unpack`](../../scanner/src/main/java/dev/crain/authtracer/scan/ArtifactScans.java#L167)
   reads the zip's central directory and writes:
   - `BOOT-INF/classes/` or `WEB-INF/classes/` to `classes/`: the classes, with the resources beside them as the build
     packed them, so `classes/` is the resource directory too;
   - each jar directly in `BOOT-INF/lib/`, `WEB-INF/lib/` or `WEB-INF/lib-provided/` at its own path, so a war's two
     library directories can hold jars of the same name;
   - for a war, everything else but those and Boot's loader to `webapp/`, the resource directory a Maven project's
     `src/main/webapp` is.

   Boot's launcher (`org/springframework/boot/loader/`) and the rest of a Boot jar's root aren't the application's and
   stay packed.
3. **A crafted archive.** [`ArtifactScans.inside`](../../scanner/src/main/java/dev/crain/authtracer/scan/ArtifactScans.java#L209)
   refuses an entry whose name would land outside its directory (`../`, an absolute path, a backslash): zip slip.
   [`ArtifactScans.Limits`](../../scanner/src/main/java/dev/crain/authtracer/scan/ArtifactScans.java#L56) caps the
   entries (200,000) and the bytes written (4 GB), counted as they are copied rather than taken from what an entry
   claims. Nothing is loaded or run: SootUp reads class files as data.
4. **Library order.** [`ArtifactScans.ordered`](../../scanner/src/main/java/dev/crain/authtracer/scan/ArtifactScans.java#L240)
   puts the libraries in the order `BOOT-INF/classpath.idx` lists them, the order Boot runs them in, then any it
   doesn't list in the archive's order.
5. **Naming.** The service is the one given, else `spring.application.name` from the resources (as for a project),
   else the manifest's `Implementation-Title` (Gradle's `bootJar` writes the project's name there), else the file's
   name without its version: [`ArtifactScans.named`](../../scanner/src/main/java/dev/crain/authtracer/scan/ArtifactScans.java#L286)
   makes `employee-service-0.0.1-SNAPSHOT.jar` `employee-service`.
6. **Revision.** The one given (the image passes `AUTHTRACER_REVISION` or the workflow's `GITHUB_SHA`), else
   [`ArtifactScans.revision`](../../scanner/src/main/java/dev/crain/authtracer/scan/ArtifactScans.java#L296): the commit in
   `git.properties` (the git-commit-id plugins'), else the version in `META-INF/build-info.properties` (Boot's
   `buildInfo()`) or the manifest's `Implementation-Version`, else `unversioned`.
7. **Facts.** A service's `authtracer.yaml` isn't in its artifact, so the caller names it, with the organisation's.

The `ScanInput` points into the work directory, which the caller deletes once the scan is done.

### Relies on, relied on by

- Hands its `ScanInput` to the scan ([`APPLICATION_GRAPH`](features.md#application_graph), next section), as
  [`PROJECT_BUILDS`](features.md#project_builds) does, and reads [`PROVIDED_FACTS`](features.md#provided_facts).
- Relied on by [`SCANNER_IMAGE`](features.md#scanner_image) ([delivery.md](delivery.md#the-scanner-image)).

### Tests

- [`ArtifactScansTests`](../../src/test/java/dev/crain/authtracer/scan/ArtifactScansTests.java#L28): a Boot jar and a war
  with stand-in classes, naming and revisions from what the build recorded, a plain jar and a file that isn't a zip,
  zip slip, and the limits.
- Integration: [`ExampleServicesScanTests`](../../src/integrationTest/java/dev/crain/authtracer/ExampleServicesScanTests.java#L25)
  scans each example service's Boot jar (`integrationTest` builds them) and compares it with its project's golden
  graph.

### Before changing it

- **Nothing in the archive is trusted.** Names go through `inside`, sizes are counted as they are written, and nothing
  is loaded. Anything new to unpack goes the same way.
- **The graph mustn't depend on where it was unpacked.** The integration test compares a Boot jar's graph with its
  project's; a path from the work directory in the graph would break it, and every scan of the same jar would differ.
- **A war's root is a resource directory without `WEB-INF/classes` and the libraries**, so a detector walking the
  resource directories doesn't find a file twice.

## The scan

Feature: [`APPLICATION_GRAPH`](features.md#application_graph)

[`ApplicationScanner.scan`](../../scanner/src/main/java/dev/crain/authtracer/scan/ApplicationScanner.java#L63) turns a
`ScanInput` into an [`ApplicationGraph`](../../scanner/src/main/java/dev/crain/authtracer/graph/ApplicationGraph.java#L21): one
service's entry points, checks, calls, fields, the order they run in, and findings, at one revision. No code of the
service runs; everything is read from bytecode and its configuration files. Two scans of the same classes write the
same JSON, so graphs of two revisions compare line by line.

### How it works

1. **The scanner.** [`ProjectScans.defaultScanner`](../../scanner/src/main/java/dev/crain/authtracer/scan/ProjectScans.java#L34)
   makes an `ApplicationScanner` with one [`FrameworkModule`](../../scanner/src/main/java/dev/crain/authtracer/scan/FrameworkModule.java#L11),
   `SpringSecurityModule`. The CLI, the diff commands and the tests' `FixtureScans` all use it.
2. **The view.** `ApplicationScanner.scan` gives SootUp three kinds of input location, each wrapped in
   [`OrderedMembers`](../../scanner/src/main/java/dev/crain/authtracer/scan/OrderedMembers.java#L30): every class directory as
   application code, the library jars as one library location, and the JDK's own classes (`jrt:`). Bodies are built
   with SootUp's default interceptors minus `TypeAssigner`
   ([`ApplicationScanner.INTERCEPTORS`](../../scanner/src/main/java/dev/crain/authtracer/scan/ApplicationScanner.java#L53)); the
   application's bodies also get [`GroovyTypedCalls`](../../scanner/src/main/java/dev/crain/authtracer/scan/GroovyTypedCalls.java#L70)
   (see [Groovy and Kotlin calls](#groovy-and-kotlin-calls)).
3. **The application's classes** are the class directories' classes that
   [`ScanInput.includes`](../../scanner/src/main/java/dev/crain/authtracer/scan/ScanInput.java#L34) keeps (`--packages`: a prefix
   covers its subpackages, not its namesakes), sorted by name.
4. **The context.** [`ScanContext`](../../scanner/src/main/java/dev/crain/authtracer/scan/ScanContext.java#L31) holds the view,
   the application's classes, and the shared readers built once per scan: [`ClassFileMetadata`](../../scanner/src/main/java/dev/crain/authtracer/scan/ClassFileMetadata.java#L53),
   [`ConfigurationProperties`](../../scanner/src/main/java/dev/crain/authtracer/scan/ConfigurationProperties.java#L37) and
   [`TypeRelations`](../../scanner/src/main/java/dev/crain/authtracer/scan/TypeRelations.java#L25) (the table below).
5. **The modules.** A new [`GraphBuilder`](../../scanner/src/main/java/dev/crain/authtracer/scan/GraphBuilder.java#L26) is handed
   to each module whose [`FrameworkModule.applies`](../../scanner/src/main/java/dev/crain/authtracer/scan/FrameworkModule.java#L16)
   says yes. [`SpringSecurityModule.applies`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L73)
   when Spring Security's `Authentication` or a Spring web stack is on the classpath; what it then does is
   [call-paths.md](call-paths.md) and the pages it leads to.
6. **Field facts.** [`ApplicationScanner.applyFieldFacts`](../../scanner/src/main/java/dev/crain/authtracer/scan/ApplicationScanner.java#L181)
   puts the Provided `SENSITIVE` labels and `DECLASSIFY` marks on the Field nodes, records every fact applied
   (`provided[]`), and adds a `PROVIDED_CONFLICT` finding for each local fact that lost to the organisation's.
7. **Finding names.** [`GraphBuilder.renameFindings`](../../scanner/src/main/java/dev/crain/authtracer/scan/GraphBuilder.java#L149)
   with [`EnclosingMethods.named`](../../scanner/src/main/java/dev/crain/authtracer/scan/EnclosingMethods.java#L80) rewrites
   every finding that names a lambda body or Groovy closure as "a lambda in" the method it is written in, at its
   line there (decision 0089, amended).
8. **Build.** [`GraphBuilder.build`](../../scanner/src/main/java/dev/crain/authtracer/scan/GraphBuilder.java#L191) makes the
   `ApplicationGraph`, whose constructor sorts nodes by id, edges by path, order, from and to, flows (once each) and
   findings, so what the detectors did in which order doesn't show.
9. **Out.** `CliRunner.scan` writes it with [`GraphJson.write`](../../scanner/src/main/java/dev/crain/authtracer/graph/GraphJson.java#L57)
   and, with `--publish`, posts it to a server, where
   [`GraphController.publish`](../../src/main/java/dev/crain/authtracer/api/GraphController.java#L47) checks it
   ([`GraphValidation.check`](../../src/main/java/dev/crain/authtracer/api/GraphValidation.java#L36)) and
   [`GraphStore.save`](../../src/main/java/dev/crain/authtracer/store/GraphStore.java#L37) keeps it.

### What the detectors are given

Everything a detector needs to read the application comes from `ScanContext` and a few static helpers. Use them
rather than SootUp directly: each one exists because SootUp's own answer was too slow, unordered, or missing.

| Helper | What it answers | Worth knowing |
|---|---|---|
| [`ScanContext.findAnnotation`](../../scanner/src/main/java/dev/crain/authtracer/scan/ScanContext.java#L178) | An annotation on a class or method, directly or as a meta-annotation (`@Service` carries `@Component`) | The usage returned is the nearest one, with its own values; meta-annotations are found breadth first and cached ([`ScanContext.metaAnnotations`](../../scanner/src/main/java/dev/crain/authtracer/scan/ScanContext.java#L222)), skipping `java.lang.annotation` and `kotlin.` |
| [`ScanContext.methodsAnnotated`](../../scanner/src/main/java/dev/crain/authtracer/scan/ScanContext.java#L212), [`ScanContext.anyClassAnnotated`](../../scanner/src/main/java/dev/crain/authtracer/scan/ScanContext.java#L202) | The application's methods with an annotation; whether any class has one | Methods come in class order, then in the order the class file declares them, which is the order Spring registers `@Bean` methods in (decision 0089) |
| [`ScanContext.subtypesOf`](../../scanner/src/main/java/dev/crain/authtracer/scan/ScanContext.java#L148), `superClassesOf`, `interfacesOf` | Type relations | Answered by [`TypeRelations`](../../scanner/src/main/java/dev/crain/authtracer/scan/TypeRelations.java#L25): subtypes among application classes only, supertypes looked up lazily. SootUp's own hierarchy would load every class of every library |
| [`ScanContext.isApplication`](../../scanner/src/main/java/dev/crain/authtracer/scan/ScanContext.java#L125), `findClass`, `findMethod` | Whether a type is the application's; a class or method from the view | Library and JDK classes are in the view too; `applicationClasses()` is what detectors look through |
| [`ClassFileMetadata`](../../scanner/src/main/java/dev/crain/authtracer/scan/ClassFileMetadata.java#L53) | What SootUp drops: generic signatures ([`ClassFileMetadata.genericReturnType`](../../scanner/src/main/java/dev/crain/authtracer/scan/ClassFileMetadata.java#L116) and kin), record components, getters as Jackson names them, declared fields, parameter annotations and names, annotation defaults, declaration order | Read with the JDK's ClassFile API, cached per class; library lookups index every jar once. [`ClassFileMetadata.property`](../../scanner/src/main/java/dev/crain/authtracer/scan/ClassFileMetadata.java#L422) names getters as Jackson 3 does unless asked for Jackson 2's legacy names |
| [`ConfigurationProperties`](../../scanner/src/main/java/dev/crain/authtracer/scan/ConfigurationProperties.java#L37) | `application.properties`/`.yaml`/`.yml` values, `${...}` placeholders, lists, flags, names under a prefix | Loaded with Spring Boot's own loaders, as Boot finds them: `config/` over the resource directory's root, `.properties` over YAML, the first resource directory that sets a key, and within a file a later document. Profiles the configuration activates itself (`spring.profiles.active`) are applied, their `application-<profile>` files and `on-profile` documents over the rest; other profiles' files and documents, cloud platforms and `spring.config.import` are left out and logged as such. Keys bind relaxedly (`serviceUrl` = `service-url`), placeholders exactly. An unresolvable placeholder gives no value, and is logged once |
| [`Annotations`](../../scanner/src/main/java/dev/crain/authtracer/scan/Annotations.java#L20) | Annotation element values as strings, booleans, ints, nested annotations | SootUp hands them over as Jimple constants; a single value comes back as a one-element list from [`Annotations.strings`](../../scanner/src/main/java/dev/crain/authtracer/scan/Annotations.java#L37) |
| [`Locals`](../../scanner/src/main/java/dev/crain/authtracer/scan/Locals.java#L29) | Def lookups within one body: the invoke a statement makes, a local's first or every definition, array elements, varargs strings, parameter indexes | Within one body only |
| [`MethodNames`](../../scanner/src/main/java/dev/crain/authtracer/scan/MethodNames.java#L17) | `find(long)`, `com.example.Service#find(long)`, and the `CodeRef` for a method or statement | [`MethodNames.key`](../../scanner/src/main/java/dev/crain/authtracer/scan/MethodNames.java#L28) is the form node ids, `via` lists and Provided facts use |
| [`EnclosingMethods`](../../scanner/src/main/java/dev/crain/authtracer/scan/EnclosingMethods.java#L32) | The method a lambda body or Groovy closure is written in | See [Groovy and Kotlin calls](#groovy-and-kotlin-calls)
| [`OpaqueCode`](../../scanner/src/main/java/dev/crain/authtracer/scan/OpaqueCode.java#L33) | After every module, gives each opaque requirement that stands for code a digest of it (`Requirement.code`): its `decidedBy` class, else the class a check that isn't an annotation is declared in, with its nested classes, application superclasses and subclasses | Decision 0106: the diff compares opaque requirements by text and digest, so a change to code it can't read is CHANGED |

### Recording: `GraphBuilder`

[`GraphBuilder`](../../scanner/src/main/java/dev/crain/authtracer/scan/GraphBuilder.java#L26) is the one place a detector writes
to. Its rules are what keep ids stable:

- [`GraphBuilder.node`](../../scanner/src/main/java/dev/crain/authtracer/scan/GraphBuilder.java#L50) adds a node unless one with
  its id is there, and returns the one kept: two detectors that reach the same check share one node. To enrich a node
  (a requirement widened by the role hierarchy, credentials found later), build the new version and
  [`GraphBuilder.replace`](../../scanner/src/main/java/dev/crain/authtracer/scan/GraphBuilder.java#L132) it; `find` reads one back.
- `edge` and [`GraphBuilder.path`](../../scanner/src/main/java/dev/crain/authtracer/scan/GraphBuilder.java#L187) record and read
  one Ingress's steps; `flow` records lineage; [`GraphBuilder.finding`](../../scanner/src/main/java/dev/crain/authtracer/scan/GraphBuilder.java#L142)
  keeps findings in a set, so raising one twice is harmless.
- [`GraphBuilder.split`](../../scanner/src/main/java/dev/crain/authtracer/scan/GraphBuilder.java#L76) adds a Split location
  (decision 0027: a check that asks for any one of several alternatives, as when another rule may match first, or
  only some ways a method returns pass a check) and remembers its parts in `splits()`, innermost first, so a later
  pass that changes the parts' requirements can rebuild it.
- `authoritySource`, `port`, `additionalPort`, `issuer` and `provided` set the graph's top-level properties.

### Relies on, relied on by

- Relies on [`PROJECT_BUILDS`](features.md#project_builds) for its input when scanning by directory, and on SootUp
  3.0.1 (`org.soot-oss:sootup.*`).
- Every other feature of a graph relies on it, through `SpringSecurityModule` ([call-paths.md](call-paths.md)),
  which writes to the `GraphBuilder`, and [`CallTraversal`](../../scanner/src/main/java/dev/crain/authtracer/scan/CallTraversal.java#L44),
  which reads through `ScanContext`. Its JSON is read by [`Linker.link`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L114)
  ([system.md](system.md)), by `Exposures` and `GraphDiff` ([analysis.md](analysis.md)), by the store and API
  ([delivery.md](delivery.md)), and by the UI, whose
  [`ApplicationGraph`](../../frontend/src/lib/types.ts#L168) type mirrors it.

### Tests

- [`FixtureScans`](../../src/test/java/dev/crain/authtracer/scan/FixtureScans.java#L23) is how unit tests run this
  pipeline: `ProjectScans.defaultScanner()` over the compiled fixtures, kept to one fixture package, with that
  fixture's resources from `src/fixtures/resources/<name>`.
- [`GraphJsonTests`](../../src/test/java/dev/crain/authtracer/graph/GraphJsonTests.java#L17),
  [`GraphModelTests`](../../src/test/java/dev/crain/authtracer/graph/GraphModelTests.java#L12),
  [`RequirementTests`](../../src/test/java/dev/crain/authtracer/graph/RequirementTests.java#L9): the model and its JSON.
- [`ClassFileMetadataTests`](../../src/test/java/dev/crain/authtracer/scan/ClassFileMetadataTests.java#L17),
  [`ConfigurationPropertiesTests`](../../src/test/java/dev/crain/authtracer/scan/ConfigurationPropertiesTests.java#L13),
  [`OrderedMembersTests`](../../src/test/java/dev/crain/authtracer/scan/OrderedMembersTests.java#L25),
  [`ScanInputTests`](../../src/test/java/dev/crain/authtracer/scan/ScanInputTests.java#L13),
  [`TypedBodiesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/TypedBodiesFixtureTests.java#L14): the
  helpers.
- [`LambdaNamesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/LambdaNamesFixtureTests.java#L16)
  (fixture [`lambdanames`](../../src/fixtures/java/fixtures/lambdanames/)): names that don't change when a lambda is
  added.
- Integration: [`RepeatableScansTests`](../../src/integrationTest/java/dev/crain/authtracer/scan/RepeatableScansTests.java#L24)
  scans every fixture twice, four at a time, and expects the same JSON;
  [`ExampleServicesScanTests`](../../src/integrationTest/java/dev/crain/authtracer/ExampleServicesScanTests.java#L25)
  compares the example services' graphs with the [goldens](../../src/integrationTest/resources/golden/).

### Before changing it

- **Same code, same graph.** SootUp 3.0.1 keeps a class's methods in a hash set of objects that hash by identity, so
  every scan walked them in a different order; `OrderedMembers` sorts them by signature. Its `getFields()` makes a new
  hash set on every call: sort fields yourself when the order matters. Anything new that iterates a `HashMap` or
  `HashSet` into the graph will show up as a flaky `RepeatableScansTests`.
- **Ids are the diff's keys.** A node's id must not change while the code it describes doesn't: build ids from
  `MethodNames.key`, routes and field names, never from a counter or the order something was found. Compiler-numbered
  lambda names count as counters, hence `EnclosingMethods`.
- **Finding messages are keys too.** `GraphDiff.findingKey` matches findings by service, kind and message, and
  `EnclosingMethods.named` rewrites the method keys in messages: changing either makes every existing finding of that
  kind read as new in the next diff.
- **`TypeAssigner` stays out.** It builds the whole type hierarchy, which loads every library class and the JDK. Read
  def/use chains and invoke signatures, not inferred local types.
- **A module receives the context and the builder, nothing else.** A second framework would be a second
  `FrameworkModule` in `ProjectScans.defaultScanner`; the field facts and finding names after the modules apply to
  whatever they produced.
- **Goldens.** A change meant to alter the example services' graphs is accepted with
  `./gradlew integrationTest -PupdateGolden=true`, reading the golden diff line by line.

## The graph model

Feature: [`APPLICATION_GRAPH`](features.md#application_graph)

The records in [`graph/`](../../scanner/src/main/java/dev/crain/authtracer/graph/) are what a scan writes, what the linker
joins, and what the diff and the UI read. They are immutable; each `withX` method returns a changed copy. Each entry
below says what the record means, how its id is made where it has one, and the feature it is for.

An application graph's JSON, abridged from the golden of `payroll-service`:

```json
{
  "schemaVersion" : 1,
  "service" : "payroll-service",
  "revision" : "golden",
  "port" : 8083,
  "authoritySource" : { "kind" : "JWT_CLAIMS", "freshness" : "SNAPSHOT", "granted" : [ "ROLE_*", "SCOPE_*", ... ] },
  "nodes" : [ { "type" : "egress", "id" : "egress:...EmployeeServiceClient#employee(long) GRPC employees.v1.EmployeeDirectory/GetEmployee", ... },
              { "type" : "field", "id" : "field:dev.crain.employees.v1.EmployeeRecord.email", ... },
              { "type" : "ingress", "id" : "ingress:GET /directory/teams", ... },
              { "type" : "location", "id" : "location:HTTP_REQUEST:...SecurityConfig#apiSecurity(...):0:/actuator/health", ... } ],
  "edges" : [ { "from" : "ingress:GET /actuator/health", "to" : "location:HTTP_REQUEST:...", "kind" : "LOCAL",
                "path" : "ingress:GET /actuator/health", "order" : 1, "via" : [ ], "bidirectional" : false } ],
  "flows" : [ { "path" : "ingress:GET /directory/teams", "from" : "field:...Team.name",
                "to" : "field:...TeamSummary.name", "source" : "DIRECT", "kind" : "LOCAL" } ],
  "provided" : [ ],
  "findings" : [ ]
}
```

### The graph

- [`ApplicationGraph`](../../scanner/src/main/java/dev/crain/authtracer/graph/ApplicationGraph.java#L21): one service at one
  revision. `port` and `additionalPorts` are where it listens, when its configuration or code says, for matching other
  services' calls to it; `authoritySource` is where its authorities come from; `issuer` is set when it is an
  authorization server; `provided` the facts applied. [`ApplicationGraph.path`](../../scanner/src/main/java/dev/crain/authtracer/graph/ApplicationGraph.java#L73)
  gives one Ingress's ordered steps, [`ApplicationGraph.flows`](../../scanner/src/main/java/dev/crain/authtracer/graph/ApplicationGraph.java#L81)
  the flows that build its response. `SCHEMA_VERSION` is 1. Feature [`APPLICATION_GRAPH`](features.md#application_graph).
- [`Node`](../../scanner/src/main/java/dev/crain/authtracer/graph/Node.java#L17): the sealed interface of the five node kinds,
  written with a `"type"` property (`ingress`, `egress`, `location`, `field`, `opaque`). Its one method, `id()`, is
  stable across scans of unchanged code.

### Nodes

| Record (`type`) | Id | What it is | Features |
|---|---|---|---|
| [`Ingress`](../../scanner/src/main/java/dev/crain/authtracer/graph/Ingress.java#L25) (`ingress`) | `ingress:GET /teams/{id}`, with `?params` when the mapping requires some ([`Ingress.withParams`](../../scanner/src/main/java/dev/crain/authtracer/graph/Ingress.java#L94)) | A way in. `httpMethod` carries the protocol's verb: an HTTP method or `*`, `GRPC`, `KAFKA`, `RABBIT`, `QUERY`/`MUTATION`/`SUBSCRIPTION` for GraphQL (`graphQlOperation()`); `route` is the path, topic, queue or operation; `handler` the method that serves it; `response` and `request` the body types | [`APPLICATION_GRAPH`](features.md#application_graph); the entry points are [entry-points.md](entry-points.md) |
| [`Egress`](../../scanner/src/main/java/dev/crain/authtracer/graph/Egress.java#L24) (`egress`) | `egress:<call site key> <METHOD> <uriTemplate>` ([`Egress.withCallSite`](../../scanner/src/main/java/dev/crain/authtracer/graph/Egress.java#L80) renames it with its site) | A call out: `client` (RestClient, gRPC, KafkaTemplate...), `httpMethod` and `uriTemplate` as for Ingress, `baseUrl` or the unresolved `baseUrlExpression`, `query`, `callSite`, `response` and `request` types, `credentials` and `credentialsVia`, `registration`. [`Egress.UNKNOWN_TARGET`](../../scanner/src/main/java/dev/crain/authtracer/graph/Egress.java#L32) (`?`) is a target the scan recognises but can't read (decision 0082) | [`SERVICE_CALLS`](features.md#service_calls), [`MESSAGE_SENDS`](features.md#message_sends), [`INFRASTRUCTURE_CALLS`](features.md#infrastructure_calls); [calls.md](calls.md) |
| [`AuthorizationLocation`](../../scanner/src/main/java/dev/crain/authtracer/graph/AuthorizationLocation.java#L30) (`location`) | `location:<SCOPE>:<target key>:<mechanism>` for method and field checks, `location:HTTP_REQUEST:<config method>:<index>:<patterns>` for rules, `location:SPLIT:...` for Splits | A check that is enforced: `mechanism` (`@PreAuthorize`, `authorizeHttpRequests`...), `scope` (`HTTP_REQUEST`, `METHOD`, `FIELD`), `phase` (`PRE`, `POST`), `requirement`, `target`, `routePattern` for rules, `field` and `fieldOwner` for field checks ([`AuthorizationLocation.guardedField`](../../scanner/src/main/java/dev/crain/authtracer/graph/AuthorizationLocation.java#L89)), `denial` (`THROW`, `NULL`, `HANDLER`, `FILTER`), `proxied`, `freshness`, and the `arguments` and `claims` its expression reads | [`APPLICATION_GRAPH`](features.md#application_graph); [rules.md](rules.md), [method-checks.md](method-checks.md), [fields.md](fields.md) |
| [`Field`](../../scanner/src/main/java/dev/crain/authtracer/graph/Field.java#L25) (`field`) | `field:<owner class>.<name>` ([`Field.id`](../../scanner/src/main/java/dev/crain/authtracer/graph/Field.java#L56)) | A property of a type as JSON writes it: `jsonName` (how fields match across services), `javaType` (`app.Pet[]` for a list of application objects, `app.Pet{}` for a map of them; [`Field.held`](../../scanner/src/main/java/dev/crain/authtracer/graph/Field.java#L43) unwraps either), Provided `labels` and `declassified`, `graphQl` (whether the schema has it), `views` | [`RESPONSE_FIELDS`](features.md#response_fields); [fields.md](fields.md) |
| [`Opaque`](../../scanner/src/main/java/dev/crain/authtracer/graph/Opaque.java#L11) (`opaque`) | `opaque:<site key>:<line>` ([`Opaque.of`](../../scanner/src/main/java/dev/crain/authtracer/graph/Opaque.java#L13)) | A step the scan can't see past (reflection, a filter it can't resolve, a dynamic Groovy HTTP call), with its `reason` and `site`. What runs after it is unknown and is never guessed | [`FINDING_OPAQUE_CALLPATH`](features.md#finding_opaque_callpath); [call-paths.md](call-paths.md) |

### Values inside nodes

| Record | What it holds | Features |
|---|---|---|
| [`CodeRef`](../../scanner/src/main/java/dev/crain/authtracer/graph/CodeRef.java#L12) | A class, optionally a method sub-signature and a line. [`CodeRef.key`](../../scanner/src/main/java/dev/crain/authtracer/graph/CodeRef.java#L29) (`Class#method(args)`, without the line) is what ids use; `atLine` drops lines a class file doesn't have | [`APPLICATION_GRAPH`](features.md#application_graph) |
| [`Payload`](../../scanner/src/main/java/dev/crain/authtracer/graph/Payload.java#L17) | A request or response body: its `type`, whether it is a collection (`many`), and the `@JsonView`s it is written with | [`RESPONSE_FIELDS`](features.md#response_fields) |
| [`Requirement`](../../scanner/src/main/java/dev/crain/authtracer/graph/Requirement.java#L25) | What a check asks for, normalized: `PERMIT_ALL`, `AUTHENTICATED`, `FULLY_AUTHENTICATED`, `REMEMBER_ME`, `ANONYMOUS`, `ANY_AUTHORITY`, `ALL_AUTHORITIES` (full names, `ROLE_ADMIN`, `SCOPE_x`), `DENY_ALL`, `AND`/`OR`/`NOT` of operands, or `EXPRESSION` when it can't be reduced. `decidedBy` is the application code that decides it ([`Requirement.custom`](../../scanner/src/main/java/dev/crain/authtracer/graph/Requirement.java#L116)); [`Requirement.permitsAnyone`](../../scanner/src/main/java/dev/crain/authtracer/graph/Requirement.java#L154) is true for permit-all and what only combines it | [`REQUIREMENTS`](features.md#requirements), [`CUSTOM_DECISIONS`](features.md#custom_decisions); [requirements.md](requirements.md) |
| [`AuthoritySource`](../../scanner/src/main/java/dev/crain/authtracer/graph/AuthoritySource.java#L24) | Where authorities come from (`JWT_CLAIMS`, `OPAQUE_TOKEN_INTROSPECTION`, `USER_DETAILS`, `IDENTITY_PROVIDER`, `CUSTOM_FILTER`) and how fresh (`SNAPSHOT`, `LIVE`); the `roleHierarchy`; `granted`, the only authorities a request can carry when the scan knows them (`SCOPE_*` for a prefix); and for a resource server the [`AuthoritySource.Jwt`](../../scanner/src/main/java/dev/crain/authtracer/graph/AuthoritySource.java#L114) it reads: claims that become authorities, accepted audiences, validators, what it can't read. [`AuthoritySource.unmet`](../../scanner/src/main/java/dev/crain/authtracer/graph/AuthoritySource.java#L64) is what keeps a requirement from ever passing | [`AUTHORITY_SOURCE`](features.md#authority_source), [`FINDING_ALWAYS_DENIED`](features.md#finding_always_denied), [`FINDING_TOKEN_REJECTED`](features.md#finding_token_rejected) |
| [`Credentials`](../../scanner/src/main/java/dev/crain/authtracer/graph/Credentials.java#L11) | What an Egress authenticates with: `RELAY` (the caller's token), `OAUTH2_CLIENT`, `STATIC`, `NONE`, `UNKNOWN`. [`Credentials.callerChecked`](../../scanner/src/main/java/dev/crain/authtracer/graph/Credentials.java#L38) says whether the called service's checks constrain the original caller (decision 0021) | [`CALL_CREDENTIALS`](features.md#call_credentials), [`EXPOSURES`](features.md#exposures) |
| [`Registration`](../../scanner/src/main/java/dev/crain/authtracer/graph/Registration.java#L23) | The OAuth2 client registration an Egress's own token is issued to: id, client id, grant type, scopes, token and issuer URIs, as the properties declare them (decision 0075, amended) | [`CALL_CREDENTIALS`](features.md#call_credentials), [`FINDING_TOKEN_REJECTED`](features.md#finding_token_rejected) |
| [`Issuer`](../../scanner/src/main/java/dev/crain/authtracer/graph/Issuer.java#L24) | What an authorization server issues tokens with: each registered client and the scopes it can be granted ([`Issuer.scopes`](../../scanner/src/main/java/dev/crain/authtracer/graph/Issuer.java#L40) for all of them), the claims its customizers add, and what it can't read (decision 0075) | [`FINDING_TOKEN_REJECTED`](features.md#finding_token_rejected), [`FINDING_ALWAYS_DENIED`](features.md#finding_always_denied); [system.md](system.md) |

### Edges

[`Edge`](../../scanner/src/main/java/dev/crain/authtracer/graph/Edge.java#L23) is one step of a Callpath. In an application graph
every edge is `LOCAL` ([`Edge.local`](../../scanner/src/main/java/dev/crain/authtracer/graph/Edge.java#L48)): `path` is the
Ingress whose request path it belongs to (a field check can sit on several paths, so each path's chain is followed by
this id), `order` is the position of `to` along it (1 is first, and the order is the relative timing of the checks),
`via` lists the methods between the entry point and `to`, outermost first, and `conditional` marks a step only some
of the ways the code returns reach (decision 0027), which doesn't constrain the whole path. In a system graph's
`links[]` the same record joins a qualified Egress to an Ingress, as `NETWORK_INFERRED` (matched statically) or
`NETWORK_OBSERVED` (seen in a trace). Features [`CALL_PATHS`](features.md#call_paths) and
[`SYSTEM_GRAPH`](features.md#system_graph); [call-paths.md](call-paths.md), [system.md](system.md).

### Flows

[`Flow`](../../scanner/src/main/java/dev/crain/authtracer/graph/Flow.java#L19) is data moving from one field into another. A
`LOCAL` flow's `path` is the Ingress whose response it builds, or the message Egress whose payload it builds (decision
0090); a `NETWORK` flow, in a system graph, carries a field across a call or message and its path is the qualified
Egress. Its `source` is a [`FieldSource`](../../scanner/src/main/java/dev/crain/authtracer/graph/FieldSource.java#L10):
`DIRECT` (the same value), `COMPLEX` (a structure that nests it), `COMPUTED` (derived), `MASKED` (what a denial
handler derives for the callers it denies). Feature [`FIELD_LINEAGE`](features.md#field_lineage); [fields.md](fields.md).

### Findings and facts

- [`Finding`](../../scanner/src/main/java/dev/crain/authtracer/graph/Finding.java#L12): a [`Finding.Kind`](../../scanner/src/main/java/dev/crain/authtracer/graph/Finding.java#L18),
  a message, and the `CodeRef` it is about. Each kind is its own feature; [findings.md](findings.md) covers them.
- [`ProvidedFact`](../../scanner/src/main/java/dev/crain/authtracer/graph/ProvidedFact.java#L26): a fact as it was applied:
  `SENSITIVE`, `DECLASSIFY`, `CHECK`, `REQUIREMENT`, `POLICY`, `ENDPOINT_POLICY`, `RULE` (a
  [structure rule](method-checks.md#structure-rules)), with its subject and its `origin`
  (`ORG_OVERRIDE` beats `ORG` beats `LOCAL`; [`ProvidedFact.conflictKey`](../../scanner/src/main/java/dev/crain/authtracer/graph/ProvidedFact.java#L68)
  says which facts compete). Features [`PROVIDED_FACTS`](features.md#provided_facts) and
  [`POLICIES`](features.md#policies); [requirements.md](requirements.md), [analysis.md](analysis.md).

### The system graph

[`SystemGraph`](../../scanner/src/main/java/dev/crain/authtracer/graph/SystemGraph.java#L18) is several application graphs
linked: `services`, cross-service `links` and `flows`, the [`Observation`](../../scanner/src/main/java/dev/crain/authtracer/graph/Observation.java#L15)s
traces made (how often a location granted or denied, how often a link was called), the
[`IdentityUsage`](../../scanner/src/main/java/dev/crain/authtracer/graph/IdentityUsage.java#L25) of each identity traces showed
(what it was granted and needed), and the findings only linking can raise. Ids there are qualified as
`service/nodeId` ([`SystemGraph.qualify`](../../scanner/src/main/java/dev/crain/authtracer/graph/SystemGraph.java#L48)).
Features [`SYSTEM_GRAPH`](features.md#system_graph), [`TRACE_OBSERVATIONS`](features.md#trace_observations),
[`IDENTITIES`](features.md#identities); [system.md](system.md) builds it.

### The JSON

[`GraphJson`](../../scanner/src/main/java/dev/crain/authtracer/graph/GraphJson.java#L25) writes both graphs as indented JSON with a
final newline and reads them back. [`GraphJson.readAny`](../../scanner/src/main/java/dev/crain/authtracer/graph/GraphJson.java#L104)
takes either kind of file and gives a system graph (an application graph becomes a system of one), which is how
`diff`, `exposures` and the API accept both. Reading is tolerant: unknown properties are ignored, a null primitive
reads as its default, and every record's constructor treats a missing list as empty, so graphs written before a
property existed still load.

**Before changing the model:**

- **Add, don't change.** A new property goes at the end of the record with `@JsonInclude` `NON_NULL` or `NON_EMPTY`,
  so graphs that don't use it, the goldens among them, are written as before; keep the old constructor as an overload
  so existing callers compile. Renaming or retyping a property breaks every stored graph and needs `SCHEMA_VERSION`
  raised and a reader for the old form.
- **Keep the sorting.** `ApplicationGraph` and `SystemGraph` sort their lists in their constructors with `Edge.ORDER`,
  `Flow.ORDER`, `Finding.ORDER` and by id; a new list needs the same, or two scans of the same code differ.
- **Mirror it in the UI.** The UI's [`types.ts`](../../frontend/src/lib/types.ts) declares the same shapes; a property
  the UI should show must be added there too ([delivery.md](delivery.md)).

## Groovy and Kotlin calls

Features: [`CALL_PATHS`](features.md#call_paths), [`SERVICE_CALLS`](features.md#service_calls), [`FIELD_LINEAGE`](features.md#field_lineage)

Every detector reads bytecode, and Groovy's and Kotlin's bytecode differs from javac's in ways that would hide calls.
Groovy outside `@CompileStatic` compiles every call to an `invokedynamic` that returns `Object`; Kotlin and Groovy
name lambdas and closures differently from javac. This section is how the scan reads them as it reads Java, so a
Groovy controller's `restClient.get().uri(..).retrieve()` is an Egress, its named-argument constructor has lineage,
and a call on a typed field reaches the method security behind it.

### How it works

1. **A dynamic call.** [`GroovyCalls.of`](../../scanner/src/main/java/dev/crain/authtracer/scan/GroovyCalls.java#L92) reads an
   `invokedynamic` bootstrapped by Groovy's `IndyInterface` into a [`GroovyCalls.Call`](../../scanner/src/main/java/dev/crain/authtracer/scan/GroovyCalls.java#L38):
   the call type is the call site's name (`invoke`, `getProperty`, `setProperty`, `cast`, `init`), the method or
   property name is the first bootstrap argument, the receiver is the first argument (a `Class` constant for a static
   call), and the call site's descriptor carries the receiver's static type when the compiler knew it.
2. **Typing at load time.** [`GroovyTypedCalls.interceptBody`](../../scanner/src/main/java/dev/crain/authtracer/scan/GroovyTypedCalls.java#L92)
   runs on every body of the application's classes as SootUp builds it. It walks the statements in order, tracking
   the types the bytecode does know (parameters, `this`, fields, casts, `new`, the call site's receiver type, the
   results of calls it has already typed), and replaces each dynamic call it can resolve with the ordinary invoke
   Groovy will make. The result has that method's return type, so the next call in a chain resolves too:
   - `invoke`: the method of that name on the receiver's type or its supertypes whose parameters the arguments fit
     (assignable, boxed, numbers widened or narrowed, a varargs method's trailing arguments), preferring an exact
     number of parameters over varargs ([`GroovyTypedCalls.method`](../../scanner/src/main/java/dev/crain/authtracer/scan/GroovyTypedCalls.java#L376)).
     Several that fit and return the same type: the first by signature; that return different types: the call stays
     dynamic.
     A method a closure doesn't have is looked up on the class it is written in, as Groovy delegates to its owner.
   - `getProperty`: the getter (`getX()`, `isX()`, a record's `x()`); on a `Map`, `map.get("x")`; on a closure, the
     type of the outer class's field or getter ([`GroovyTypedCalls.outerProperty`](../../scanner/src/main/java/dev/crain/authtracer/scan/GroovyTypedCalls.java#L326)).
   - A property assignment (`ScriptBytecodeAdapter.setGroovyObjectProperty`): the setter
     ([`GroovyTypedCalls.setter`](../../scanner/src/main/java/dev/crain/authtracer/scan/GroovyTypedCalls.java#L177)).
   - `init`: `new` and the constructor that fits; with named arguments (`new Item(id: 1)`), the constructor that takes
     a map when the class has one, else the no-argument constructor and one setter call per argument
     ([`GroovyTypedCalls.construct`](../../scanner/src/main/java/dev/crain/authtracer/scan/GroovyTypedCalls.java#L220)).
   - `cast` to an object type: a cast.
   - A varargs call gets its array built before the call, as javac would
     ([`GroovyTypedCalls.arguments`](../../scanner/src/main/java/dev/crain/authtracer/scan/GroovyTypedCalls.java#L510)).
3. **What stays dynamic.** A call that passes a closure, unless it is on Spring's HTTP clients
   ([`GroovyTypedCalls.CLOSURE_COERCING`](../../scanner/src/main/java/dev/crain/authtracer/scan/GroovyTypedCalls.java#L79)) where
   the parameter is a functional interface the closure is coerced to: the security DSL's closures are interpreted by
   [`SecurityDsl`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SecurityDsl.java#L68) instead (decision 0022,
   [rules.md](rules.md)). Calls on Groovy's own types, whose metaclass decides, and calls on untyped (`def`) receivers.
4. **Following what stayed dynamic.** [`CallTraversal.targets`](../../scanner/src/main/java/dev/crain/authtracer/scan/CallTraversal.java#L416)
   asks [`GroovyCalls.target`](../../scanner/src/main/java/dev/crain/authtracer/scan/GroovyCalls.java#L63) for a remaining
   dynamic `invoke`: an application method on the receiver's class or its application superclasses, by name, static
   or not, and number of arguments; among several, the one whose parameter types match the call site's, or the only
   one. Overrides in subclasses are added as for a virtual call. Detectors read `GroovyCalls.Call` too: the DSL readers,
   and [`HttpClientEgress.dynamicClient`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L449),
   which spots a call on an HTTP client that stayed dynamic, so the request it makes is shown as an Opaque step
   rather than missed.
5. **Names that don't move.** javac names a lambda body `lambda$employee$2`, Kotlin `employee$lambda$0`, Groovy a
   closure class `Outer$_employee_closure1` with a `doCall` method, each numbered by its place, so a name taken from
   one changes when another is added before it. [`EnclosingMethods.of`](../../scanner/src/main/java/dev/crain/authtracer/scan/EnclosingMethods.java#L139)
   finds the method that creates it (its `invokedynamic` names the body, or it makes a `new` closure), up to eight
   levels out, and `site`, `key`, `codeRef` and `named` use that method instead (decision 0089, amended). Kotlin
   doesn't mark its lambda bodies synthetic, so the name is what identifies them.
6. **Kotlin otherwise** compiles calls to ordinary invokes, so it needs no call resolution here. What it does need is
   read where it applies: [`ClassFileMetadata.getters`](../../scanner/src/main/java/dev/crain/authtracer/scan/ClassFileMetadata.java#L248)
   takes a constructor property's annotations from the primary constructor's parameter, where jackson-module-kotlin
   reads them, and names parameters from the `LocalVariableTable` kotlinc writes; the Kotlin security DSL is read by
   `SecurityDsl`, and a suspend function's real result type by [`Payloads`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/Payloads.java#L20).

### Relies on, relied on by

- Relies on [`APPLICATION_GRAPH`](features.md#application_graph): `ApplicationScanner` installs the interceptor on
  application locations only.
- Relied on by the call-path walk ([call-paths.md](call-paths.md)), Egress detection ([calls.md](calls.md)), lineage
  ([fields.md](fields.md)) and the DSL readers ([rules.md](rules.md)) whenever the application is Groovy or Kotlin.

### Tests

- [`GroovyCallsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/GroovyCallsFixtureTests.java#L16)
  ([`groovycalls`](../../src/fixtures/groovy/fixtures/groovycalls/)): inherited, interface, static, overloaded,
  varargs and ambiguous calls, closures reading their owner.
- [`GroovyFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GroovyFixtureTests.java#L22)
  ([`groovydsl`](../../src/fixtures/groovy/fixtures/groovydsl/), [`groovyclients`](../../src/fixtures/groovy/fixtures/groovyclients/)):
  typed RestClient chains, method security through dynamic calls, named-argument constructors.
- [`GroovyMapsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/GroovyMapsFixtureTests.java#L17),
  [`GroovyUriFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GroovyUriFixtureTests.java#L17),
  [`GroovyFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GroovyFormsFixtureTests.java#L17):
  map constructors, `uri { }` closures, the DSL's call forms.
- [`LambdaCallsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/LambdaCallsFixtureTests.java#L15)
  ([`kotlinlambdas`](../../src/fixtures/kotlin/fixtures/kotlinlambdas/), [`groovylambdas`](../../src/fixtures/groovy/fixtures/groovylambdas/))
  and [`LambdaNamesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/LambdaNamesFixtureTests.java#L16):
  names by enclosing method.
- [`KotlinCtorFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/KotlinCtorFixtureTests.java#L14),
  [`KotlinPropertiesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/KotlinPropertiesFixtureTests.java#L15):
  Kotlin properties as Jackson writes them.

### Before changing it

- **Never guess what Groovy decides at run time.** An untyped receiver, overloads the call site can't tell apart, or
  a Groovy type's metaclass: the call stays dynamic and the walk doesn't follow it, rather than picking one.
- **Keep the closures the DSL readers interpret dynamic.** Typing a call that passes a closure turns the closure into
  an ordinary argument that `SecurityDsl` no longer recognises; `CLOSURE_COERCING` is the list of exceptions.
- **Replacements keep their statement's position**, so call sites and findings keep their source lines.
- **The interceptor sees one body at a time**, as SootUp builds it, whenever a detector first asks for it: it can use
  SootUp's view for classes and methods, but nothing from `ScanContext`.
- **The Groovy forms are read from bytecode**: Groovy 4 and later (`org.codehaus.groovy.vmplugin.*.IndyInterface`).
  Check a new form with `javap -c -p` on a compiled fixture before matching it.

## Files

| File | Role | Features |
|---|---|---|
| [`graph/ApplicationGraph.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/ApplicationGraph.java) | One service's graph at one revision, sorted | APPLICATION_GRAPH (its `path` CALL_PATHS, `flows` FIELD_LINEAGE) |
| [`graph/AuthoritySource.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/AuthoritySource.java) | Where a service's authorities come from, what a JWT gives, what it can grant | AUTHORITY_SOURCE, APPLICATION_GRAPH (`unmet`, `withGranted`, `Jwt.checksAudience`: FINDING_ALWAYS_DENIED, FINDING_TOKEN_REJECTED) |
| [`graph/AuthorizationLocation.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/AuthorizationLocation.java) | An enforced check | APPLICATION_GRAPH (`withFreshness` AUTHORITY_SOURCE, `withReads` and `Argument` METHOD_SECURITY, `guardedField` FIELD_CHECKS) |
| [`graph/CodeRef.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/CodeRef.java) | A place in the code | APPLICATION_GRAPH |
| [`graph/Credentials.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/Credentials.java) | What a call authenticates with | CALL_CREDENTIALS, APPLICATION_GRAPH (`callerChecked` EXPOSURES) |
| [`graph/Edge.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/Edge.java) | A step of a Callpath, or a link between services | CALL_PATHS, SYSTEM_GRAPH, APPLICATION_GRAPH |
| [`graph/Egress.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/Egress.java) | A call out | SERVICE_CALLS, MESSAGE_SENDS, INFRASTRUCTURE_CALLS, APPLICATION_GRAPH (`withCredentials`, `withRegistration` CALL_CREDENTIALS, `withRequest` FIELD_LINEAGE) |
| [`graph/Field.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/Field.java) | A property of a type as JSON writes it | RESPONSE_FIELDS, APPLICATION_GRAPH (`withLabels`, `declassify` PROVIDED_FACTS) |
| [`graph/FieldSource.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/FieldSource.java) | How a flow's value relates to its source | FIELD_LINEAGE, APPLICATION_GRAPH |
| [`graph/Finding.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/Finding.java) | Something a person should look at, and its kinds | APPLICATION_GRAPH, SYSTEM_GRAPH |
| [`graph/Flow.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/Flow.java) | Data moving from one field to another | FIELD_LINEAGE, APPLICATION_GRAPH |
| [`graph/GraphJson.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/GraphJson.java) | Writes and reads both graphs | APPLICATION_GRAPH, SYSTEM_GRAPH |
| [`graph/IdentityUsage.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/IdentityUsage.java) | What a traced identity was granted and needed | IDENTITIES, SYSTEM_GRAPH |
| [`graph/Ingress.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/Ingress.java) | A way in | APPLICATION_GRAPH (`withParams`, `andParams` HTTP_ENDPOINTS, `graphQlOperation` GRAPHQL_OPERATIONS, `withRequest` FIELD_LINEAGE) |
| [`graph/Issuer.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/Issuer.java) | An authorization server's clients and their scopes | FINDING_TOKEN_REJECTED, FINDING_ALWAYS_DENIED, APPLICATION_GRAPH |
| [`graph/Node.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/Node.java) | The five node kinds and their JSON `type` | APPLICATION_GRAPH |
| [`graph/Observation.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/Observation.java) | What traces showed for a location or link | TRACE_OBSERVATIONS, SYSTEM_GRAPH |
| [`graph/Opaque.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/Opaque.java) | A step the scan can't see past | FINDING_OPAQUE_CALLPATH, APPLICATION_GRAPH |
| [`graph/Payload.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/Payload.java) | A request or response body type | RESPONSE_FIELDS, APPLICATION_GRAPH |
| [`graph/ProvidedFact.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/ProvidedFact.java) | A Provided fact as applied | PROVIDED_FACTS, POLICIES, APPLICATION_GRAPH |
| [`graph/Registration.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/Registration.java) | The client registration a call's own token is issued to | CALL_CREDENTIALS, FINDING_TOKEN_REJECTED, APPLICATION_GRAPH |
| [`graph/Requirement.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/Requirement.java) | What a check asks for, normalized | REQUIREMENTS, APPLICATION_GRAPH (`custom`, `decidedBy` CUSTOM_DECISIONS) |
| [`graph/SystemGraph.java`](../../scanner/src/main/java/dev/crain/authtracer/graph/SystemGraph.java) | Several services linked | SYSTEM_GRAPH |
| [`scan/Annotations.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/Annotations.java) | Reads annotation values | APPLICATION_GRAPH |
| [`scan/ArtifactScans.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/ArtifactScans.java) | A Boot jar or war unpacked into a `ScanInput`, safely | BUILT_ARTIFACTS |
| [`scan/ApplicationScanner.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/ApplicationScanner.java) | Runs a scan: view, context, modules, build | APPLICATION_GRAPH (`applyFieldFacts` PROVIDED_FACTS, FINDING_PROVIDED_CONFLICT) |
| [`scan/ClassFileMetadata.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/ClassFileMetadata.java) | What SootUp drops, read from class files | APPLICATION_GRAPH (getters, records, fields, `property` RESPONSE_FIELDS; `declaredParameterNames` METHOD_SECURITY) |
| [`scan/ConfigurationProperties.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/ConfigurationProperties.java) | The application's properties and placeholders | APPLICATION_GRAPH |
| [`scan/EnclosingMethods.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/EnclosingMethods.java) | Names lambdas and closures by the method they are written in | APPLICATION_GRAPH |
| [`scan/FrameworkModule.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/FrameworkModule.java) | The extension point a framework's detectors plug into | APPLICATION_GRAPH |
| [`scan/GitWorktree.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/GitWorktree.java) | A temporary checkout of another revision | DIFF, PROJECT_BUILDS |
| [`scan/GraphBuilder.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/GraphBuilder.java) | Where detectors record nodes, edges, flows and findings | APPLICATION_GRAPH (Splits REQUEST_RULES, CALL_PATHS; `flow` FIELD_LINEAGE; `authoritySource` AUTHORITY_SOURCE; `port`, `additionalPort` SYSTEM_GRAPH; `issuer` FINDING_TOKEN_REJECTED, FINDING_ALWAYS_DENIED; `provided` PROVIDED_FACTS) |
| [`scan/GroovyCalls.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/GroovyCalls.java) | Reads a dynamic Groovy call site and the method it names | APPLICATION_GRAPH (`target`, `receiverClass` CALL_PATHS) |
| [`scan/GroovyTypedCalls.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/GroovyTypedCalls.java) | Types dynamic Groovy call chains as bodies load | SERVICE_CALLS, FIELD_LINEAGE, CALL_PATHS |
| [`scan/Locals.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/Locals.java) | Def lookups within one body | APPLICATION_GRAPH |
| [`scan/MethodNames.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/MethodNames.java) | Stable, readable method names and `CodeRef`s | APPLICATION_GRAPH |
| [`scan/OrderedMembers.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/OrderedMembers.java) | Methods in signature order, for repeatable scans | APPLICATION_GRAPH |
| [`scan/Processes.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/Processes.java) | Runs git, Gradle and Maven to an end or a timeout | PROJECT_BUILDS |
| [`scan/ProjectScans.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/ProjectScans.java) | A project directory to a `ScanInput`; the default scanner | PROJECT_BUILDS (`defaultScanner` APPLICATION_GRAPH, `gitRevision` DIFF) |
| [`scan/ScanContext.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/ScanContext.java) | The loaded application and the shared lookups | APPLICATION_GRAPH |
| [`scan/ScanInput.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/ScanInput.java) | What to scan | APPLICATION_GRAPH |
| [`scan/TypeRelations.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/TypeRelations.java) | Sub- and supertypes of application classes | APPLICATION_GRAPH |
| [`scan/build/BuildClasspath.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/build/BuildClasspath.java) | A built project's classes, resources and libraries | PROJECT_BUILDS |
| [`scan/build/Builds.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/build/Builds.java) | Chooses Gradle or Maven | PROJECT_BUILDS |
| [`scan/build/GradleProject.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/build/GradleProject.java) | Builds and reads a Gradle project | PROJECT_BUILDS |
| [`scan/build/MavenProject.java`](../../scanner/src/main/java/dev/crain/authtracer/scan/build/MavenProject.java) | Builds and reads a Maven project | PROJECT_BUILDS |
| [`annotations/Might.java`](../../annotations/src/main/java/dev/crain/authtracer/annotations/Might.java) | `@Might("...")`: a deliberately deferred change, greppable instead of a long comment; in the `annotations` module beside `@Supports`, so it is a convention rather than a feature's code | none |
