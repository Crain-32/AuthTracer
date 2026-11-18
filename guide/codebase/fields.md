# Fields: what a response carries, and where it comes from

This page covers the field level of a graph: which fields each response and message has
([response fields](#response-fields)), where each field's value comes from inside a service and between services
([field lineage](#field-lineage)), what a server-rendered page shows ([view fields](#view-fields)), and how checks on
single fields are attached to those fields ([field checks](#field-checks-the-fields-side)). How a field check is found
in the first place (`@AuthorizeReturnObject`, `@PreAuthorize` on a getter) is on [method-checks.md](method-checks.md);
how the exposures add the checks up is on [analysis.md](analysis.md).

Two things to hold on to before reading on:

- A **Field** node is one property of one type, `field:<class>.<property>`, as
  [`Field.id`](../../scanner/src/main/java/dev/crain/authtracer/graph/Field.java#L56) makes it. It is not a JSON path: a type
  nested twice in a response has one set of Field nodes, and [`Exposures`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L40)
  works out the paths (`owner.pets[].name`) later. Provided facts name fields by these ids.
- A **Flow** belongs to a path: [`Flow.path`](../../scanner/src/main/java/dev/crain/authtracer/graph/Flow.java#L19) is the
  Ingress whose response it builds, or the message Egress whose payload it builds. The same field can be filled from
  different places on different endpoints, and the exposures only follow the flows of the path they are on.

| Where fields and flows come from | Class | Path of its flows |
|---|---|---|
| A handler's response body | [`ResponseFields.expose`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ResponseFields.java#L44), shape from [`ValueFlow.returnShape`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ValueFlow.java#L166) | The Ingress |
| A rendered view's model | [`ViewFields.expose`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewFields.java#L159) | The Ingress |
| A GraphQL field resolver | [`ResponseFields.resolved`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ResponseFields.java#L77) | Each operation that can reach it |
| A message sent, a Stream function's result | [`MessagePayloads.sent`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessagePayloads.java#L59), [`MessagePayloads.returned`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessagePayloads.java#L70) | The send's Egress |
| A message received, and what a listener keeps of it | [`MessagePayloads.received`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessagePayloads.java#L76), [`MessagePayloads.written`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessagePayloads.java#L89) | The listener's Ingress |
| A STOMP broadcast | `stompBroadcasts` in [`SpringSecurityModule`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L60) | The subscription's Ingress |
| What a denial handler hands a denied caller | [`ResponseFields.denied`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ResponseFields.java#L96) | The Ingress |
| A field that crosses a call or a message | [`Linker`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L53) (`networkFlows`) | The qualified Egress (a NETWORK flow) |

## Response fields

**Feature:** [`RESPONSE_FIELDS`](features.md#response_fields)

Every Ingress that returns something gets the fields of its response as Field nodes: the properties Jackson writes
(names, `@JsonIgnore`, naming strategies, `@JsonView`), nested types flattened, collections and maps of application
objects marked as such, and for GraphQL whether the schema has the field. Message payloads get the same treatment.

### How it works

1. **Set up once per scan.** The `Scan` constructor in
   [`SpringSecurityModule`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L60) builds one
   [`TypeProperties`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/TypeProperties.java#L32), and with it the
   [`ValueFlow`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ValueFlow.java#L64),
   [`ResponseFields`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ResponseFields.java#L23) and
   [`MessagePayloads`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessagePayloads.java#L38) that share it.
2. **The response type.** [`SpringSecurityModule.Scan.walk`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L426)
   picks it: a rendered view's type (see [view fields](#view-fields)), a functional endpoint's response as its detector
   recorded it, else [`Payloads.returnedBy`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/Payloads.java#L49) on the
   handler, with the handler's `@JsonView`s from `jsonViews`. The Ingress is stored with that
   [`Payload`](../../scanner/src/main/java/dev/crain/authtracer/graph/Payload.java#L17).
3. **Unwrapping.** [`Payloads.unwrap`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/Payloads.java#L63) peels the
   containers frameworks put around a body (`Optional`, `ResponseEntity`, `Mono`, `CompletableFuture`,
   `DeferredResult`, HATEOAS's `EntityModel`...) and marks collections (`List`, `Flux`, `Stream`, Kotlin's `Flow`) as
   many; so is any library type that is an `Iterable`, a `Map` (its values), a `Stream` or a `Publisher` (a `Page`, an
   `ArrayList`, a `CollectionModel`), through its generic supertypes (`GenericTypes.as`). A library type that is none
   of these with one of the application's types among its arguments (`Payloads.unread`) is an OPAQUE_CONFIG finding:
   its fields would otherwise be missing without a word. A Kotlin suspend
   function's result is its `Continuation` parameter's type argument. JAX-RS's `Response` names no body type, so it
   gives none (decision 0052). Other detectors use the same method for their responses (Actuator, SOAP, RSocket,
   Data REST, STOMP), and [`HttpClientEgress`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpClientEgress.java#L77)
   for what a call returns, which the linker needs to carry fields between services.
4. **Fields.** [`ResponseFields.expose`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ResponseFields.java#L44) calls
   `flatten`, which goes through the type's properties and adds a Field node for each (`field`), then fills its
   lineage (`fill`, next section) and flattens the type each one holds. Only application types are flattened, and a
   type that holds itself is flattened once per chain (the `enclosing` set).
5. **Properties.** [`TypeProperties.of`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/TypeProperties.java#L150)
   resolves them once per type (`resolve`):
   - a record's components;
   - a generated protobuf message's fields, from its `*_FIELD_NUMBER` constants (`protobufFields`), with
     `getXList()` and `getXMap()` for repeated and map fields;
   - for other classes, the superclass's properties, then public non-transient fields, fields with `@JsonProperty`,
     and every non-transient field with field visibility `ANY` (`@JsonAutoDetect`, or
     `spring.jackson.visibility.field`), then getters (as [`ClassFileMetadata`](../../scanner/src/main/java/dev/crain/authtracer/scan/ClassFileMetadata.java#L53)
     names them for the Jackson in use) and methods of any name marked `@JsonProperty` or `@JsonGetter`, without
     Groovy's `getMetaClass()`. `ResponseFields` leaves out an `isX()` that isn't a boolean's: it reads the field
     (lineage), but Jackson doesn't write it. A type with `@JsonValue`, `@JsonAnyGetter`, `@JsonTypeInfo`,
     `@JsonSubTypes` or its own `@JsonSerialize` is written some other way (`TypeProperties.writtenOtherwise`): an
     OPAQUE_CONFIG finding says so where it is in a response.

   `hidden` drops `@JsonIgnore`, `@JsonProperty(access = WRITE_ONLY)` and the names in `@JsonIgnoreProperties`
   (unless it has `allowGetters`). `jsonName` takes `@JsonProperty`'s name, else applies the naming strategy
   (`naming`: the class's `@JsonNaming`, else `spring.jackson.property-naming-strategy`). `views` reads `@JsonView` on
   the property, falling back to the class's.
6. **What a property holds.** [`TypeProperties.heldType`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/TypeProperties.java#L153)
   writes an array, collection or stream of application objects as `app.Pet[]`, a map of them as `app.Pet{}`, and an
   `Optional` or `AtomicReference` as the type it holds, using
   [`GenericTypes`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/GenericTypes.java#L36) to read the generic
   signature. [`Field.held`](../../scanner/src/main/java/dev/crain/authtracer/graph/Field.java#L43) undoes the marker.
7. **Messages.** A listener's parameter type is exposed on its Ingress by
   [`MessagePayloads.received`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessagePayloads.java#L76), a send's
   payload type on its Egress by `sent` (see [field lineage](#field-lineage)).
8. **GraphQL's schema.** After every path is walked,
   [`GraphQlFieldPaths.markSchemaFields`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlFieldPaths.java#L74)
   follows each operation's root field type through the schema and marks every Field of the Java types it maps with
   [`Field.withGraphQl`](../../scanner/src/main/java/dev/crain/authtracer/graph/Field.java#L84): in the schema or not
   (decision 0033).
9. **Where it lands.** Field nodes in the graph. `responseFields` in
   [`Exposures`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L40) reads them back by JSON path
   (`pets[].name`, a map's values as `pets.*.name`), leaving out fields the schema doesn't have and fields outside the
   handler's views.

### Relies on / relied on by

- **Relies on** [`APPLICATION_GRAPH`](features.md#application_graph): `ScanContext` and `ClassFileMetadata` for the
  generic signatures, annotations and getters; and on every entry point detector setting its Ingress's response.
- **Relied on by** [`FIELD_LINEAGE`](features.md#field_lineage) (the fields its flows fill),
  [`VIEW_FIELDS`](features.md#view_fields), [`FIELD_CHECKS`](features.md#field_checks) (the fields a check guards),
  [`EXPOSURES`](features.md#exposures) (`Exposures.responseFields`), the linker's `networkFlows` (fields are matched
  by JSON name), and [`PROVIDED_FACTS`](features.md#provided_facts) (labels go on Field ids).

### Tests

- [`JsonFieldsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/JsonFieldsFixtureTests.java#L18),
  [`JsonHiddenFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/JsonHiddenFixtureTests.java#L15),
  [`JsonNamingFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/JsonNamingFixtureTests.java#L14),
  [`JsonMapsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/JsonMapsFixtureTests.java#L18) and
  [`JsonViewFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/JsonViewFixtureTests.java#L15): what Jackson
  writes, on the fixtures of the same names under [`src/fixtures/java/fixtures/`](../../src/fixtures/java/fixtures/).
- [`JacksonNamesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/JacksonNamesFixtureTests.java#L20):
  Jackson 2's getter names against Jackson 3's, and Boot's preferred mapper.
- [`KotlinPropertiesFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/KotlinPropertiesFixtureTests.java#L15)
  and [`KotlinCtorFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/KotlinCtorFixtureTests.java#L14):
  where Kotlin puts a property's annotations.
- [`FlowsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/FlowsFixtureTests.java#L15) (arrays and
  collections in the response, `@JsonProperty` names),
  [`AsyncResultsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/AsyncResultsFixtureTests.java#L16)
  (asynchronous results and Kotlin flows), and
  [`GraphQlFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GraphQlFixtureTests.java#L21)
  (`fieldsTheSchemaLeavesOutAreNotExposed`).

### Before changing it

- **Field ids are by type and property.** Goldens, Provided facts (`field:<class>.<property>`) and the UI all key on
  them; JSON paths only exist in the exposures.
- **Which Jackson writes the JSON decides the getter names** (decision 0078). `TypeProperties.jackson2` follows Spring
  Framework 7.0.9 (Jackson 3 whenever `tools.jackson.databind.ObjectMapper` is on the classpath) and Spring Boot 4.1.1
  (`spring.http.converters.preferred-json-mapper: jackson2`). The naming strategies (`snakeCase`, `separated`) copy
  Jackson's own rules, capitals runs included.
- **`TypeProperties.of` must not use `computeIfAbsent`**: resolving a class resolves its superclass, a recursive
  update of the same map.
- **A class's fields come in no fixed order**, so protobuf fields are read sorted by name; graphs must be the same
  every scan.

## Field lineage

**Feature:** [`FIELD_LINEAGE`](features.md#field_lineage)

For every response field on every path, the fields its value is made from, each as a Flow with a
[`FieldSource`](../../scanner/src/main/java/dev/crain/authtracer/graph/FieldSource.java#L10). The exposures follow the flows back
to the root sources, which is how a field inherits the checks, labels and policies of the data it carries, across
calls and messages between services.

| Source | Meaning | Example |
|---|---|---|
| `DIRECT` | The same value, maybe renamed | `dto.name = employee.getName()` |
| `COMPLEX` | A structure that nests other fields | `new Summary(employee)`: `summary.employee` is COMPLEX from every field inside it |
| `COMPUTED` | Derived by an operation, or chosen by testing a field (an implicit flow) | `first + " " + last`; `salary > 100 ? "high" : "low"` |
| `MASKED` | What a field check's denial handler derives from the value for the callers it denies | `iban(denied)` from `iban` (see [field checks](#field-checks-the-fields-side)) |

### How it works

1. **A method's summary.** [`ValueFlow.returnShape`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ValueFlow.java#L166)
   asks `summary`, cached by full signature, which runs one
   [`ValueFlow.Analysis.run`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ValueFlow.java#L335) over the body in
   statement order. Values are [`Shape`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/Shape.java#L18)s: a `Leaf`
   (field ids and parameter indexes, and whether it was computed), a `Composite` (an object whose properties are
   known), or a `Function`/`Functions` (a lambda or method reference to application code).
2. **Statements.** `assign` gives a parameter its index, holds a `new` until its constructor runs, records writes to
   `this` fields and to public fields of objects built here, and merges every other assignment into the local
   (`Shape.merge`: a value assigned on two branches holds both). `if` and `switch` conditions are collected, and at
   the end a returned `Leaf` becomes COMPUTED from the fields they tested. `invokeStatement` handles calls whose
   result is unused: a gRPC handler's `StreamObserver.onNext(..)` is what it returns, a setter on an object built
   here fills that property, and a library `add`/`put` puts its last argument into the collection.
3. **Expressions.** `eval` and `call` read each value:
   - a getter or record accessor on an application type (`accessor`) is a read of that field, or of the component
     an object built here was given;
   - an application method is read through [`CallTraversal`](../../scanner/src/main/java/dev/crain/authtracer/scan/CallTraversal.java#L44)'s
     targets, its summary's parameters replaced with the arguments (`substitute`);
   - a fluent builder's methods (Lombok's or hand-written `*Builder`) carry what each call sets on the receiver;
     a protobuf message's builder is read as one by `protobufBuilder` (decision 0032);
   - a constructor (`construct`) fills a record's components by position, or another class's fields from what its
     constructor stores; Groovy's named-argument maps (`namedArguments`) give each field the argument of its name;
   - library calls are read by name: `PRESERVING` ones pass values through (streams, optionals, `ResponseEntity.ok`),
     `KEEPING` ones keep the receiver (a filter's predicate isn't the result), `FALLING_BACK` ones are the receiver
     or the function's result, `LOOKUPS` pick elements by key without copying it; any other library call is COMPUTED
     from its receiver and arguments;
   - a function argument (`map(Mapper::from)`) is applied to the receiver's elements (`apply`), and read with the
     values it is given when their fields are known (`returnedWith`).
4. **Into flows.** `fill` in [`ResponseFields`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ResponseFields.java#L23)
   turns the response's shape into flows on the Ingress's path: a `Composite` gives a COMPLEX flow from each field it
   holds, then fills the nested type's own fields from its components; a `Leaf` gives DIRECT or COMPUTED flows from
   each field it holds. `ensureField` adds the field a flow starts from as a node, so lineage can start at a field no
   response shows.
5. **Messages** (decisions 0090 and 0098). The walker's `onCallSite` in
   [`SpringSecurityModule`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L60) calls
   [`MessagePayloads.sent`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessagePayloads.java#L59) for every send
   it adds: the payload argument ([`MessageSends.payload`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessageSends.java#L110))
   is read with `ValueFlow.argumentShape`, then put in terms of what the callers on the walk pass (`resolved`, through
   `ValueFlow.atCallSite`, or `ValueFlow.atLambda` for a send inside a lambda). On a listener's path it calls
   `written`: an object of another application type built or set there from the payload's fields gets flows on the
   listener's Ingress, which is how what a service keeps of a message, and later serves, traces back to the sender.
   `returned` does the same for a Spring Cloud Stream function's result on its output binding.
6. **GraphQL resolvers.** [`GraphQlFieldPaths.append`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlFieldPaths.java#L44)
   finds the operations whose result can hold a resolver's type and calls
   [`ResponseFields.resolved`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ResponseFields.java#L77) with what the
   resolver returns: the field it adds (or fills in place of the type's own property) gets its lineage on each of
   those paths (decision 0030).
7. **Between services.** `networkFlows` in [`Linker`](../../src/main/java/dev/crain/authtracer/link/Linker.java#L53)
   matches, on every link, the fields of the call's response type with those of the called endpoint's response type
   by JSON name, five types deep (`matchFields`), and a message's sent payload with the listener's parameter type.
   Each match is a NETWORK flow whose path is the qualified Egress (see [system.md](system.md)).
8. **Where it lands.** Flows in the graph and the system graph. `trace` in
   [`Exposures`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L40) follows them from each response field
   back to its roots (see [analysis.md](analysis.md)), and the UI's
   [`lineageLayout.ts`](../../frontend/src/features/lineage/lineageLayout.ts) draws them.

### Relies on / relied on by

- **Relies on** [`RESPONSE_FIELDS`](features.md#response_fields) (the fields flows fill) and
  [`CALL_PATHS`](features.md#call_paths): `CallTraversal.targets` resolves calls, and the walk's call sites carry a
  send's payload back to where it was built. Message lineage needs [`MESSAGE_SENDS`](features.md#message_sends) and
  [`MESSAGE_LISTENERS`](features.md#message_listeners); lineage between services needs the links of
  [`SYSTEM_GRAPH`](features.md#system_graph).
- **Relied on by** [`EXPOSURES`](features.md#exposures) (each field's sources, labels and lineage),
  [`DIAGONAL_ESCALATION`](features.md#diagonal_escalation) (routes to the same source),
  [`POLICIES`](features.md#policies) (labels inherited from sources) and [`LINEAGE_VIEW`](features.md#lineage_view).

### Tests

- [`FlowsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/FlowsFixtureTests.java#L15): the four sources,
  implicit flows, collections, builders, constructors and setters, on [`fixtures/flows`](../../src/fixtures/java/fixtures/flows/)
  and [`fixtures/accessors`](../../src/fixtures/java/fixtures/accessors/).
- [`FlowFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/FlowFormsFixtureTests.java#L20),
  [`FlowFunctionsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/FlowFunctionsFixtureTests.java#L13),
  [`BuilderStatementsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/BuilderStatementsFixtureTests.java#L13),
  [`BridgedFlowsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/BridgedFlowsFixtureTests.java#L14) and
  [`GroovyMapsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/GroovyMapsFixtureTests.java#L17): the
  harder forms (operators, method references chosen on branches, bridge methods, Groovy's maps).
- [`MessageLineageFixtureTests`](../../src/test/java/dev/crain/authtracer/diff/MessageLineageFixtureTests.java#L24) and
  [`MessageFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/diff/MessageFormsFixtureTests.java#L24): a send's
  payload, a listener's, what the listener writes, and the exposures that follow them, on the `messagelineage*` and
  `messageforms*` fixtures.
- [`StompTopicsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/StompTopicsFixtureTests.java#L20)
  (each STOMP sender's own type), [`GrpcFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GrpcFixtureTests.java#L30)
  (protobuf builders) and [`GraphQlFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/GraphQlFixtureTests.java#L21)
  (`resolvedFieldsAreExposedWithTheirOwnChecks`).
- Between services: [`LinkerTests`](../../src/test/java/dev/crain/authtracer/link/LinkerTests.java#L35)
  (`fieldsCrossLinksByJsonName`, `fieldsAreMatchedFiveTypesDeep`), and in the integration tests
  [`ExampleServicesLinkTests`](../../src/integrationTest/java/dev/crain/authtracer/ExampleServicesLinkTests.java#L26) and
  [`ReactiveServiceLinkTests`](../../src/integrationTest/java/dev/crain/authtracer/ReactiveServiceLinkTests.java#L21).

### Before changing it

- **Locals merge, they never overwrite.** One pass in statement order can't tell which assignment reaches the return,
  so a reassigned local holds everything it was given.
- **Summaries are keyed by the full signature.** A bridge method (`Object run()`) and the method it bridges
  (`Account run()`) differ only in their return type, and the bridge's summary is not the real one.
- **Recursion is read until it settles.** A method already being summarised returns what it returns so far (at first
  `Shape.EMPTY`), and is then read again, at most `MAX_RECURSION_PASSES` times, until that stops changing. The methods
  between the call and its recursion used an unfinished summary, so theirs aren't kept (`unfinished`): mappers that
  call each other give the same lineage whichever endpoint is read first.
- **A component built from constants comes from the property itself.** `accessor` falls back to the field when the
  object's component holds no field, so a value set from a literal still has a source.
- **The parameter numbering of builder summaries is load-bearing:** `RECEIVER` is `-1`, the receiver's fields read
  before they are set are `receiverField(i)`, `-2 - i`; `builderSummary` and `substitute` decode them.
- **Fields cross services by JSON name**, as the wire carries them, not by Java name.
- **A listener's writes are followed only from the payload** (decision 0098): objects built of none of its fields
  are not, or every entity a listener touched would trace back to the message.

## View fields

**Feature:** [`VIEW_FIELDS`](features.md#view_fields)

A `@Controller` handler that renders a Thymeleaf, JSP or FreeMarker view responds with what the page shows. Its
response type is the view (`view:owners/ownerDetails`), with one field per model path the template reads
(`owner.pets[].name`), a DIRECT flow from the domain field it shows (`Pet.name`), and a field check for each path
shown only inside `sec:authorize` (decision 0035).

### How it works

1. **The models.** The `Scan` constructor in
   [`SpringSecurityModule`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L60) builds a
   [`ViewModels`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewModels.java#L45) and a
   [`ViewFields`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewFields.java#L45), giving the latter a function
   that asks [`HttpSecurityRules.locationFor`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/HttpSecurityRules.java#L792)
   what the request rules ask of a request. Before the walk,
   [`ViewModels.prepare`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewModels.java#L90) reads every handler's
   view, and gives handlers that render one view with different models a type of their own
   (`view:owners/details (OwnerController#print)`, decision 0081).
2. **A handler's view.** `ViewModels.view` applies to a handler that returns a `String` or a `ModelAndView`, on a
   controller that isn't `@ResponseBody` or a JAX-RS resource. Its names come from what it returns (`views`: constants,
   each branch's, helpers', `ModelAndView`'s constructor and `setViewName`), without `redirect:` and `forward:`. Its
   model is what `added` finds (`addAttribute`, `addObject`, `put` on a `Model`, `ModelMap`, `ModelAndView` or a
   `Map` parameter, and in the helpers it is handed to), the `@ModelAttribute` methods of the controller, its
   superclasses and every `@ControllerAdvice`, and `parameters` (`@ModelAttribute` and form objects), each named by
   Spring's convention (`conventionalName`).
3. **The walk.** [`SpringSecurityModule.Scan.walk`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L426)
   gives the Ingress the view as its response and calls
   [`ViewFields.expose`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewFields.java#L159), which returns the field
   checks. They are added to the path after the handler's steps and the serialization checks: the page renders after
   the handler returns.
4. **Finding the template.** The `ViewFields` constructor lists one
   [`ViewTemplates`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewTemplates.java#L42) reader per dialect:
   Thymeleaf (`spring.thymeleaf.prefix` and `suffix`), FreeMarker (`spring.freemarker.template-loader-path`, `.ftlh`)
   and, when the application has a JSP view resolver (`jspResolver`: Boot's `spring.mvc.view.*`, an XML
   `InternalResourceViewResolver`, `ViewResolverRegistry.jsp()`, or one the code builds with constants), JSP.
   `expose` asks each in turn for the view's reads.
5. **Without a template**, every model attribute is a field of the view, and its type's properties are exposed as
   any response's are ([`ResponseFields.expose`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ResponseFields.java#L44)).
6. **With one**, [`ViewTemplates.reads`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewTemplates.java#L173)
   parses it (`parse`): a scan over the tags with a stack of scopes for `th:each`, `th:with`, `th:object`, JSTL's
   `<c:forEach>` and `<c:set>`, and Spring's form tags; every `${..}` and `*{..}` in attributes and inline text becomes
   model paths (`paths`, `resolve`); guards come from `sec:authorize`, `sec:authorize-url`, `sec:authorize-acl`, a
   `th:if` that is only `#authorization.expression(..)` (`thymeleafGuard`), and JSP's `<sec:authorize>` and
   `<sec:accesscontrollist>` (`jspGuard`); fragments and includes are read with their arguments and inside their
   caller's guards (`Read.inside`). A FreeMarker template is first rewritten line for line into the JSP markup this
   parser reads, by [`FreeMarkerMarkup.of`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FreeMarkerMarkup.java#L46).
7. **Fields and flows.** For each model path read from a model attribute, `expose` adds a Field of the view
   (`owner:pets[]:name`, JSON name `owner.pets[].name`), and `source` walks the path through
   [`TypeProperties`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/TypeProperties.java#L32) to the domain field it
   shows, which gets a DIRECT flow into it.
8. **Field checks.** A path every read of which is guarded gets one `sec:authorize` location (scope FIELD, phase
   POST, denial NULL), at the guarding element's template line: it asks for any of the reads' guards, each read's own
   guards together. `guard` turns a guard into a requirement:
   [`SpelRequirements.standard`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpelRequirements.java#L99) for an
   expression, and for `url:GET /admin` what the request rules ask of that request (`permitAll` when no rule
   matches).

### Relies on / relied on by

- **Relies on** [`RESPONSE_FIELDS`](features.md#response_fields) (`TypeProperties`, `GenericTypes`, `ResponseFields`)
  and [`REQUEST_RULES`](features.md#request_rules) for URL guards; [`REQUIREMENTS`](features.md#requirements) reads the
  guard expressions.
- **Relied on by** [`EXPOSURES`](features.md#exposures), which counts the template checks as field checks, and
  [`DIFF`](features.md#diff): `locate` in [`GraphDiff`](../../src/main/java/dev/crain/authtracer/diff/GraphDiff.java#L34)
  points a check removed from a template at the template, and
  [`SourceFiles`](../../src/main/java/dev/crain/authtracer/diff/SourceFiles.java#L34) finds the template's line for SARIF.

### Tests

- [`ViewFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ViewFixtureTests.java#L27): the view as the
  response, the template's fields, shared fragments' guards, and a diff that fails when `sec:authorize` is dropped
  (`droppingSecAuthorizeFromATemplateWeakensTheField`), on [`fixtures/views`](../../src/fixtures/java/fixtures/views/)
  and its templates in [`src/fixtures/resources/views`](../../src/fixtures/resources/views/).
- [`ViewFormsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ViewFormsFixtureTests.java#L19) (models
  from advice, `setViewName`, `Map.of`, no template) and
  [`ViewTagsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ViewTagsFixtureTests.java#L18) (URL and
  ACL guards, one view with different models).
- [`JspViewFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/JspViewFixtureTests.java#L19),
  [`FreeMarkerViewFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FreeMarkerViewFixtureTests.java#L18)
  and [`ViewArraysFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/flow/ViewArraysFixtureTests.java#L14).
- Parser units: [`ViewTemplatesTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ViewTemplatesTests.java#L14)
  and [`FreeMarkerMarkupTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FreeMarkerMarkupTests.java#L10).

### Before changing it

- **Shown unguarded anywhere, a field isn't guarded.** Only a path no read of which is outside a guard gets a check.
- **A template check's id holds the view and every guard's template and line**, so another view showing the same
  fragment, or showing it under fewer guards, has its own check (decision 0081). The diff and SARIF locate the check
  by that file and line.
- **URL guards ask what the request rules ask**, as Spring's `WebInvocationPrivilegeEvaluator` does (7.1.1
  `AuthorizationManagerWebInvocationPrivilegeEvaluator`): the DispatcherServlet's path is dropped, `${..}` is a path
  variable, a URL no chain authorizes is allowed.
- **JSP's `<sec:authorize>` reads `access`, else `url` (with `method`, `GET` by default), else shows nothing**, as
  7.x's `AbstractAuthorizeTag#authorize` does: `jspGuard` returns `denyAll` for the last case.
- **`FreeMarkerMarkup` keeps every line where it was** (comments and directives keep their line breaks), because the
  checks' lines are the template's.

## Field checks: the fields side

**Feature:** [`FIELD_CHECKS`](features.md#field_checks)

A check on one field of a response guards that field and the fields nested under it, nothing else. This section
covers how such checks are joined to the response's fields, what a denied caller gets instead, and how the exposures
count them; [method-checks.md](method-checks.md) covers how `MethodSecurity` finds them on getters.

### How it works

1. **Checks that serializing runs.** In [`SpringSecurityModule.Scan.walk`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/SpringSecurityModule.java#L426),
   when the handler returns a proxy (`Proxies.frame` says which
   [`ProxyFactories`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ProxyFactories.java#L49) factory made it:
   Spring's, or one the application builds), `serialized` collects the FIELD-scope checks that factory applies on the
   response type's getters, in name order, and on the types its `@AuthorizeReturnObject` getters return. They are
   added to the path as unconditional steps after the handler: Jackson calls those getters.
2. **What a denied caller gets** (DENY-02, decision 0076). `deniedValues` keeps the serialized checks whose denial
   handler (`MethodSecurity.denialHandler`) returns a value derived from the denied one,
   [`ValueFlow.derivesFrom`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ValueFlow.java#L174) its parameter 0, and
   calls [`ResponseFields.denied`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ResponseFields.java#L96): a field
   `iban(denied)` beside `iban`, with a MASKED flow from it. Where the code reads such a getter instead of serializing
   it, the derived value flows on into what the code builds, which the graph doesn't follow: that is an
   `OPAQUE_CALLPATH` finding.
3. **GraphQL resolvers** (decision 0030). [`GraphQlFieldPaths.resolverSteps`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlFieldPaths.java#L116)
   turns the checks every way through a resolver passes into one FIELD check on the field it resolves (denial NULL,
   `fieldOwner` the resolved type), since a denied resolver nulls the field and the rest of the result is returned.
4. **Templates.** [`ViewFields.expose`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewFields.java#L159) adds a
   FIELD check per guarded model path (see [view fields](#view-fields)).
5. **Exposures.** `checks` in [`Exposures`](../../src/main/java/dev/crain/authtracer/diff/Exposures.java#L40) keeps the
   path's FIELD checks by the field they guard
   ([`AuthorizationLocation.guardedField`](../../scanner/src/main/java/dev/crain/authtracer/graph/AuthorizationLocation.java#L89)),
   and notes those that answer a denied caller rather than throw. `trace` adds a field's own guards when it reaches
   the field; a nested field starts from its enclosing field's steps. Following a MASKED flow uses
   `PathChecks.throwing`: the checks that answer don't stand in front of what they answer with. `notHandedOut` leaves
   out the masked values of checks this endpoint's serialization doesn't run.
6. **Elsewhere.** The linker's `credentialFindings` names a field check by its field; `clientTokenFindings` doesn't
   judge field checks (one only hides its field); trace decisions on field checks repeat once per element, so
   `observeChecks` prefers a location not yet matched (see [system.md](system.md)).
   [`Policies`](../../src/main/java/dev/crain/authtracer/diff/Policies.java#L51) leaves field checks out of an endpoint's
   chain.

### Relies on / relied on by

- **Relies on** [`METHOD_SECURITY`](features.md#method_security) (`MethodSecurity.checks`, `authorizesReturnObject`,
  `denialHandler`), [`RESPONSE_FIELDS`](features.md#response_fields) and [`FIELD_LINEAGE`](features.md#field_lineage)
  (`derivesFrom`, the MASKED flow).
- **Relied on by** [`EXPOSURES`](features.md#exposures) and so [`DIFF`](features.md#diff): dropping a field check
  weakens that field only.

### Tests

- [`FieldsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/FieldsFixtureTests.java#L12) and
  [`ProxyFlowsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/ProxyFlowsFixtureTests.java#L15): which
  reads and serializations run a getter's check, on [`fixtures/fields`](../../src/fixtures/java/fixtures/fields/) and
  [`fixtures/proxyflows`](../../src/fixtures/java/fixtures/proxyflows/).
- [`DenialsFixtureTests`](../../src/test/java/dev/crain/authtracer/scan/spring/DenialsFixtureTests.java#L23): masked
  values and the finding for code that reads them, on [`fixtures/denials`](../../src/fixtures/java/fixtures/denials/).
- [`ExposuresTests`](../../src/test/java/dev/crain/authtracer/diff/ExposuresTests.java#L24): a field check guards its
  field and those under it, counts once, and a derived value passes only the checks that throw.
- [`GraphDiffTests`](../../src/test/java/dev/crain/authtracer/diff/GraphDiffTests.java#L25)
  (`droppingAFieldCheckWeakensThatFieldOnly`) and [`LinkerTests`](../../src/test/java/dev/crain/authtracer/link/LinkerTests.java#L35)
  (`aFieldCheckIsCountedForEveryElementItGuards`).

### Before changing it

- **A field check counts only for its field, and only where it ran on the path.** It never joins an endpoint's
  request steps, so it can't strengthen the endpoint or the other fields.
- **Serialization checks are in getter name order**: a class's methods come in no fixed order, and the path must be
  the same every scan.
- **The masked field's id is the real one with `(denied)` after it**; the exposures find what a check hands out by
  its MASKED flow, not by the name.

## Files

| File | Role | Features |
|---|---|---|
| [`ResponseFields`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ResponseFields.java#L23) | Turns a response's shape into Field nodes and the Flows that fill them; resolved and masked fields | RESPONSE_FIELDS, FIELD_LINEAGE; `resolved` GRAPHQL_OPERATIONS; `denied` FIELD_CHECKS |
| [`TypeProperties`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/TypeProperties.java#L32) | The properties Jackson writes for a type, their JSON names, views and held types | RESPONSE_FIELDS |
| [`GenericTypes`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/GenericTypes.java#L36) | A value's static type with its generic arguments, and a container's element type | VIEW_FIELDS, WEBSOCKET_MESSAGES, RESPONSE_FIELDS |
| [`Payloads`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/Payloads.java#L20) | Body types, unwrapped from the containers frameworks put around them | RESPONSE_FIELDS, FIELD_LINEAGE |
| [`ValueFlow`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/ValueFlow.java#L64) | What each method returns, in terms of fields and its parameters | FIELD_LINEAGE; `derivesFrom` FIELD_CHECKS |
| [`Shape`](../../scanner/src/main/java/dev/crain/authtracer/scan/flow/Shape.java#L18) | What a value is made of, as far as fields go | FIELD_LINEAGE |
| [`MessagePayloads`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/MessagePayloads.java#L38) | What a message carries at both ends, and what a listener keeps of it | MESSAGE_SENDS, MESSAGE_LISTENERS, FIELD_LINEAGE |
| [`GraphQlFieldPaths`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/GraphQlFieldPaths.java#L33) | Joins GraphQL field resolvers to the operations' paths and marks the schema's fields | GRAPHQL_OPERATIONS; `resolverSteps` FIELD_CHECKS |
| [`ViewModels`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewModels.java#L45) | The views a handler renders and the model they get | VIEW_FIELDS |
| [`ViewFields`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewFields.java#L45) | A view's fields, their flows from domain fields, and its template checks | VIEW_FIELDS |
| [`ViewTemplates`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/ViewTemplates.java#L42) | The model paths a Thymeleaf or JSP template reads, and the guards around them | VIEW_FIELDS |
| [`FreeMarkerMarkup`](../../scanner/src/main/java/dev/crain/authtracer/scan/spring/FreeMarkerMarkup.java#L21) | A FreeMarker template rewritten as the JSP markup `ViewTemplates` reads | VIEW_FIELDS |
