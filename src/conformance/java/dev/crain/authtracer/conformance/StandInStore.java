package dev.crain.authtracer.conformance;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.aopalliance.intercept.MethodInterceptor;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.annotation.AnnotatedBeanDefinition;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.ConstructorArgumentValues;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.CollectionFactory;
import org.springframework.core.ResolvableType;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.type.filter.AssignableTypeFilter;
import org.springframework.data.annotation.Id;
import org.springframework.data.keyvalue.core.KeyValueTemplate;
import org.springframework.data.keyvalue.core.mapping.KeyValuePersistentEntity;
import org.springframework.data.keyvalue.core.mapping.KeyValuePersistentProperty;
import org.springframework.data.keyvalue.core.mapping.context.KeyValueMappingContext;
import org.springframework.data.keyvalue.repository.query.KeyValuePartTreeQuery;
import org.springframework.data.keyvalue.repository.query.PredicateQueryCreator;
import org.springframework.data.keyvalue.repository.support.KeyValueRepositoryFactoryBean;
import org.springframework.data.map.MapKeyValueAdapter;
import org.springframework.data.mapping.PersistentProperty;
import org.springframework.data.mapping.PersistentPropertyAccessor;
import org.springframework.data.mapping.SimpleAssociationHandler;
import org.springframework.data.mapping.model.Property;
import org.springframework.data.mapping.model.SimpleTypeHolder;
import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.core.support.RepositoryFactoryInformation;
import org.springframework.objenesis.ObjenesisStd;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

/**
 * The store a fixture's Spring Data repositories would have in an application of its own: Spring Data's map store,
 * for each repository interface of the fixture's package that no store backs, so that Spring Data REST serves it.
 * Each domain type holds one item, id 1 (what the probes' paths name), its associations linked to the other types'
 * items; a delete leaves it, so that every caller finds it. A property named {@code id} is the id when none is marked
 * {@code @Id}, as the fixtures' domain types have it.
 */
final class StandInStore implements BeanDefinitionRegistryPostProcessor {

    private static final String PREFIX = "conformanceStore";

    private final String fixture;
    /**
     * For the report: the repositories it backs.
     */
    private final List<String> stored;
    private IdNamed context;
    private KeyValueTemplate template;
    private Set<Class<?>> domainTypes;

    StandInStore(String fixture, List<String> stored) {
        this.fixture = fixture;
        this.stored = stored;
    }

    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) {
        ClassLoader loader = ((ConfigurableListableBeanFactory) registry).getBeanClassLoader();
        Set<String> backed = new HashSet<>();
        for (String name : registry.getBeanDefinitionNames()) {
            BeanDefinition definition = registry.getBeanDefinition(name);
            String type = definition.getBeanClassName();
            if (type != null && ClassUtils.isPresent(type, loader) && RepositoryFactoryInformation.class
                    .isAssignableFrom(ClassUtils.resolveClassName(type, loader))) {
                ConstructorArgumentValues.ValueHolder repository = definition.getConstructorArgumentValues()
                        .getIndexedArgumentValue(0, null);
                if (repository != null && repository.getValue() != null) {
                    backed.add(repository.getValue() instanceof Class<?> given ? given.getName()
                            : repository.getValue().toString());
                }
            }
        }
        Map<Class<?>, Class<?>[]> repositories = new LinkedHashMap<>();
        for (Class<?> repository : repositories(loader)) {
            Class<?>[] types = ResolvableType.forClass(repository).as(Repository.class).resolveGenerics();
            if (!backed.contains(repository.getName()) && types[0] != null && types[1] != null && id(types[0])) {
                repositories.put(repository, types);
            }
        }
        if (repositories.isEmpty()) {
            return;
        }
        context = new IdNamed();
        template = new KeyValueTemplate(new Kept(), context);
        domainTypes = new LinkedHashSet<>();
        repositories.values().forEach(types -> domainTypes.add(types[0]));
        seed(template, context, domainTypes);
        IdNamed mapping = context;
        KeyValueTemplate operations = template;
        registry.registerBeanDefinition(PREFIX + "MappingContext", new RootBeanDefinition(IdNamed.class,
                () -> mapping));
        registry.registerBeanDefinition(PREFIX + "Template", new RootBeanDefinition(KeyValueTemplate.class,
                () -> operations));
        repositories.forEach((repository, types) -> {
            RootBeanDefinition definition = new RootBeanDefinition(Factory.class);
            definition.getConstructorArgumentValues().addIndexedArgumentValue(0, repository);
            definition.getPropertyValues().add("keyValueOperations", template);
            definition.getPropertyValues().add("mappingContext", context);
            definition.getPropertyValues().add("queryCreator", PredicateQueryCreator.class);
            definition.getPropertyValues().add("queryType", KeyValuePartTreeQuery.class);
            definition.setTargetType(ResolvableType.forClassWithGenerics(Factory.class,
                    repository, types[0], types[1]));
            definition.setAttribute(FactoryBean.OBJECT_TYPE_ATTRIBUTE, repository);
            registry.registerBeanDefinition(PREFIX + repository.getSimpleName(), definition);
            stored.add(repository.getSimpleName());
        });
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
    }

    /**
     * The store as it was seeded, for the next probe: Spring Data REST writes into the item it reads (a {@code PUT}
     * nulls what it doesn't send), so the items are made anew.
     */
    void reset() {
        if (template != null) {
            template.getKeyValueAdapter().clear();
            seed(template, context, domainTypes);
        }
    }

    /**
     * The repository interfaces of the fixture's package, as Spring Data finds them.
     */
    private List<Class<?>> repositories(ClassLoader loader) {
        ClassPathScanningCandidateComponentProvider scanner = new ClassPathScanningCandidateComponentProvider(false) {

            @Override
            protected boolean isCandidateComponent(AnnotatedBeanDefinition definition) {
                return definition.getMetadata().isInterface()
                        && !definition.getMetadata().hasAnnotation(NoRepositoryBean.class.getName());
            }
        };
        scanner.setResourceLoader(new DefaultResourceLoader(loader));
        scanner.addIncludeFilter(new AssignableTypeFilter(Repository.class));
        List<Class<?>> found = new ArrayList<>();
        for (BeanDefinition candidate : scanner.findCandidateComponents("fixtures." + fixture)) {
            found.add(ClassUtils.resolveClassName(candidate.getBeanClassName(), loader));
        }
        return found;
    }

    /**
     * Whether the type has an id the store can read: one marked {@code @Id}, or a field named {@code id}.
     */
    private static boolean id(Class<?> type) {
        return marked(type) || ReflectionUtils.findField(type, "id") != null;
    }

    private static boolean marked(Class<?> type) {
        boolean[] found = {false};
        ReflectionUtils.doWithFields(type, field -> found[0] = true, field -> field.isAnnotationPresent(Id.class));
        return found[0];
    }

    /**
     * One item of each type, id 1, its associations linked to the other items. A type the store can't make an item of
     * (a record whose id can't be given) has none: its repository serves nothing, as it would empty.
     */
    private static void seed(KeyValueTemplate template, IdNamed context, Set<Class<?>> types) {
        Map<Class<?>, PersistentPropertyAccessor<?>> items = new HashMap<>();
        for (Class<?> type : types) {
            try {
                KeyValuePersistentEntity<?, ?> entity = entity(context, type);
                PersistentPropertyAccessor<?> accessor = entity.getPropertyAccessor(instance(type));
                accessor.setProperty(entity.getRequiredIdProperty(), DefaultConversionService.getSharedInstance()
                        .convert("1", entity.getRequiredIdProperty().getType()));
                items.put(type, accessor);
            } catch (RuntimeException e) {
                // No item of this type.
            }
        }
        items.forEach((type, accessor) -> entity(context, type).doWithAssociations(
                (SimpleAssociationHandler) association -> {
                    PersistentProperty<?> property = association.getInverse();
                    PersistentPropertyAccessor<?> linked = items.get(property.getActualType());
                    if (linked == null) {
                        return;
                    }
                    try {
                        if (property.isCollectionLike()) {
                            // Linking adds to it, unlinking removes from it.
                            Collection<Object> collection = CollectionFactory.createCollection(property.getType(),
                                    1);
                            collection.add(linked.getBean());
                            accessor.setProperty(property, collection);
                        } else {
                            accessor.setProperty(property, linked.getBean());
                        }
                    } catch (RuntimeException e) {
                        // Left unlinked: its resource answers that there is nothing there.
                    }
                }));
        items.forEach((type, accessor) -> {
            Object item = accessor.getBean();
            try {
                template.insert(entity(context, type).getIdentifierAccessor(item).getRequiredIdentifier(), item);
            } catch (RuntimeException e) {
                // No item of this type.
            }
        });
    }

    private static KeyValuePersistentEntity<?, ?> entity(IdNamed context, Class<?> type) {
        return (KeyValuePersistentEntity<?, ?>) context.getRequiredPersistentEntity(type);
    }

    private static Object instance(Class<?> type) {
        try {
            return BeanUtils.instantiateClass(ReflectionUtils.accessibleConstructor(type));
        } catch (NoSuchMethodException e) {
            return new ObjenesisStd().newInstance(type);
        }
    }

    /**
     * Makes the repository's proxy in the interface's own class loader, as an application has one: the harness boots a
     * fixture with resources in a loader of their own, and a package-private interface can't be proxied there. A query
     * the map store can't run (one written for another store's {@code @Query}) answers an empty value, as a stand-in
     * would.
     */
    static final class Factory<T extends Repository<S, ID>, S, ID> extends KeyValueRepositoryFactoryBean<T, S, ID> {

        private final Class<? extends T> repository;

        Factory(Class<? extends T> repository) {
            super(repository);
            this.repository = repository;
            addRepositoryFactoryCustomizer(factory -> factory.addRepositoryProxyPostProcessor((proxy, information) ->
                    proxy.addAdvice((MethodInterceptor) invocation -> {
                        try {
                            return invocation.proceed();
                        } catch (RuntimeException e) {
                            if (!information.isQueryMethod(invocation.getMethod())) {
                                throw e;
                            }
                            return FixtureApps.empty(invocation.getMethod().getReturnType(),
                                    repository.getClassLoader());
                        }
                    })));
        }

        @Override
        public void setBeanClassLoader(ClassLoader loader) {
            super.setBeanClassLoader(repository.getClassLoader());
        }
    }

    /**
     * Spring Data's map store, but a delete leaves the item: each caller's probe finds what an earlier one deleted.
     */
    private static final class Kept extends MapKeyValueAdapter {

        @Override
        public Object delete(Object id, String keyspace) {
            return get(id, keyspace);
        }

        @Override
        public void deleteAllOf(String keyspace) {
        }
    }

    /**
     * The map store's mapping, with a property named {@code id} as the id when the type marks none.
     */
    @SuppressWarnings({"rawtypes", "unchecked"})
    private static final class IdNamed extends KeyValueMappingContext {

        @Override
        protected KeyValuePersistentProperty createPersistentProperty(Property property,
                KeyValuePersistentEntity owner, SimpleTypeHolder simpleTypeHolder) {
            boolean named = property.getName().equals("id") && !marked(owner.getType());
            return new KeyValuePersistentProperty(property, owner, simpleTypeHolder) {

                @Override
                public boolean isIdProperty() {
                    return named || super.isIdProperty();
                }
            };
        }
    }
}
