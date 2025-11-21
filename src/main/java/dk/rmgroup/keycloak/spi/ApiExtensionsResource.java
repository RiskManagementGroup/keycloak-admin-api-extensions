package dk.rmgroup.keycloak.spi;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.resteasy.reactive.NoCache;
import org.keycloak.authorization.fgap.AdminPermissionsSchema;
import org.keycloak.common.Profile;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.jpa.JpaUserProvider;
import static org.keycloak.models.jpa.PaginationUtils.paginateQuery;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.jpa.entities.UserGroupMembershipEntity;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.resources.KeycloakOpenAPI;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.fgap.UserPermissionEvaluator;
import org.keycloak.storage.jpa.JpaHashUtils;
import static org.keycloak.storage.jpa.JpaHashUtils.predicateForFilteringUsersByAttributes;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.utils.MediaType;
import org.keycloak.utils.SearchQueryUtils;
import static org.keycloak.utils.StreamsUtil.closing;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.From;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;

public class ApiExtensionsResource {
  private final KeycloakSession session;
  private final RealmModel realm;
  private final AdminPermissionEvaluator auth;
  @SuppressWarnings("unused")
  private final AdminEventBuilder adminEvent;
  private static final String SEARCH_ID_PARAMETER = "id:";
  private static final String EMAIL = "email";
  private static final String EMAIL_VERIFIED = "emailVerified";
  private static final String USERNAME = "username";
  private static final String FIRST_NAME = "firstName";
  private static final String LAST_NAME = "lastName";
  private static final char ESCAPE_BACKSLASH = '\\';

  public ApiExtensionsResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth,
      AdminEventBuilder adminEvent) {
    this.session = session;
    this.auth = auth;
    this.realm = session.getContext().getRealm();
    this.adminEvent = adminEvent.resource(ResourceType.USER);
  }

  /**
   * Get users
   *
   * Returns a stream of users, filtered according to query parameters.
   *
   * @param search              A String contained in username, first or last
   *                            name, or email. Default search behavior is
   *                            prefix-based (e.g., <code>foo</code> or
   *                            <code>foo*</code>). Use <code>*foo*</code> for
   *                            infix search and <code>"foo"</code> for exact
   *                            search.
   * @param last                A String contained in lastName, or the complete
   *                            lastName, if param "exact" is true
   * @param first               A String contained in firstName, or the complete
   *                            firstName, if param "exact" is true
   * @param email               A String contained in email, or the complete
   *                            email, if param "exact" is true
   * @param username            A String contained in username, or the complete
   *                            username, if param "exact" is true
   * @param emailVerified       whether the email has been verified
   * @param idpAlias            The alias of an Identity Provider linked to the
   *                            user
   * @param idpUserId           The userId at an Identity Provider linked to the
   *                            user
   * @param firstResult         Pagination offset
   * @param maxResults          Maximum results size (defaults to 100)
   * @param enabled             Boolean representing if user is enabled or not
   * @param briefRepresentation Boolean which defines whether brief
   *                            representations are returned (default: false)
   * @param exact               Boolean which defines whether the params "last",
   *                            "first", "email" and "username" must match exactly
   * @param searchQuery         A query to search for custom attributes, in the
   *                            format 'key1:value2 key2:value2'
   * @param groupIds            An array of groupIds to filter on. comma separated
   * 
   * @return a non-null {@code Stream} of users
   */
  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @APIResponses(value = {
      @APIResponse(responseCode = "200", description = "OK", content = @Content(schema = @Schema(implementation = UserRepresentation.class, type = SchemaType.ARRAY))),
      @APIResponse(responseCode = "403", description = "Forbidden")
  })
  @Tag(name = KeycloakOpenAPI.Admin.Tags.USERS)
  @Operation(summary = "Get users Returns a stream of users, filtered according to query parameters.")
  @Path("/users")
  @NoCache
  public Stream<UserRepresentation> getUsers(
      @Parameter(description = "A String contained in username, first or last name, or email. Default search behavior is prefix-based (e.g., foo or foo*). Use *foo* for infix search and \"foo\" for exact search.") @QueryParam("search") String search,
      @Parameter(description = "A String contained in lastName, or the complete lastName, if param \"exact\" is true") @QueryParam("lastName") String last,
      @Parameter(description = "A String contained in firstName, or the complete firstName, if param \"exact\" is true") @QueryParam("firstName") String first,
      @Parameter(description = "A String contained in email, or the complete email, if param \"exact\" is true") @QueryParam("email") String email,
      @Parameter(description = "A String contained in username, or the complete username, if param \"exact\" is true") @QueryParam("username") String username,
      @Parameter(description = "whether the email has been verified") @QueryParam("emailVerified") Boolean emailVerified,
      @Parameter(description = "The alias of an Identity Provider linked to the user") @QueryParam("idpAlias") String idpAlias,
      @Parameter(description = "The userId at an Identity Provider linked to the user") @QueryParam("idpUserId") String idpUserId,
      @Parameter(description = "Pagination offset") @QueryParam("first") Integer firstResult,
      @Parameter(description = "Maximum results size (defaults to 100)") @QueryParam("max") Integer maxResults,
      @Parameter(description = "Boolean representing if user is enabled or not") @QueryParam("enabled") Boolean enabled,
      @Parameter(description = "Boolean which defines whether brief representations are returned (default: false)") @QueryParam("briefRepresentation") Boolean briefRepresentation,
      @Parameter(description = "Boolean which defines whether the params \"last\", \"first\", \"email\" and \"username\" must match exactly") @QueryParam("exact") Boolean exact,
      @Parameter(description = "A query to search for custom attributes, in the format 'key1:value2 key2:value2'") @QueryParam("q") String searchQuery,
      @Parameter(description = "An array of groupIds to filter on") @QueryParam("groupIds") String groupIds,
      @Parameter(description = "Field to sort by") @QueryParam("sortBy") String sortBy,
      @Parameter(description = "Sort order: asc or desc") @QueryParam("sortOrder") String sortOrder) {
    UserPermissionEvaluator userPermissionEvaluator = auth.users();

    userPermissionEvaluator.requireQuery();

    firstResult = firstResult != null ? firstResult : -1;
    maxResults = maxResults != null ? maxResults : Constants.DEFAULT_MAX_RESULTS;

    Map<String, String> searchAttributes = searchQuery == null
        ? Collections.emptyMap()
        : SearchQueryUtils.getFields(searchQuery);

    Stream<UserModel> userModels;
    if (search != null) {
      if (search.startsWith(SEARCH_ID_PARAMETER)) {
        String[] userIds = search.substring(SEARCH_ID_PARAMETER.length()).trim().split("\\s+");
        userModels = Arrays.stream(userIds).map(id -> session.users().getUserById(realm, id)).filter(Objects::nonNull);
        if (AdminPermissionsSchema.SCHEMA.isAdminPermissionsEnabled(realm)) {
          userModels = userModels.filter(userPermissionEvaluator::canView);
        }
      } else {
        Map<String, String> attributes = new HashMap<>();
        attributes.put(UserModel.SEARCH, search.trim());
        if (enabled != null) {
          attributes.put(UserModel.ENABLED, enabled.toString());
        }
        if (emailVerified != null) {
          attributes.put(UserModel.EMAIL_VERIFIED, emailVerified.toString());
        }
        if (groupIds != null) {
          attributes.put(UserModel.GROUPS, groupIds);
        }

        return searchForUser(attributes, realm, userPermissionEvaluator, briefRepresentation, firstResult,
            maxResults, false, sortBy, sortOrder);
      }
    } else if (last != null || first != null || email != null || username != null || emailVerified != null
        || idpAlias != null || idpUserId != null || enabled != null || exact != null || !searchAttributes.isEmpty()
        || groupIds != null) {
      Map<String, String> attributes = new HashMap<>();
      if (last != null) {
        attributes.put(UserModel.LAST_NAME, last);
      }
      if (first != null) {
        attributes.put(UserModel.FIRST_NAME, first);
      }
      if (email != null) {
        attributes.put(UserModel.EMAIL, email);
      }
      if (username != null) {
        attributes.put(UserModel.USERNAME, username);
      }
      if (emailVerified != null) {
        attributes.put(UserModel.EMAIL_VERIFIED, emailVerified.toString());
      }
      if (idpAlias != null) {
        attributes.put(UserModel.IDP_ALIAS, idpAlias);
      }
      if (idpUserId != null) {
        attributes.put(UserModel.IDP_USER_ID, idpUserId);
      }
      if (enabled != null) {
        attributes.put(UserModel.ENABLED, enabled.toString());
      }
      if (exact != null) {
        attributes.put(UserModel.EXACT, exact.toString());
      }
      if (groupIds != null) {
        attributes.put(UserModel.GROUPS, groupIds);
      }

      attributes.putAll(searchAttributes);

      return searchForUser(attributes, realm, userPermissionEvaluator, briefRepresentation, firstResult,
          maxResults, false, sortBy, sortOrder);
    } else {
      return searchForUser(new HashMap<>(), realm, userPermissionEvaluator, briefRepresentation,
          firstResult, maxResults, false, sortBy, sortOrder);
    }

    return toRepresentation(realm, userPermissionEvaluator, briefRepresentation, userModels);
  }

  // Copied from UsersResource. Only difference is the that it calls our
  // searchForUserStream and toRepresentation instead of the ones in UsersResource
  private Stream<UserRepresentation> searchForUser(Map<String, String> attributes, RealmModel realm,
      UserPermissionEvaluator usersEvaluator, Boolean briefRepresentation, Integer firstResult, Integer maxResults,
      Boolean includeServiceAccounts, String sortBy, String sortOrder) {
    attributes.put(UserModel.INCLUDE_SERVICE_ACCOUNT, includeServiceAccounts.toString());

    if (Profile.isFeatureEnabled(Profile.Feature.ADMIN_FINE_GRAINED_AUTHZ)) {
      Set<String> groupIds = auth.groups().getGroupIdsWithViewPermission();
      if (!groupIds.isEmpty()) {
        session.setAttribute(UserModel.GROUPS, groupIds);
      }
    }

    return toRepresentation(realm, usersEvaluator, briefRepresentation,
        searchForUserStream(realm, attributes, firstResult, maxResults, sortBy, sortOrder));
  }

  // Copied from UsersResource. No difference
  private Stream<UserRepresentation> toRepresentation(RealmModel realm, UserPermissionEvaluator usersEvaluator,
      Boolean briefRepresentation, Stream<UserModel> userModels) {
    boolean briefRepresentationB = briefRepresentation != null && briefRepresentation;

    if (!AdminPermissionsSchema.SCHEMA.isAdminPermissionsEnabled(realm)) {
      usersEvaluator.grantIfNoPermission(session.getAttribute(UserModel.GROUPS) != null);
      userModels = userModels.filter(usersEvaluator::canView);
      usersEvaluator.grantIfNoPermission(session.getAttribute(UserModel.GROUPS) != null);
    }

    UserProfileProvider provider = session.getProvider(UserProfileProvider.class);

    return userModels
        .map(user -> {
          UserProfile profile = provider.create(UserProfileContext.USER_API, user);
          UserRepresentation rep = profile.toRepresentation();
          UserRepresentation userRep = briefRepresentationB
              ? ModelToRepresentation.toBriefRepresentation(user, rep, false)
              : ModelToRepresentation.toRepresentation(session, realm, user, rep, false);
          userRep.setAccess(usersEvaluator.getAccessForListing(user));
          return userRep;
        });
  }

  // Copied from JpaUserProvider. Calls our local predicates method. Had to get
  // entityManager differently
  // Also added sortBy and sortOrder
  // I have added group by to get distinct users when joining with attributes
  public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> attributes, Integer firstResult,
      Integer maxResults, String sortBy, String sortOrder) {
    EntityManager em = ((JpaUserProvider) session.getProvider(UserProvider.class)).getEntityManager();
    CriteriaBuilder builder = em.getCriteriaBuilder();
    CriteriaQuery<UserEntity> queryBuilder = builder.createQuery(UserEntity.class);
    Root<UserEntity> root = queryBuilder.from(UserEntity.class);

    Map<String, String> customLongValueSearchAttributes = new HashMap<>();
    List<Predicate> predicates = predicates(attributes, root, customLongValueSearchAttributes);

    predicates.add(builder.equal(root.get("realmId"), realm.getId()));

    predicates.addAll(AdminPermissionsSchema.SCHEMA.applyAuthorizationFilters(session, AdminPermissionsSchema.USERS,
        (JpaUserProvider) session.getProvider(UserProvider.class), realm, builder, queryBuilder, root));

    // We group by user Id since we want to avoid duplicates of users
    queryBuilder.distinct(false).where(predicates.toArray(Predicate[]::new)).groupBy(root.get("id"));

    if (sortBy == null) {
      queryBuilder.orderBy(builder.asc(root.get(UserModel.USERNAME)));
    } else {
      jakarta.persistence.criteria.Path<UserEntity> sortPath;
      Join<UserEntity, UserAttributeEntity> attributesJoin = root.join("attributes", JoinType.LEFT);
      attributesJoin.on(builder.equal(attributesJoin.get("name"), sortBy));
      Boolean isAttribute = false;

      switch (sortBy.toLowerCase()) {
        case "firstname":
          sortPath = root.get(UserModel.FIRST_NAME);
          break;
        case "lastname":
          sortPath = root.get(UserModel.LAST_NAME);
          break;
        case "email":
          sortPath = root.get(UserModel.EMAIL);
          break;
        case "username":
          sortPath = root.get(UserModel.USERNAME);
          break;
        default:
          isAttribute = true;
          sortPath = attributesJoin.get("value");
          break;
      }

      boolean descending = sortOrder != null && sortOrder.equalsIgnoreCase("desc");
      if (descending) {
        if (isAttribute) {
          // We use min since we group by user id. It is a bit of a hack, but should work
          queryBuilder.orderBy(builder.desc(builder.min(attributesJoin.get("value"))));
        } else {
          queryBuilder.orderBy(builder.desc(sortPath));
        }
      } else {
        if (isAttribute) {
          // We use min since we group by user id. It is a bit of a hack, but should work
          queryBuilder.orderBy(builder.asc(builder.min(attributesJoin.get("value"))));
        } else {
          queryBuilder.orderBy(builder.asc(sortPath));
        }
      }
    }

    TypedQuery<UserEntity> query = em.createQuery(queryBuilder);

    UserProvider users = session.users();
    return closing(paginateQuery(query, firstResult, maxResults).getResultStream())
        // following check verifies that there are no collisions with hashes
        .filter(predicateForFilteringUsersByAttributes(customLongValueSearchAttributes,
            JpaHashUtils::compareSourceValueLowerCase))
        .map(userEntity -> users.getUserById(realm, userEntity.getId()))
        .filter(Objects::nonNull);
  }

  // Copied from JpaUserProvider. Added case for Groups
  private List<Predicate> predicates(Map<String, String> attributes, Root<UserEntity> root,
      Map<String, String> customLongValueSearchAttributes) {
    EntityManager em = ((JpaUserProvider) session.getProvider(UserProvider.class)).getEntityManager();
    CriteriaBuilder builder = em.getCriteriaBuilder();

    List<Predicate> predicates = new ArrayList<>();
    List<Predicate> attributePredicates = new ArrayList<>();

    Join<Object, Object> federatedIdentitiesJoin = null;
    Join<UserEntity, UserGroupMembershipEntity> groupMembershipUserJoin = null;

    for (Map.Entry<String, String> entry : attributes.entrySet()) {
      String key = entry.getKey();
      String value = entry.getValue();

      if (value == null) {
        continue;
      }

      switch (key) {
        case UserModel.SEARCH:
          for (String stringToSearch : value.trim().split("\\s+")) {
            predicates.add(builder.or(getSearchOptionPredicateArray(stringToSearch, builder, root)));
          }
          break;
        case FIRST_NAME:
        case LAST_NAME:
          if (Boolean.parseBoolean(attributes.get(UserModel.EXACT))) {
            predicates.add(builder.equal(builder.lower(root.get(key)), value.toLowerCase()));
          } else {
            predicates.add(builder.like(builder.lower(root.get(key)), "%" + value.toLowerCase() + "%"));
          }
          break;
        case USERNAME:
        case EMAIL:
          if (Boolean.parseBoolean(attributes.get(UserModel.EXACT))) {
            predicates.add(builder.equal(root.get(key), value.toLowerCase()));
          } else {
            predicates.add(builder.like(root.get(key), "%" + value.toLowerCase() + "%"));
          }
          break;
        case EMAIL_VERIFIED:
          predicates.add(builder.equal(root.get(key), Boolean.valueOf(value.toLowerCase())));
          break;
        case UserModel.ENABLED:
          predicates.add(builder.equal(root.get(key), Boolean.valueOf(value)));
          break;
        case UserModel.IDP_ALIAS:
          if (federatedIdentitiesJoin == null) {
            federatedIdentitiesJoin = root.join("federatedIdentities", JoinType.LEFT);
          }
          predicates.add(builder.equal(federatedIdentitiesJoin.get("identityProvider"), value));
          break;
        case UserModel.IDP_USER_ID:
          if (federatedIdentitiesJoin == null) {
            federatedIdentitiesJoin = root.join("federatedIdentities", JoinType.LEFT);
          }
          predicates.add(builder.equal(federatedIdentitiesJoin.get("userId"), value));
          break;
        case UserModel.EXACT:
          break;
        case UserModel.GROUPS:
          if (groupMembershipUserJoin == null) {
            groupMembershipUserJoin = root.join(UserGroupMembershipEntity.class, JoinType.LEFT);
            groupMembershipUserJoin.on(builder.equal(groupMembershipUserJoin.get("user").get("id"), root.get("id")));
          }
          Collection<String> groupIdsList = new ArrayList<>();
          groupIdsList.addAll(Arrays.asList(value.split(",")));
          Predicate groupPredicate = groupMembershipUserJoin.get("groupId").in(groupIdsList);
          attributePredicates.add(groupPredicate);
          break;

        // All unknown attributes will be assumed as custom attributes
        default:
          Join<UserEntity, UserAttributeEntity> attributesJoin = root.join("attributes", JoinType.LEFT);
          if (value.length() > 255) {
            customLongValueSearchAttributes.put(key, value);
            attributePredicates.add(builder.and(
                builder.equal(attributesJoin.get("name"), key),
                builder.equal(attributesJoin.get("longValueHashLowerCase"),
                    JpaHashUtils.hashForAttributeValueLowerCase(value))));
          } else {
            if (Boolean.parseBoolean(attributes.getOrDefault(UserModel.EXACT, Boolean.TRUE.toString()))) {
              attributePredicates.add(builder.and(
                  builder.equal(attributesJoin.get("name"), key),
                  builder.equal(builder.lower(attributesJoin.get("value")), value.toLowerCase())));
            } else {
              attributePredicates.add(builder.and(
                  builder.equal(attributesJoin.get("name"), key),
                  builder.like(builder.lower(attributesJoin.get("value")), "%" + value.toLowerCase() + "%")));
            }
          }
          break;
        case UserModel.INCLUDE_SERVICE_ACCOUNT: {
          if (!attributes.containsKey(UserModel.INCLUDE_SERVICE_ACCOUNT)
              || !Boolean.parseBoolean(attributes.get(UserModel.INCLUDE_SERVICE_ACCOUNT))) {
            predicates.add(root.get("serviceAccountClientLink").isNull());
          }
          break;
        }
      }
    }

    if (!attributePredicates.isEmpty()) {
      predicates.add(builder.and(attributePredicates.toArray(Predicate[]::new)));
    }

    return predicates;
  }

  // Copied from JpaUserProvider. Nothing is changed.
  private Predicate[] getSearchOptionPredicateArray(String value, CriteriaBuilder builder,
      From<?, UserEntity> from) {
    value = value.toLowerCase();

    List<Predicate> orPredicates = new ArrayList<>();

    if (value.length() >= 2 && value.charAt(0) == '"' && value.charAt(value.length() - 1) == '"') {
      // exact search
      value = value.substring(1, value.length() - 1);

      orPredicates.add(builder.equal(from.get(USERNAME), value));
      orPredicates.add(builder.equal(from.get(EMAIL), value));
      orPredicates.add(builder.equal(builder.lower(from.get(FIRST_NAME)), value));
      orPredicates.add(builder.equal(builder.lower(from.get(LAST_NAME)), value));
    } else {
      value = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
      value = value.replace("*", "%");
      if (value.isEmpty() || value.charAt(value.length() - 1) != '%')
        value += "%";

      orPredicates.add(builder.like(from.get(USERNAME), value, ESCAPE_BACKSLASH));
      orPredicates.add(builder.like(from.get(EMAIL), value, ESCAPE_BACKSLASH));
      orPredicates.add(builder.like(builder.lower(from.get(FIRST_NAME)), value, ESCAPE_BACKSLASH));
      orPredicates.add(builder.like(builder.lower(from.get(LAST_NAME)), value, ESCAPE_BACKSLASH));
    }

    return orPredicates.toArray(Predicate[]::new);
  }

  /**
   * Returns the number of users that match the given criteria.
   * It can be called in three different ways.
   * 1. Don't specify any criteria and pass {@code null}. The number of all
   * users within that realm will be returned.
   * <p>
   * 2. If {@code search} is specified other criteria such as {@code last} will
   * be ignored even though you set them. The {@code search} string will be
   * matched against the first and last name, the username and the email of a
   * user.
   * <p>
   * 3. If {@code search} is unspecified but any of {@code last}, {@code first},
   * {@code email} or {@code username} those criteria are matched against their
   * respective fields on a user entity. Combined with a logical and.
   *
   * @param search        A String contained in username, first or last name, or
   *                      email. Default search behavior is prefix-based (e.g.,
   *                      <code>foo</code> or <code>foo*</code>). Use
   *                      <code>*foo*</code> for infix search and
   *                      <code>"foo"</code> for exact search.
   * @param last          A String contained in lastName, or the complete
   *                      lastName, if param "exact" is true
   * @param first         A String contained in firstName, or the complete
   *                      firstName, if param "exact" is true
   * @param email         A String contained in email, or the complete email, if
   *                      param "exact" is true
   * @param username      A String contained in username, or the complete
   *                      username, if param "exact" is true
   * @param emailVerified whether the email has been verified
   * @param idpAlias      The alias of an Identity Provider linked to the user
   * @param idpUserId     The userId at an Identity Provider linked to the user
   * @param enabled       Boolean representing if user is enabled or not
   * @param exact         Boolean which defines whether the params "last",
   *                      "first", "email" and "username" must match exactly
   * @param searchQuery   A query to search for custom attributes, in the format
   *                      'key1:value2 key2:value2'
   * @return the number of users that match the given criteria
   */
  @Path("/users/count")
  @GET
  @NoCache
  @Produces(MediaType.APPLICATION_JSON)
  @APIResponses(value = {
      @APIResponse(responseCode = "200", description = "OK", content = @Content(schema = @Schema(implementation = Integer.class))),
      @APIResponse(responseCode = "403", description = "Forbidden")
  })
  @Tag(name = KeycloakOpenAPI.Admin.Tags.USERS)
  @Operation(summary = "Returns the number of users that match the given criteria.", description = "It can be called in three different ways. "
      +
      "1. Don’t specify any criteria and pass {@code null}. The number of all users within that realm will be returned. <p> "
      +
      "2. If {@code search} is specified other criteria such as {@code last} will be ignored even though you set them. The {@code search} string will be matched against the first and last name, the username and the email of a user. <p> "
      +
      "3. If {@code search} is unspecified but any of {@code last}, {@code first}, {@code email} or {@code username} those criteria are matched against their respective fields on a user entity. Combined with a logical and.")
  public Integer getUsersCount(
      @Parameter(description = "A String contained in username, first or last name, or email. Default search behavior is prefix-based (e.g., foo or foo*). Use *foo* for infix search and \"foo\" for exact search.") @QueryParam("search") String search,
      @Parameter(description = "A String contained in lastName, or the complete lastName, if param \"exact\" is true") @QueryParam("lastName") String last,
      @Parameter(description = "A String contained in firstName, or the complete firstName, if param \"exact\" is true") @QueryParam("firstName") String first,
      @Parameter(description = "A String contained in email, or the complete email, if param \"exact\" is true") @QueryParam("email") String email,
      @Parameter(description = "A String contained in username, or the complete username, if param \"exact\" is true") @QueryParam("username") String username,
      @Parameter(description = "whether the email has been verified") @QueryParam("emailVerified") Boolean emailVerified,
      @Parameter(description = "The alias of an Identity Provider linked to the user") @QueryParam("idpAlias") String idpAlias,
      @Parameter(description = "The userId at an Identity Provider linked to the user") @QueryParam("idpUserId") String idpUserId,
      @Parameter(description = "Boolean representing if user is enabled or not") @QueryParam("enabled") Boolean enabled,
      @Parameter(description = "Boolean which defines whether the params \"last\", \"first\", \"email\" and \"username\" must match exactly") @QueryParam("exact") Boolean exact,
      @Parameter(description = "A query to search for custom attributes, in the format 'key1:value2 key2:value2'") @QueryParam("q") String searchQuery,
      @Parameter(description = "An array of groupIds to filter on") @QueryParam("groupIds") String groupIds) {
    UserPermissionEvaluator userPermissionEvaluator = auth.users();
    userPermissionEvaluator.requireQuery();

    Set<String> groupIdsSet = new HashSet<>();
    if (groupIds != null) {
      groupIdsSet.addAll(Arrays.asList(groupIds.split(",")));
    }

    Map<String, String> searchAttributes = searchQuery == null
        ? Collections.emptyMap()
        : SearchQueryUtils.getFields(searchQuery);
    if (search != null) {
      if (search.startsWith(SEARCH_ID_PARAMETER)) {
        UserModel userModel = session.users().getUserById(realm, search.substring(SEARCH_ID_PARAMETER.length()).trim());
        return userModel != null && userPermissionEvaluator.canView(userModel) ? 1 : 0;
      }

      Map<String, String> parameters = new HashMap<>();
      parameters.put(UserModel.SEARCH, search.trim());

      if (enabled != null) {
        parameters.put(UserModel.ENABLED, enabled.toString());
      }
      if (emailVerified != null) {
        parameters.put(UserModel.EMAIL_VERIFIED, emailVerified.toString());
      }
      // search /users equivalent to this doesn't include service-accounts so counting
      // shouldn't as well
      parameters.put(UserModel.INCLUDE_SERVICE_ACCOUNT, "false");
      if (userPermissionEvaluator.canView()) {
        return getUsersCount(realm, parameters, groupIdsSet);
      } else {
        if (Profile.isFeatureEnabled(Profile.Feature.ADMIN_FINE_GRAINED_AUTHZ)) {
          return session.users().getUsersCount(realm, parameters, auth.groups().getGroupIdsWithViewPermission());
        } else {
          return getUsersCount(realm, parameters, groupIdsSet);
        }
      }
    } else if (last != null || first != null || email != null || username != null || emailVerified != null
        || enabled != null || !searchAttributes.isEmpty()) {
      Map<String, String> parameters = new HashMap<>();
      if (last != null) {
        parameters.put(UserModel.LAST_NAME, last);
      }
      if (first != null) {
        parameters.put(UserModel.FIRST_NAME, first);
      }
      if (email != null) {
        parameters.put(UserModel.EMAIL, email);
      }
      if (username != null) {
        parameters.put(UserModel.USERNAME, username);
      }
      if (emailVerified != null) {
        parameters.put(UserModel.EMAIL_VERIFIED, emailVerified.toString());
      }
      if (idpAlias != null) {
        parameters.put(UserModel.IDP_ALIAS, idpAlias);
      }
      if (idpUserId != null) {
        parameters.put(UserModel.IDP_USER_ID, idpUserId);
      }
      if (enabled != null) {
        parameters.put(UserModel.ENABLED, enabled.toString());
      }
      if (exact != null) {
        parameters.put(UserModel.EXACT, exact.toString());
      }
      parameters.putAll(searchAttributes);
      parameters.put(UserModel.INCLUDE_SERVICE_ACCOUNT, "false");

      if (userPermissionEvaluator.canView()) {
        return getUsersCount(realm, parameters, groupIdsSet);
      } else {
        if (Profile.isFeatureEnabled(Profile.Feature.ADMIN_FINE_GRAINED_AUTHZ)) {
          return session.users().getUsersCount(realm, parameters, auth.groups().getGroupIdsWithViewPermission());
        } else {
          return getUsersCount(realm, parameters, groupIdsSet);
        }
      }
    } else {
      Map<String, String> parameters = new HashMap<>();
      // list /users equivalent to this doesn't include service-accounts so counting
      // shouldn't as well
      parameters.put(UserModel.INCLUDE_SERVICE_ACCOUNT, "false");
      if (userPermissionEvaluator.canView()) {
        return getUsersCount(realm, parameters, groupIdsSet);
      } else {
        if (Profile.isFeatureEnabled(Profile.Feature.ADMIN_FINE_GRAINED_AUTHZ)) {
          return session.users().getUsersCount(realm, parameters, auth.groups().getGroupIdsWithViewPermission());
        } else {
          return getUsersCount(realm, parameters, groupIdsSet);
        }
      }
    }
  }

  // Copied from JpaUserProvider. Added group filtering.
  @SuppressWarnings("unchecked")
  public int getUsersCount(RealmModel realm, Map<String, String> params, Set<String> groupIds) {
    EntityManager em = ((JpaUserProvider) session.getProvider(UserProvider.class)).getEntityManager();

    CriteriaBuilder cb = em.getCriteriaBuilder();

    CriteriaQuery<Long> countQuery = cb.createQuery(Long.class);
    Root<UserEntity> root = countQuery.from(UserEntity.class);
    countQuery.select(cb.countDistinct(root));

    List<Predicate> restrictions = predicates(params, root, Map.of());
    restrictions.add(cb.equal(root.get("realmId"), realm.getId()));

    if (groupIds != null && !groupIds.isEmpty()) {
      Join<UserEntity, UserGroupMembershipEntity> groupMembershipUserJoin = root.join(UserGroupMembershipEntity.class,
          JoinType.LEFT);
      groupMembershipUserJoin.on(cb.equal(groupMembershipUserJoin.get("user").get("id"), root.get("id")));
      Predicate groupPredicate = groupMembershipUserJoin.get("groupId").in(groupIds);

      restrictions.add(groupPredicate);
    }

    restrictions.addAll(AdminPermissionsSchema.SCHEMA.applyAuthorizationFilters(session, AdminPermissionsSchema.USERS,
        (JpaUserProvider) session.getProvider(UserProvider.class), realm, cb, countQuery, root));

    countQuery.where(restrictions.toArray(Predicate[]::new));
    TypedQuery<Long> query = em.createQuery(countQuery);
    Long result = query.getSingleResult();

    return result.intValue();
  }
}
