package dk.rmgroup.keycloak.spi;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

public class ApiExtensions implements AdminRealmResourceProvider {
  private final KeycloakSession keycloakSession;

  public ApiExtensions(KeycloakSession keycloakSession) {
    this.keycloakSession = keycloakSession;
  }

  @Override
  public void close() {
  }

  @Override
  public Object getResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth,
      AdminEventBuilder adminEvent) {
    return new ApiExtensionsResource(keycloakSession, realm, auth, adminEvent);
  }
}
