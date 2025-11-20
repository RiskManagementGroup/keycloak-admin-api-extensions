package dk.rmgroup.keycloak.spi;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;

public class ApiExtensionsFactory implements AdminRealmResourceProviderFactory {
  static final String PROVIDER_ID = "api-extensions";

  @Override
  public AdminRealmResourceProvider create(KeycloakSession session) {
    return new ApiExtensions(session);
  }

  @Override
  public void init(Config.Scope config) {

  }

  @Override
  public void close() {

  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {

  }
}
