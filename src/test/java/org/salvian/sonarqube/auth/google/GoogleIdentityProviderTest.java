/*
 * Google Authentication for SonarQube
 * Copyright (C) 2016-2016 SonarSource SA
 * mailto:contact AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.salvian.sonarqube.auth.google;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.sonar.api.config.Settings;
import org.sonar.api.server.authentication.OAuth2IdentityProvider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class GoogleIdentityProviderTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  Settings settings = new Settings();

  GoogleSettings googleSettings = new GoogleSettings(settings);

  GoogleIdentityProvider underTest = new GoogleIdentityProvider(googleSettings);

  @Test
  public void check_fields() throws Exception {
    assertThat(underTest.getKey()).isEqualTo("google");
    assertThat(underTest.getName()).isEqualTo("Google");
    assertThat(underTest.getDisplay().getIconPath()).isEqualTo("/static/authgoogle/google.png");
    assertThat(underTest.getDisplay().getBackgroundColor()).isEqualTo("#444444");
  }

  @Test
  public void is_enabled() throws Exception {
    settings.setProperty(GoogleSettings.CLIENT_ID, "id");
    settings.setProperty(GoogleSettings.CLIENT_SECRET, "secret");
    settings.setProperty(GoogleSettings.REDIRECT_URI, "redirect");
    settings.setProperty(GoogleSettings.ENABLED, true);
    assertThat(underTest.isEnabled()).isTrue();

    settings.setProperty(GoogleSettings.ENABLED, false);
    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void init() throws Exception {
    setSettings(true);
    OAuth2IdentityProvider.InitContext context = mock(OAuth2IdentityProvider.InitContext.class);
    when(context.generateCsrfState()).thenReturn("state");
    when(context.getCallbackUrl()).thenReturn("http://localhost/callback");
    underTest.init(context);
    verify(context).redirectTo("https://accounts.google.com/o/oauth2/auth?access_type=offline&client_id=id&redirect_uri=redirect&response_type=code" +
            "&scope=email%20profile%20openid&state=state&hd=hd");
  }

  @Test
  public void fail_to_init_when_disabled() throws Exception {
    setSettings(false);
    OAuth2IdentityProvider.InitContext context = mock(OAuth2IdentityProvider.InitContext.class);

    thrown.expect(IllegalStateException.class);
    thrown.expectMessage("Google Authentication is disabled");
    underTest.init(context);
  }

  private void setSettings(boolean enabled) {
    if (enabled) {
      settings.setProperty(GoogleSettings.CLIENT_ID, "id");
      settings.setProperty(GoogleSettings.CLIENT_SECRET, "secret");
      settings.setProperty(GoogleSettings.HOSTED_DOMAIN, "hd");
      settings.setProperty(GoogleSettings.REDIRECT_URI, "redirect");
      settings.setProperty(GoogleSettings.ENABLED, true);
    } else {
      settings.setProperty(GoogleSettings.ENABLED, false);
    }
  }
}
