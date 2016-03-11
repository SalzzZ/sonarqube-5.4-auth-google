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

import org.junit.Test;
import org.sonar.api.config.Settings;

import static org.assertj.core.api.Assertions.assertThat;

public class GoogleSettingsTest {

  Settings settings = new Settings();

  GoogleSettings underTest = new GoogleSettings(settings);

  @Test
  public void is_enabled() throws Exception {
    settings.setProperty(GoogleSettings.CLIENT_ID, "id");
    settings.setProperty(GoogleSettings.CLIENT_SECRET, "secret");
    settings.setProperty(GoogleSettings.HOSTED_DOMAIN, "hd");
    settings.setProperty(GoogleSettings.REDIRECT_URI, "redirect");

    settings.setProperty(GoogleSettings.ENABLED, true);
    assertThat(underTest.isEnabled()).isTrue();

    settings.setProperty(GoogleSettings.ENABLED, false);
    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void is_enabled_always_return_false_when_client_id_is_null() throws Exception {
    settings.setProperty(GoogleSettings.ENABLED, true);
    settings.setProperty(GoogleSettings.CLIENT_ID, (String) null);
    settings.setProperty(GoogleSettings.CLIENT_SECRET, "secret");
    settings.setProperty(GoogleSettings.REDIRECT_URI, "redirect");

    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void is_enabled_always_return_false_when_client_secret_is_null() throws Exception {
    settings.setProperty(GoogleSettings.ENABLED, true);
    settings.setProperty(GoogleSettings.CLIENT_ID, "id");
    settings.setProperty(GoogleSettings.CLIENT_SECRET, (String) null);
    settings.setProperty(GoogleSettings.REDIRECT_URI, "redirect");

    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void is_enabled_always_return_false_when_redirect_uri_is_null() throws Exception {
    settings.setProperty(GoogleSettings.ENABLED, true);
    settings.setProperty(GoogleSettings.CLIENT_ID, "id");
    settings.setProperty(GoogleSettings.CLIENT_SECRET, "secret");
    settings.setProperty(GoogleSettings.REDIRECT_URI, (String)null);
    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void return_client_id() throws Exception {
    settings.setProperty(GoogleSettings.CLIENT_ID, "id");
    assertThat(underTest.clientId()).isEqualTo("id");
  }

  @Test
  public void return_client_secret() throws Exception {
    settings.setProperty(GoogleSettings.CLIENT_SECRET, "secret");
    assertThat(underTest.clientSecret()).isEqualTo("secret");
  }

  @Test
  public void return_hosted_domain() throws Exception {
    settings.setProperty(GoogleSettings.HOSTED_DOMAIN, "hd");
    assertThat(underTest.hostedDomain()).isEqualTo("hd");
  }

  @Test
  public void allow_users_to_sign_up() throws Exception {
    settings.setProperty(GoogleSettings.ALLOW_USERS_TO_SIGN_UP, "true");
    assertThat(underTest.allowUsersToSignUp()).isTrue();

    settings.setProperty(GoogleSettings.ALLOW_USERS_TO_SIGN_UP, "false");
    assertThat(underTest.allowUsersToSignUp()).isFalse();
  }

  @Test
  public void definitions() throws Exception {
    assertThat(GoogleSettings.definitions()).hasSize(6);
  }
}
