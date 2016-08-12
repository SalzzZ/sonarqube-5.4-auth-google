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
package com.traveloka.sonarqube.plugin;

import org.sonar.api.config.PropertyDefinition;
import org.sonar.api.config.Settings;
import org.sonar.api.server.ServerSide;

import javax.annotation.CheckForNull;
import java.util.Arrays;
import java.util.List;

import static java.lang.String.valueOf;
import static org.sonar.api.PropertyType.BOOLEAN;
import static org.sonar.api.PropertyType.PASSWORD;
import static org.sonar.api.PropertyType.STRING;

@ServerSide
public class GoogleSettings {

    public static final String ENABLED = "sonar.auth.google.enabled";
    public static final String CLIENT_ID = "sonar.auth.google.clientId";
    public static final String CLIENT_SECRET = "sonar.auth.google.clientSecret.secured";
    public static final String REDIRECT_URI = "sonar.auth.google.redirectUri";
    public static final String ALLOW_USERS_TO_SIGN_UP = "sonar.auth.google.allowUsersToSignUp";
    public static final String HOSTED_DOMAIN = "sonar.auth.google.hostedDomain";
    public static final String CATEGORY = "google";
    public static final String SUBCATEGORY = "authentication";

    private final Settings settings;

    public GoogleSettings(Settings settings) {
        this.settings = settings;
    }

    public static List<PropertyDefinition> definitions() {
        return Arrays.asList(
                PropertyDefinition.builder(ENABLED)
                        .name("Enabled")
                        .description("Enable Google users to login. Value is ignored if client ID and secret are not defined.")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(BOOLEAN)
                        .defaultValue(valueOf(false))
                        .index(1)
                        .build(),
                PropertyDefinition.builder(CLIENT_ID)
                        .name("Client ID")
                        .description("Client ID provided by Google when registering the application.")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .index(2)
                        .type(STRING)
                        .build(),
                PropertyDefinition.builder(CLIENT_SECRET)
                        .name("Client Secret")
                        .description("Client password provided by Google when registering the application.")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .index(3)
                        .type(PASSWORD)
                        .build(),
                PropertyDefinition.builder(REDIRECT_URI)
                        .name("Redirect URI")
                        .description("Oauth2 Redirection URI for this SonarQube Instance")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .index(4)
                        .type(STRING)
                        .build(),
                PropertyDefinition.builder(ALLOW_USERS_TO_SIGN_UP)
                        .name("Allow users to sign-up")
                        .description("Allow new users to authenticate. When set to 'false', only existing users will be able to authenticate to the server.")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(BOOLEAN)
                        .defaultValue(valueOf(true))
                        .index(5)
                        .build(),
                PropertyDefinition.builder(HOSTED_DOMAIN)
                        .name("Hosted Domain")
                        .description("Google Oauth2 Hosted Domain (https://developers.google.com/identity/protocols/OpenIDConnect#authenticationuriparameters)")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .index(6)
                        .type(STRING)
                        .build()
        );
    }

    public String clientId() {
        return settings.getString(CLIENT_ID);
    }

    public String clientSecret() {
        return settings.getString(CLIENT_SECRET);
    }

    public String redirectUri() {
        return settings.getString(REDIRECT_URI);
    }

    public boolean isEnabled() {
        return settings.getBoolean(ENABLED) && clientId() != null && clientSecret() != null && redirectUri() != null;
    }

    public boolean allowUsersToSignUp() {
        return settings.getBoolean(ALLOW_USERS_TO_SIGN_UP);
    }

    @CheckForNull
    public String hostedDomain() {
        return settings.getString(HOSTED_DOMAIN);
    }
}
