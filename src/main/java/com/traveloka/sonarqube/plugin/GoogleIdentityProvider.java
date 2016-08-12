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

import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.sonar.api.server.ServerSide;
import org.sonar.api.server.authentication.Display;
import org.sonar.api.server.authentication.OAuth2IdentityProvider;
import org.sonar.api.server.authentication.UnauthorizedException;
import org.sonar.api.server.authentication.UserIdentity;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Arrays;

@ServerSide
public class GoogleIdentityProvider implements OAuth2IdentityProvider {

    private static final Logger LOGGER = Loggers.get(GoogleIdentityProvider.class);
    private final GoogleSettings settings;

    public GoogleIdentityProvider(GoogleSettings settings) {
        this.settings = settings;
    }


    public String getKey() {
        return "google";
    }

    public String getName() {
        return "Google";
    }

    public Display getDisplay() {
        return Display.builder()
                // URL of src/main/resources/static/google.png at runtime
                .setIconPath("/static/authgoogle/google.png")
                .setBackgroundColor("#444444")
                .build();
    }

    public boolean isEnabled() {
        return settings.isEnabled();
    }

    public boolean allowsUsersToSignUp() {
        return settings.allowUsersToSignUp();
    }

    public void init(InitContext context) {
        String state = context.generateCsrfState();
        context.getRequest();
        if (!isEnabled()) {
            throw new IllegalStateException("Google Authentication is disabled");
        }
        String url = new GoogleAuthorizationCodeRequestUrl(settings.clientId(), settings.redirectUri(), Arrays.asList(
                "email", "profile", "openid")).setState(state)
                .setAccessType("offline").set("hd", settings.hostedDomain())
                .build();
        context.redirectTo(url);
    }

    public void callback(CallbackContext context) {
        context.verifyCsrfState();
        HttpServletRequest request = context.getRequest();
        String code = request.getParameter("code");
        JsonFactory jsonFactory = new JacksonFactory();
        GoogleTokenResponse tokenResponse;
        try {
            tokenResponse = new GoogleAuthorizationCodeTokenRequest(new NetHttpTransport(), jsonFactory, settings.clientId(), settings.clientSecret(), code, settings.redirectUri()).execute();
        } catch (IOException e) {
            LOGGER.info("Authorization Code Fail", e);
            return;
        }
        GoogleIdToken googleIdToken;
        String idToken = tokenResponse.getIdToken();
        try {
            googleIdToken = GoogleIdToken.parse(jsonFactory, idToken);
        } catch (IOException e) {
            LOGGER.info("ID Token Fail", e);
            return;
        }
        if (!googleIdToken.getPayload().getHostedDomain().equals(settings.hostedDomain()) || !googleIdToken.getPayload().getEmailVerified())
            throw new UnauthorizedException("You must be a verified member of traveloka");
        String email = googleIdToken.getPayload().getEmail();
        String userName = email.substring(0, email.indexOf('@'));
        UserIdentity userIdentity = UserIdentity.builder()
                .setProviderLogin(userName)
                .setLogin(userName)
                .setName(userName)
                .setEmail(googleIdToken.getPayload().getEmail())
                .build();
        context.authenticate(userIdentity);
        context.redirectToRequestedPage();
    }

}
