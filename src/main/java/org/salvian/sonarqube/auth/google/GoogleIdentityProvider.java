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
import org.sonar.api.server.authentication.UserIdentity;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Arrays;

@ServerSide
public class GoogleIdentityProvider implements OAuth2IdentityProvider {

    private final GoogleSettings settings;

    public GoogleIdentityProvider(GoogleSettings settings) {
        this.settings = settings;
    }

    @Override
    public String getKey() {
        return "google";
    }

    @Override
    public String getName() {
        return "Google OAuth2";
    }

    @Override
    public Display getDisplay() {
        return Display.builder()
                // URL of src/main/resources/static/google.svg at runtime
                .setIconPath("/static/authgoogle/google.svg")
                .setBackgroundColor("#000000")
                .build();
    }

    @Override
    public boolean isEnabled() {
        return settings.isEnabled();
    }

    @Override
    public boolean allowsUsersToSignUp() {
        return settings.allowUsersToSignUp();
    }

    @Override
    public void init(InitContext context) {
        String state = context.generateCsrfState();
        if (!isEnabled()) {
            throw new IllegalStateException("Google Authentication is disabled");
        }
        String url = new GoogleAuthorizationCodeRequestUrl(settings.clientId(), settings.redirectUri(), Arrays.asList(
                "email", "profile", "openid")).setState(state)
                .setAccessType("offline").set("hd", settings.hostedDomain())
                .build();
        context.redirectTo(url);
    }

    @Override
    public void callback(CallbackContext context) {
        context.verifyCsrfState();
        HttpServletRequest request = context.getRequest();
        String code = null;
        try {
            code = request.getParameter("code");
        } catch (NullPointerException e) {
            throw new IllegalStateException("Authorization Code Fail", e);
        }
        JsonFactory jsonFactory = new JacksonFactory();
        GoogleTokenResponse tokenResponse = null;
        try {
            tokenResponse = new GoogleAuthorizationCodeTokenRequest(new NetHttpTransport(), jsonFactory, settings.clientId(), settings.clientSecret(), code, settings.redirectUri()).execute();
        } catch (IOException e) {
            throw new IllegalStateException("Authorization Token Fail", e);
        }
        GoogleIdToken googleIdToken;
        String idToken = tokenResponse.getIdToken();
        try {
            googleIdToken = GoogleIdToken.parse(jsonFactory, idToken);
        } catch (IOException e) {
            throw new IllegalStateException("ID Token Fail", e);
        }
        String email = googleIdToken.getPayload().getEmail();
        UserIdentity userIdentity = UserIdentity.builder()
                .setProviderLogin(email.substring(0, email.indexOf('@')))
                .setLogin(email.substring(0, email.indexOf('@')))
                .setName(email.substring(0, email.indexOf('@')))
                .setEmail(email)
                .build();
        context.authenticate(userIdentity);
        context.redirectToRequestedPage();
    }

}
