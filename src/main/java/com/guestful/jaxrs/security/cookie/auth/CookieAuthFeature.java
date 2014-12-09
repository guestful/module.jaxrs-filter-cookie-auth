/**
 * Copyright (C) 2013 Guestful (info@guestful.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.guestful.jaxrs.security.cookie.auth;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.json.Json;
import javax.json.JsonObject;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.*;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.io.StringReader;
import java.security.Principal;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class CookieAuthFeature implements DynamicFeature, Feature {

    private static final Logger LOGGER = Logger.getLogger(CookieAuthFeature.class.getName());
    private static final Date EXPIRED = new Date(System.currentTimeMillis() - 604800000);

    @Inject CookieAuthRealmConfigs configs;
    @Inject CookieAuthorizer cookieAuthorizer;

    @Override
    public boolean configure(FeatureContext context) {
        //TODO: bind
        return true;
    }

    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext context) {
        CookieAuth cookieAuth = resourceInfo.getResourceMethod().getAnnotation(CookieAuth.class);
        if (cookieAuth == null) {
            cookieAuth = resourceInfo.getResourceClass().getAnnotation(CookieAuth.class);
        }
        if (cookieAuth != null) {
            CookieAuthRealmConfig config = configs.getConfig(cookieAuth.realm());
            context.register(new CookieAuthFilter(config, cookieAuth));
        }
    }

    @Priority(Priorities.AUTHENTICATION)
    public class CookieAuthFilter implements ContainerRequestFilter, ContainerResponseFilter {

        private final CookieAuthRealmConfig config;
        private final CookieAuth cookieAuth;

        public CookieAuthFilter(CookieAuthRealmConfig config, CookieAuth cookieAuth) {
            this.config = config;
            this.cookieAuth = cookieAuth;
        }

        @Override
        public void filter(ContainerRequestContext requestContext) throws IOException {
            Cookie cookie = requestContext.getCookies().get(config.getCookieName());
            Principal principal = null;
            if (cookie == null && !cookieAuth.optional()) {
                throw new NotAuthorizedException("Missing authentication token", "GBASICAUTH realm=\"" + requestContext.getUriInfo().getBaseUri() + "\"");
            } else if (cookie != null) {
                JsonObject object = decrypt(cookie.getValue());
                // expiration check
                long time = object.getJsonNumber("t").longValue();
                if (time + config.getCookieMaxAge() * 1000 <= System.currentTimeMillis()) {
                    throw new NotAuthorizedException("Expired authentication token", "GBASICAUTH realm=\"" + requestContext.getUriInfo().getBaseUri() + "\"");
                }
                principal = new NamedPrincipal(object.getString("p"));
                if(!cookieAuthorizer.isAuthorized(principal, cookieAuth)) {
                    throw new NotAuthorizedException("Not authorized", "GBASICAUTH realm=\"" + requestContext.getUriInfo().getBaseUri() + "\"");
                }
            }
            CookieSubject cookieSubject = new CookieSubject(principal);
            requestContext.setProperty(CookieSubject.class.getName() + "." + cookieAuth.realm(), cookieSubject);
        }

        @Override
        public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {
            CookieSubject cookieSubject = (CookieSubject) requestContext.getProperty(CookieSubject.class.getName() + "." + cookieAuth.realm());

            if (cookieSubject != null) {

                requestContext.removeProperty(CookieSubject.class.getName() + "." + cookieAuth.realm());

                if (!cookieSubject.isAnonymous()) {
                    responseContext.getHeaders().add(HttpHeaders.SET_COOKIE, new NewCookie(
                            config.getCookieName(),
                            encrypt(cookieSubject.getPrincipal()),
                            config.getCookiePath(),
                            config.getCookieDomain(),
                            null,
                            config.getCookieMaxAge(),
                            false,
                            true)
                    );
                }

                Cookie cookie = requestContext.getCookies().get(config.getCookieName());
                if (cookie != null && !responseContext.getCookies().containsKey(cookie.getName())) {
                    responseContext.getHeaders().addFirst(HttpHeaders.SET_COOKIE, new NewCookie(
                        cookie.getName(),
                        "delete",
                        config.getCookiePath(),
                        config.getCookieDomain(),
                        cookie.getVersion(),
                        null,
                        0,
                        EXPIRED,
                        false,
                        true));
                }
            }
        }

        private String encrypt(Principal principal) {
            String val = Json.createObjectBuilder()
                .add("u", principal.getName())
                .add("t", System.currentTimeMillis())
                .build()
                .toString();

            return ;
        }

        private JsonObject decrypt(String cookieValue) {
            try {
                String val = ;
                JsonObject object = Json.createReader(new StringReader(val)).readObject();
                object.getInt("t");
                object.getString("u");
                return object;
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Unable to decrypt cookie value: " + cookieValue, e);
                return null;
            }
        }

    }

}
