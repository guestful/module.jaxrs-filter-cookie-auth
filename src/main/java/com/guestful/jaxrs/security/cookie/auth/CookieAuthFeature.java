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

import org.glassfish.hk2.utilities.binding.AbstractBinder;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.*;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Principal;
import java.util.Base64;
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
        context.register(new Binder());
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

    public class Binder extends AbstractBinder {
        @Override
        protected void configure() {
            bindFactory(CookieSubjectFactory.class)
                .to(CookieSubject.class)
                .proxy(false);
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
                StoredPrincipal storedPrincipal = StoredPrincipal.decrypt(config.getEncryptionKey(), cookie.getValue());
                if (storedPrincipal != null) {
                    LOGGER.log(Level.FINEST, "Stored Principal: " + storedPrincipal.principal);
                    // expiration check;
                    if (storedPrincipal.expired(config.getCookieMaxAge())) {
                        LOGGER.log(Level.FINEST, "Stored Principal expired: " + storedPrincipal.principal);
                        if (!cookieAuth.optional()) {
                            throw new NotAuthorizedException("Expired authentication token", "GBASICAUTH realm=\"" + requestContext.getUriInfo().getBaseUri() + "\"");
                        }
                    } else {
                        // authz check
                        if (!cookieAuthorizer.isAuthorized(storedPrincipal.principal, cookieAuth)) {
                            LOGGER.log(Level.FINEST, "Stored Principal not authroized: " + storedPrincipal.principal);
                            if (!cookieAuth.optional()) {
                                throw new NotAuthorizedException("Not authorized", "GBASICAUTH realm=\"" + requestContext.getUriInfo().getBaseUri() + "\"");
                            }
                        } else {
                            // expiration and authz checks passed
                            principal = storedPrincipal.principal;
                        }
                    }

                }
            }
            CookieSubject cookieSubject = new CookieSubject(principal);
            requestContext.setProperty(CookieSubject.class.getName(), cookieSubject);
        }

        @Override
        public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {
            CookieSubject cookieSubject = (CookieSubject) requestContext.getProperty(CookieSubject.class.getName());

            if (cookieSubject != null) {

                requestContext.removeProperty(CookieSubject.class.getName());

                if (!cookieSubject.isAnonymous()) {
                    responseContext.getHeaders().add(HttpHeaders.SET_COOKIE, new NewCookie(
                            config.getCookieName(),
                            StoredPrincipal.store(cookieSubject.getPrincipal()).encrypt(config.getEncryptionKey()),
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

    }

    static class StoredPrincipal {

        final Principal principal;
        final long time;

        private StoredPrincipal(Principal principal, long time) {
            this.principal = principal;
            this.time = time;
        }

        boolean expired(int maxAgeSec) {
            return time + maxAgeSec * 1000 <= System.currentTimeMillis();
        }

        String encrypt(String encryptionKey) {
            try {
                ByteBuffer bb = ByteBuffer.allocate(24);
                bb.putLong(time);
                bb.put(Base64.getUrlDecoder().decode(principal.getName()));
                XOR.newInstance(encryptionKey).xor(bb.array());
                return Base64.getUrlEncoder().encodeToString(bb.array()).replace("=", "");
            } catch (Exception e) {
                throw new IllegalArgumentException("Unable to encrypt principal " + principal, e);
            }
        }

        static StoredPrincipal store(Principal principal) {
            return new StoredPrincipal(principal, System.currentTimeMillis());
        }

        static StoredPrincipal decrypt(String encryptionKey, String cookieValue) {
            try {
                ByteBuffer bb = ByteBuffer.wrap(Base64.getUrlDecoder().decode(cookieValue));
                if (bb.array().length != 24) {
                    throw new IllegalStateException("bad length: " + bb.array().length);
                }
                XOR.newInstance(encryptionKey).xor(bb.array());
                long time = bb.getLong();
                byte[] principal = new byte[16];
                bb.get(principal);
                String id = Base64.getUrlEncoder().encodeToString(principal).replace("=", "");
                return new StoredPrincipal(new NamedPrincipal(id), time);
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Unable to decrypt cookie value: " + cookieValue, e);
                return null;
            }
        }

    }

    public static void main(String[] args) {
        String key = "6E3055526D4355315F4B6B6B79674C6E392D31776C517095";

        String id = "n0URmCU1_KkkygLn9-1wlQ";

        StoredPrincipal storedPrincipal = StoredPrincipal.store(new NamedPrincipal(id));
        System.out.println(storedPrincipal.principal);
        System.out.println(storedPrincipal.time);

        String encr = storedPrincipal.encrypt(key);
        System.out.println(encr);

        StoredPrincipal decr = StoredPrincipal.decrypt(key, encr);
        System.out.println(decr.principal);
        System.out.println(decr.time);
    }

}
