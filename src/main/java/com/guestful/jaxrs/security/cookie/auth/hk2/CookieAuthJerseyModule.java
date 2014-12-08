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
package com.guestful.jaxrs.security.cookie.auth.hk2;

import com.guestful.jaxrs.security.cookie.auth.*;
import org.glassfish.hk2.api.Factory;
import org.glassfish.hk2.api.InjectionResolver;
import org.glassfish.hk2.api.ServiceLocator;
import org.glassfish.hk2.api.TypeLiteral;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.internal.inject.AbstractContainerRequestValueFactory;
import org.glassfish.jersey.server.internal.inject.AbstractValueFactoryProvider;
import org.glassfish.jersey.server.internal.inject.MultivaluedParameterExtractorProvider;
import org.glassfish.jersey.server.internal.inject.ParamInjectionResolver;
import org.glassfish.jersey.server.model.Parameter;
import org.glassfish.jersey.server.spi.internal.ValueFactoryProvider;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.Configurable;
import javax.ws.rs.core.Cookie;
import java.math.BigInteger;
import java.security.Principal;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class CookieAuthJerseyModule {

    public static CookieAuthRealmConfigs install(Configurable<?> c) {
        CookieAuthRealmConfigs configs = new CookieAuthRealmConfigs();
        c.register(new CookieAuthBinder(configs));
        c.register(CookieAuthValueFactoryProvider.class, ValueFactoryProvider.class);
        c.register(CookieAuthFeature.class);
        return configs;
    }

    static class CookieAuthBinder extends AbstractBinder {
        private final CookieAuthRealmConfigs configs;

        public CookieAuthBinder(CookieAuthRealmConfigs configs) {
            this.configs = configs;
        }

        @Override
        protected void configure() {
            bind(configs);
            bind(CookieAuthInjectionResolver.class)
                .to(new TypeLiteral<InjectionResolver<CookieAuth>>() {
                }).in(Singleton.class);
        }

    }

    static final class CookieAuthInjectionResolver extends ParamInjectionResolver<com.guestful.jaxrs.security.cookie.auth.CookieAuth> {
        CookieAuthInjectionResolver() {
            super(CookieAuthValueFactoryProvider.class);
        }
    }

    static final class CookieAuthValueFactoryProvider extends AbstractValueFactoryProvider {

        private final CookieAuthRealmConfigs configs;

        @Inject
        CookieAuthValueFactoryProvider(MultivaluedParameterExtractorProvider mpep,
                                       ServiceLocator locator,
                                       CookieAuthRealmConfigs configs) {
            super(mpep, locator, Parameter.Source.ENTITY, Parameter.Source.UNKNOWN);
            this.configs = configs;
        }

        @Override
        public PriorityType getPriority() {
            return Priority.HIGH;
        }

        @Override
        protected Factory<?> createValueFactory(Parameter parameter) {
            if (parameter.getSourceAnnotation().annotationType() != CookieAuth.class) return null;
            if (!CookieSubject.class.isAssignableFrom(parameter.getRawType())) return null;
            CookieAuth cookieAuth = (CookieAuth) parameter.getSourceAnnotation();
            if (cookieAuth.realm().length() == 0) return null;
            return new CookieAuthParamValueFactory(configs, cookieAuth);
        }
    }

    static final class CookieAuthParamValueFactory extends AbstractContainerRequestValueFactory<CookieSubject> {

        private final CookieAuthRealmConfigs configs;
        private final CookieAuth cookieAuth;

        CookieAuthParamValueFactory(CookieAuthRealmConfigs configs, CookieAuth cookieAuth) {
            this.configs = configs;
            this.cookieAuth = cookieAuth;
        }

        @Override
        public CookieSubject provide() {
            ContainerRequest request = getContainerRequest();
            CookieAuthRealmConfig config = configs.getConfig(cookieAuth.realm());
            Cookie cookie = request.getCookies().get(config.getCookieName());
            Principal principal = null;

            if(cookie == null && !cookieAuth.optional()) {
                throw new NotAuthorizedException("Guest not authenticated", "BASICAUTH realm=\"" + request.getBaseUri() + "\"");

            } else if(cookie != null) {
                String encr = cookie.getValue();

            }

            CookieSubject cookieSubject = new CookieSubject(principal);

            return cookieSubject;
        }

    }

    public static void main(String[] args) {
        String s = "Dk_0YMqYt8ZszESJoDl0ig";
        BigInteger bi = new BigInteger(s.getBytes());
        BigInteger key = new BigInteger();
        bi.xor()
    }

}
