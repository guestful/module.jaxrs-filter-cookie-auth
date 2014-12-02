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

import com.guestful.jaxrs.security.cookie.auth.CookieAuthFeature;
import org.glassfish.hk2.api.Factory;
import org.glassfish.hk2.api.ServiceLocator;
import org.glassfish.hk2.api.TypeLiteral;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.server.internal.inject.AbstractValueFactoryProvider;
import org.glassfish.jersey.server.internal.inject.MultivaluedParameterExtractorProvider;
import org.glassfish.jersey.server.internal.inject.ParamInjectionResolver;
import org.glassfish.jersey.server.model.Parameter;
import org.glassfish.jersey.server.spi.internal.ValueFactoryProvider;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.ws.rs.core.Configurable;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class CookieAuthJerseyModule {

    public static CookieAuthFeature install(Configurable<?> c) {
        CookieAuthFeature cookieAuthFeature = new CookieAuthFeature();
        c.register(CookieAuthParamValueFactoryProvider.class, ValueFactoryProvider.class);
        c.register(new Binder());
        c.register(cookieAuthFeature);
        return cookieAuthFeature;
    }

    static class Binder extends AbstractBinder {

        @Override
        protected void configure() {
            bind(InjectionResolver.class)
                .to(new TypeLiteral<InjectionResolver<com.guestful.jaxrs.security.cookie.auth.CookieAuth>>() {
                })
                .in(Singleton.class);
        }

    }

    static final class InjectionResolver extends ParamInjectionResolver<com.guestful.jaxrs.security.cookie.auth.CookieAuth> {
        public InjectionResolver() {
            super(CookieAuthParamValueFactoryProvider.class);
        }
    }

    static final class CookieAuthParamValueFactoryProvider extends AbstractValueFactoryProvider {

        @Inject
        public CookieAuthParamValueFactoryProvider(final MultivaluedParameterExtractorProvider mpep,
                                                   final ServiceLocator locator) {
            super(mpep, locator, Parameter.Source.ENTITY, Parameter.Source.UNKNOWN);
        }

        @Override
        public PriorityType getPriority() {
            return Priority.HIGH;
        }

        @Override
        protected Factory<?> createValueFactory(Parameter parameter) {
            return null;
        }

    }
}