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

import com.guestful.jaxrs.security.cookie.auth.CookieAuth;
import com.guestful.jaxrs.security.cookie.auth.CookieAuthFeature;
import com.guestful.jaxrs.security.cookie.auth.CookieSubject;
import org.glassfish.hk2.api.Factory;
import org.glassfish.hk2.api.InjectionResolver;
import org.glassfish.hk2.api.ServiceLocator;
import org.glassfish.hk2.api.TypeLiteral;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.internal.util.collection.MultivaluedStringMap;
import org.glassfish.jersey.message.MessageBodyWorkers;
import org.glassfish.jersey.message.MessageUtils;
import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.internal.inject.*;
import org.glassfish.jersey.server.model.Parameter;
import org.glassfish.jersey.server.spi.internal.ValueFactoryProvider;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.ws.rs.core.Configurable;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class CookieAuthJerseyModule {

    public static CookieAuthFeature install(Configurable<?> c) {
        CookieAuthFeature cookieAuthFeature = new CookieAuthFeature();
        c.register(CookieAuthValueFactoryProvider.class, ValueFactoryProvider.class);
        c.register(new CookieAuthBinder());
        c.register(cookieAuthFeature);
        return cookieAuthFeature;
    }

    static class CookieAuthBinder extends AbstractBinder {
        @Override
        protected void configure() {
            bind(CookieAuthInjectionResolver.class)
                .to(new TypeLiteral<InjectionResolver<CookieAuth>>() {
                })
                .in(Singleton.class);

        }

    }

    static final class CookieAuthInjectionResolver extends ParamInjectionResolver<com.guestful.jaxrs.security.cookie.auth.CookieAuth> {
        CookieAuthInjectionResolver() {
            super(CookieAuthValueFactoryProvider.class);
        }
    }

    static final class CookieAuthValueFactoryProvider extends AbstractValueFactoryProvider {

        @Inject
        CookieAuthValueFactoryProvider(final MultivaluedParameterExtractorProvider mpep,
                                              final ServiceLocator locator) {
            super(mpep, locator, Parameter.Source.ENTITY, Parameter.Source.UNKNOWN);
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
            return new CookieAuthParamValueFactory(cookieAuth);
        }
    }

    static final class CookieAuthParamValueFactory extends AbstractContainerRequestValueFactory<CookieSubject> {

        private final CookieAuth cookieAuth;

        CookieAuthParamValueFactory(CookieAuth cookieAuth) {
            this.cookieAuth = cookieAuth;
        }

        @Override
        public CookieSubject provide() {



            // Return the field value for the field specified by the sourceName property.
            final ContainerRequest request = getContainerRequest();
            final FormDataMultiPart formDataMultiPart = getEntity(request);

            final List<FormDataBodyPart> formDataBodyParts = formDataMultiPart.getFields(parameter.getSourceName());
            final FormDataBodyPart formDataBodyPart = (formDataBodyParts != null) ? formDataBodyParts.get(0) : null;

            MediaType mediaType = (formDataBodyPart != null) ? formDataBodyPart.getMediaType() : MediaType.TEXT_PLAIN_TYPE;

            final MessageBodyWorkers messageBodyWorkers = request.getWorkers();

            MessageBodyReader reader = messageBodyWorkers.getMessageBodyReader(
                    parameter.getRawType(),
                    parameter.getType(),
                    parameter.getAnnotations(),
                    mediaType);

            if (reader != null && !isPrimitiveType(parameter.getRawType())) {
                final InputStream in;
                if (formDataBodyPart == null) {
                    if (parameter.getDefaultValue() != null) {
                        // Convert default value to bytes.
                        in = new ByteArrayInputStream(parameter.getDefaultValue().getBytes(MessageUtils.getCharset(mediaType)));
                    } else {
                        return null;
                    }
                } else {
                    in = ((BodyPartEntity) formDataBodyPart.getEntity()).getInputStream();
                }


                try {
                    //noinspection unchecked
                    return reader.readFrom(
                            parameter.getRawType(),
                            parameter.getType(),
                            parameter.getAnnotations(),
                            mediaType,
                            request.getHeaders(),
                            in);
                } catch (final IOException e) {
                    throw new FormDataParamException(e, parameter.getSourceName(), parameter.getDefaultValue());
                }
            } else if (extractor != null) {
                final MultivaluedMap<String, String> map = new MultivaluedStringMap();
                try {
                    if (formDataBodyPart != null) {
                        for (final FormDataBodyPart p : formDataBodyParts) {
                            mediaType = p.getMediaType();

                            reader = messageBodyWorkers.getMessageBodyReader(
                                    String.class,
                                    String.class,
                                    parameter.getAnnotations(),
                                    mediaType);

                            @SuppressWarnings("unchecked") final String value = (String) reader.readFrom(
                                    String.class,
                                    String.class,
                                    parameter.getAnnotations(),
                                    mediaType,
                                    request.getHeaders(),
                                    ((BodyPartEntity) p.getEntity()).getInputStream());

                            map.add(parameter.getSourceName(), value);
                        }
                    }
                    return extractor.extract(map);
                } catch (final IOException | ExtractorException ex) {
                    throw new FormDataParamException(ex, extractor.getName(), extractor.getDefaultValueString());
                }
            }
            return null;
        }

    }
}