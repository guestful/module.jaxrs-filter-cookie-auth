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

import java.util.HashMap;
import java.util.Map;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class CookieAuthRealmConfigs {

    private final Map<String, CookieAuthRealmConfig> configs = new HashMap<>();

    public CookieAuthRealmConfigs add(CookieAuthRealmConfig config) {
        configs.put(config.getRealName(), config);
        return this;
    }

    public CookieAuthRealmConfig getConfig(String realmName) {
        CookieAuthRealmConfig config = configs.get(realmName);
        if (config == null) throw new IllegalArgumentException("Cookie Realm Config '" + realmName + "' not found.");
        return config;
    }
}
