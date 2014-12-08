package com.guestful.jaxrs.security.cookie.auth;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class CookieAuthRealmConfigs {

    private final Map<String, CookieAuthRealmConfig> configs = new HashMap<>();

    public CookieAuthRealmConfigs addConfig(String realmName, CookieAuthRealmConfig config) {
        configs.put(realmName, config);
        return this;
    }

    public CookieAuthRealmConfig getConfig(String realmName) {
        CookieAuthRealmConfig config = configs.get(realmName);
        if (config == null) throw new IllegalArgumentException("Cookie Realm Config '" + realmName + "' not found.");
        return config;
    }
}
