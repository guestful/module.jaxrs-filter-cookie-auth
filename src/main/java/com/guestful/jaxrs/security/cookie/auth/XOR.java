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

import javax.xml.bind.DatatypeConverter;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
class XOR {

    private final byte[] key;

    private XOR(byte[] key) {
        this.key = key;
    }

    public byte[] getKey() {
        return Arrays.copyOf(key, key.length);
    }

    public String getKeyHex() {
        return DatatypeConverter.printHexBinary(key);
    }

    public long getBitLength() {
        return key.length * 8;
    }

    public long getByteLength() {
        return key.length;
    }

    public void xor(byte[] data) {
        if (data.length != key.length) {
            throw new IllegalArgumentException("Unable to encrypt: not same length (" + key.length + " bytes)");
        }
        for (int i = 0; i < key.length; i++) {
            data[i] = (byte) (data[i] ^ key[i]);
        }
    }

    public String xor(String hex) {
        byte[] bytes = DatatypeConverter.parseHexBinary(hex);
        xor(bytes);
        return DatatypeConverter.printHexBinary(bytes);
    }

    public static XOR newInstance(int keyByteLength) {
        return new XOR(PRNG.gen(keyByteLength));
    }

    public static XOR newInstance(byte[] key) {
        return new XOR(key);
    }

    public static XOR newInstance(String hexKey) {
        return new XOR(DatatypeConverter.parseHexBinary(hexKey));
    }

    // lazy-singleton-instanciation of PRNG
    private static final class PRNG {
        private static SecureRandom secureRandom = new SecureRandom();

        static String genHex(int byteLength) {
            return DatatypeConverter.printHexBinary(gen(byteLength));
        }

        static byte[] gen(int byteLength) {
            byte[] key = new byte[byteLength];
            secureRandom.nextBytes(key);
            return key;
        }
    }

    // just to test
    public static void main(String[] args) throws Exception {
        XOR xor = XOR.newInstance(22);
        XOR b64xor = XOR.newInstance(16);

        String data = "n0URmCU1_KkkygLn9-1wlQ";
        System.out.println(data.length() + " " + data);

        System.out.println("b64");

        byte[] b64 = Base64.getUrlDecoder().decode(data);
        System.out.println(b64.length + " " + DatatypeConverter.printHexBinary(b64));

        b64xor.xor(b64);
        System.out.println(b64.length + " " + DatatypeConverter.printHexBinary(b64));

        b64xor.xor(b64);
        System.out.println(b64.length + " " + DatatypeConverter.printHexBinary(b64));

        System.out.println("ascii");

        byte[] ascii = data.getBytes("ASCII");
        System.out.println(ascii.length + " " + DatatypeConverter.printHexBinary(ascii));

        xor.xor(ascii);
        System.out.println(ascii.length + " " + DatatypeConverter.printHexBinary(ascii));

        xor.xor(ascii);
        System.out.println(ascii.length + " " + DatatypeConverter.printHexBinary(ascii));
    }

}
