/*
 * Copyright 2013 Swedish E-identification Board (E-legitimationsnämnden)
 *  		 
 *   Licensed under the EUPL, Version 1.1 or ñ as soon they will be approved by the 
 *   European Commission - subsequent versions of the EUPL (the "Licence");
 *   You may not use this work except in compliance with the Licence. 
 *   You may obtain a copy of the Licence at:
 * 
 *   http://joinup.ec.europa.eu/software/page/eupl 
 * 
 *   Unless required by applicable law or agreed to in writing, software distributed 
 *   under the Licence is distributed on an "AS IS" basis,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or 
 *   implied.
 *   See the Licence for the specific language governing permissions and limitations 
 *   under the Licence.
 */
package com.aaasec.sigserv.sigserver;

import com.aaasec.sigserv.cscommon.Base64Coder;
import com.aaasec.sigserv.cscommon.URLDecoder;
import com.aaasec.sigserv.cscommon.data.AuthData;
import com.aaasec.sigserv.cssigapp.models.RequestModel;
import com.google.gson.Gson;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Test identities for the dev mode IdP.
 */
public class TestSigIdentities {

    private static final Logger LOG = Logger.getLogger(TestSigIdentities.class.getName());
    private static String[][] testIdentities = new String[][]{
        new String[]{
            "Nils Pärsson",
            "https://idp-test.nordu.net/idp/shibboleth",
            "196501020000",
            "personalIdentityNumber",
            "nils.parsson@example.com"
        },
        new String[]{
            "Åke Östergård",
            "https://idp.kirei.se/saml2/idp/metadata.php",
            "196501021111",
            "personalIdentityNumber",
            "ake.ostergard@example.com"
        },
        new String[]{
            "Diana Bengtsson",
            "https://eidm.demo.ubisecure.com/uas",
            "196501022222",
            "personalIdentityNumber",
            "diana.bengtsson@example.com"
        },
        new String[]{
            "Guran Gustavsson",
            "https://idp-test.nordu.net/idp/shibboleth",
            "196501023333",
            "personalIdentityNumber",
            "guran.gustavsson@example.com"
        }
    };
    private static Gson gson = new Gson();

    public static String getUserInfo() {
        List<User> users = new ArrayList<User>();
        for (String[] userData : testIdentities) {
            User user = new User(userData);
            users.add(user);
        }
        return gson.toJson(users);
    }

    public static String getCookie(HttpServletRequest request, HttpServletResponse response) {
        User user = new User(new String[]{
                    utf8(request.getParameter("name")),
                    utf8(request.getParameter("idp")),
                    utf8(request.getParameter("id")),
                    utf8(request.getParameter("attr")),
                    utf8(request.getParameter("email"))
        });
        String cookieValue = gson.toJson(user);
        response.addCookie(new Cookie("testSigID", b64(cookieValue)));
        return cookieValue;
    }

    private static String b64(String toB64) {
        return String.valueOf(Base64Coder.encode(toB64.getBytes(Charset.forName("UTF-8"))));
    }

    public static AuthData getTestID(HttpServletRequest request, RequestModel req) {
        User user = new User();
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("testSigID")) {
                user = getIdFromCookie(cookie);
            }
        }

        String authType = (user.id.length() > 0) ? "shibboleth" : "";
        String remoteUser = user.name;

        String[] names = user.name.split(" ");
        String fname = names[0];
        String lname = names[names.length - 1];

        String[][] authAttributes = new String[][]{
            new String[]{"Shib-Application-ID", "Application ID", "default"},
            new String[]{"Shib-Session-ID", "Session ID", (new BigInteger(64, new Random(System.currentTimeMillis()))).toString(16)},
            new String[]{"Shib-Identity-Provider", "Idp EntityID", URLDecoder.queryDecode(user.idp)},
            new String[]{"Shib-Authentication-Instant", "Authentication Time", String.valueOf(new Date())},
            new String[]{"Shib-Authentication-Method", "Authentication Method", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"},
            new String[]{"Shib-AuthnContext-Class", "Authentication Context", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"}
        };

        String[][] idAttributes = new String[][]{
            new String[]{"displayName", "Display Name", user.name},
            new String[]{"cn", "Common Name", user.name},
            new String[]{"sn", "Surename", lname},
            new String[]{"givenName", "Given Name", fname},
            new String[]{"personalIdentityNumber", "Personal ID Number", user.id},
            new String[]{"mail", "E-mail", user.email}                
        };

        List<List<String>> contextList = new ArrayList<List<String>>();
        for (String[] authAttr : authAttributes) {
            List<String> authAttrList = Arrays.asList(authAttr);
            contextList.add(authAttrList);
        }
        List<List<String>> idAttrList = new ArrayList<List<String>>();
        for (String[] idAttr : idAttributes) {
            List<String> attrList = Arrays.asList(idAttr);
            idAttrList.add(attrList);
        }

        AuthData authData = new AuthData(authType, remoteUser, contextList, idAttrList, user.idp, user.attribute, user.id, new ArrayList<>());
        return authData;
    }

    private static User getIdFromCookie(Cookie cookie) {
        User user = new User();
        String value = new String(Base64Coder.decode(cookie.getValue()), Charset.forName("UTF-8"));
        user = gson.fromJson(value, User.class);
        return user;
    }

    static class User {

        String name = "", idp = "", id = "", attribute = "", email = "";

        public User() {
        }

        public User(String[] testIdentity) {
            try {
                this.name = testIdentity[0];
                this.idp = testIdentity[1];
                this.id = testIdentity[2];
                this.attribute = testIdentity[3];
                this.email = testIdentity[4];
            } catch (Exception ex) {
            }
        }
    }

    private static String utf8(String isoStr) {
        if (isoStr == null) {
            return "";
        }
        byte[] bytes = isoStr.getBytes(Charset.forName("ISO-8859-1"));
        return new String(bytes, Charset.forName("UTF-8"));
    }
}
