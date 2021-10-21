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
package com.aaasec.sigserv.cscommon;

import org.apache.commons.io.IOUtils;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HttpOps {

    private static final Logger LOG = Logger.getLogger(HttpOps.class.getName());
    private static int maxMessageLength = 500000;
    private static String tempFileLocation = new File(System.getProperty("user.dir"), "tempData").getAbsolutePath();
    private static Random rng = new Random(System.currentTimeMillis());
    private static Map<String, Map<String, String>> cookieMap = new HashMap<String, Map<String, String>>();
    private static String userAgent = "Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25";

    /**
     * Dummy constructor, preventing instantiation
     */
    private HttpOps() {
    }

    public static void clearCookies() {
        cookieMap.clear();
    }

    /**
     * Sets the maximum message length that will be allowed in the exchange of
     * data between the requesting service and the central signing support
     * service.
     *
     * @param messageMaxLength Integer specifying the maximum number of bytes
     */
    public static void setMaxMessageLength(int messageMaxLength) {
        HttpOps.maxMessageLength = messageMaxLength;
    }

    public static void setTempFileLocation(String tempFileLocation) {
        HttpOps.tempFileLocation = tempFileLocation;
    }

    public static void setUserAgent(String userAgent) {
        HttpOps.userAgent = userAgent;
    }
        

    public static byte[] httpPost(String serviceUrl, Map<String, String> valueMap) {
        byte[] response = null;
        try {
            URL url = new URL(serviceUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            setCookies(conn);
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setInstanceFollowRedirects(false);
            conn.setRequestProperty("User-Agent", userAgent);

            OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
            try {
                wr.write(getRequestQueryData(valueMap, ReqType.POST));
                wr.flush();
            } catch (Exception ex) {
            } finally {
                wr.close();
            }
            getCookies(conn);

            int respCode = conn.getResponseCode();
            while (respCode == 301 || respCode == 302 || respCode == 303) {
                URL redirUrl = getLocationUrl(conn);
                conn.disconnect();
                conn = (HttpURLConnection) redirUrl.openConnection();
                setCookies(conn);
                conn.setRequestMethod("GET");
                conn.setInstanceFollowRedirects(false);
                conn.setRequestProperty("User-Agent", userAgent);
                conn.connect();
                getCookies(conn);
                respCode = conn.getResponseCode();
            }

            try {

                int responseCode = conn.getResponseCode();
                if (responseCode == 200) {
                    //response = getBytesFromHttpInputStream(conn.getInputStream(), maxMessageLength);
                    response = IOUtils.toByteArray(conn.getInputStream());
                }
            } catch (Exception ex) {
            }

        } catch (Exception e) {
            int i = 0;
        }
        return response;
    }

    public static byte[] httpGet(String serviceUrl, Map<String, String> valueMap) {
        byte[] response = null;
        try {
            URL url = new URL(serviceUrl + getRequestQueryData(valueMap, ReqType.GET));
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            setCookies(conn);
            conn.setRequestMethod("GET");
            conn.setInstanceFollowRedirects(false);
            conn.setRequestProperty("User-Agent", userAgent);
            conn.connect();
            getCookies(conn);

            int respCode = conn.getResponseCode();
            while (respCode == 301 || respCode == 302 || respCode == 303) {
                URL redirUrl = getLocationUrl(conn);
                conn.disconnect();
                conn = (HttpURLConnection) redirUrl.openConnection();
                setCookies(conn);
                conn.setRequestMethod("GET");
                conn.setInstanceFollowRedirects(false);
                conn.setRequestProperty("User-Agent", userAgent);
                conn.connect();
                getCookies(conn);
                respCode = conn.getResponseCode();
            }

            try {

                int responseCode = conn.getResponseCode();
                if (responseCode == 200) {
                    //response = getBytesFromHttpInputStream(conn.getInputStream(), maxMessageLength);
                    response = IOUtils.toByteArray(conn.getInputStream());
                }

            } catch (Exception ex) {
            }

        } catch (Exception e) {
        }
        return response;
    }

    public String getEncodedData(byte[] data) {
        try {
            return encodeURIComponent(b64Eencode(data));
        } catch (Exception ex) {
        }
        return "";
    }

    public static void trustAllCAs() {
        try {
            /*
             *  fix for
             *    Exception in thread "main" javax.net.ssl.SSLHandshakeException:
             *       sun.security.validator.ValidatorException:
             *           PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException:
             *               unable to find valid certification path to requested target
             */
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
            };

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };
            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (Exception ex) {
            LOG.warning(ex.getMessage());
        }
    }

    private static String retrieveCookieVals(URL url) {
        String urlId = getUrlId(url);
        Map<String, String> cookies = new HashMap<String, String>();
        if (!cookieMap.containsKey(urlId)) {
            return null;
        }
        cookies = cookieMap.get(urlId);
        StringBuilder b = new StringBuilder();
        Set<String> keySet = cookies.keySet();
        for (String key : keySet) {
            String val = cookies.get(key);
            b.append(key).append("=").append(val).append("; ");
        }
        return b.toString().trim();
    }

    private static URL getLocationUrl(HttpURLConnection conn) {
        String headerName;
        for (int i = 1; (headerName = conn.getHeaderFieldKey(i)) != null; i++) {
            if (headerName.equals("Location")) {
                String location = conn.getHeaderField(i);
                try {
                    return new URL(location);
                } catch (MalformedURLException ex) {
                    return null;
                }
            }
        }
        return null;
    }

    private static void getCookies(HttpURLConnection conn) {
        String urlId = getUrlId(conn.getURL());
        Map<String, String> cookies = new HashMap<String, String>();
        if (cookieMap.containsKey(urlId)) {
            cookies = cookieMap.get(urlId);
        }
        String headerName;
        for (int i = 1; (headerName = conn.getHeaderFieldKey(i)) != null; i++) {
            if (headerName.equals("Set-Cookie")) {
                String cookieVals = conn.getHeaderField(i);
                String[] valSplit = cookieVals.split(";");
                for (String nvPair : valSplit) {
                    String[] nvSplit = nvPair.split("=");
                    if (nvSplit.length == 2) {
                        cookies.put(nvSplit[0].trim(), nvSplit[1].trim());
                    }
                }
            }
        }
        cookieMap.put(urlId, cookies);
    }

    private static void setCookies(HttpURLConnection conn) {
        String cookieVals = retrieveCookieVals(conn.getURL());
        if (cookieVals != null) {
            conn.setRequestProperty("Cookie", cookieVals);
        }
    }

    private static String getUrlId(URL url) {
        return url.getHost();
    }

    private static String getRequestQueryData(Map<String, String> paramMap, ReqType type) {
        if (paramMap == null) {
            return "";
        }
        StringBuilder b = new StringBuilder();
        Iterator<String> keys = paramMap.keySet().iterator();
        if (keys.hasNext()) {
            switch (type) {
                case GET:
                    b.append("?");
                default:
            }
        }
        while (keys.hasNext()) {
            String key = keys.next();
            b.append(encodeURIComponent(key)).append("=").append(encodeURIComponent(paramMap.get(key)));
            if (keys.hasNext()) {
                b.append("&");
            }
        }
        return b.toString();
    }

    private static byte[] getBytesFromInputStream(InputStream is, int maxLen)
            throws IOException {

        byte[] bytes = null;
        try {
            // Get the size of the file
            long length = is.available();

            if (length > maxLen) {
                return null;
            }

            // Create the byte array to hold the data
            bytes = new byte[(int) length];

            // Read in the bytes
            int offset = 0;
            int numRead = 0;
            while (offset < bytes.length
                    && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
                offset += numRead;
            }

            // Ensure all the bytes have been read in
            if (offset < bytes.length) {
                throw new IOException("Could not completely read file ");
            }
        } catch (Exception ex) {
        } finally {
            is.close();
        }


        // Close the input stream and return bytes
        return bytes;
    }

    private static byte[] getBytesFromHttpInputStream(InputStream is, int maxLen)
            throws IOException {

        byte[] bytes = null;
        // create tempFile;
        String fName = String.valueOf(rng.nextLong()).replaceAll("-", "a") + ".tmp";
        File resultFile = new File(getfileNameString(tempFileLocation, fName));
        resultFile.getParentFile().mkdirs();

        // Store result in tempprary file
        BufferedInputStream bufIn = new BufferedInputStream(is);
        try {

            FileOutputStream fos = new FileOutputStream(resultFile);
            byte[] b = new byte[100];
            for (;;) {
                int len = bufIn.read(b);
                if (len == -1) {
                    break;
                } else {
                    fos.write(b, 0, len);
                }
            }
            fos.close();
        } catch (Exception ex) {
            return null;
        } finally {
            bufIn.close();
        }
        //Read result from file
        long length = resultFile.length();
        if (length < maxLen) {
            bytes = readBinaryFile(resultFile);
        }
        resultFile.delete();

        return bytes;
    }

    /**
     * Decodes the passed UTF-8 String using an algorithm that's compatible with
     * JavaScript's
     * <code>decodeURIComponent</code> function. Returns
     * <code>null</code> if the String is
     * <code>null</code>.
     *
     * @param s The UTF-8 encoded String to be decoded
     * @return the decoded String
     */
    public static String decodeURIComponent(String s) {
        if (s == null) {
            return null;
        }

        String result = null;

        try {
            result = URLDecoder.decode(s, "UTF-8");
        } // This exception should never occur.
        catch (UnsupportedEncodingException e) {
            result = s;
        }

        return result;
    }

    /**
     * Encodes the passed String as UTF-8 using an algorithm that's compatible
     * with JavaScript's
     * <code>encodeURIComponent</code> function. Returns
     * <code>null</code> if the String is
     * <code>null</code>.
     *
     * @param s The String to be encoded
     * @return the encoded String
     */
    public static String encodeURIComponent(String s) {
        String result = null;

        try {
            result = URLEncoder.encode(s, "UTF-8").replaceAll("\\+", "%20").replaceAll("\\%21", "!").replaceAll("\\%27", "'").replaceAll("\\%28", "(").replaceAll("\\%29", ")").replaceAll("\\%7E", "~");
        } // This exception should never occur.
        catch (UnsupportedEncodingException e) {
            result = s;
        }

        return result;
    }
    /*
     * Base 64 encoder and decoder
     */
    // Mapping table from 6-bit nibbles to Base64 characters.
    private static char[] map1 = new char[64];

    static {
        int i = 0;
        for (char c = 'A'; c <= 'Z'; c++) {
            map1[i++] = c;
        }
        for (char c = 'a'; c <= 'z'; c++) {
            map1[i++] = c;
        }
        for (char c = '0'; c <= '9'; c++) {
            map1[i++] = c;
        }
        map1[i++] = '+';
        map1[i++] = '/';
    }
    // Mapping table from Base64 characters to 6-bit nibbles.
    private static byte[] map2 = new byte[128];

    static {
        for (int i = 0; i < map2.length; i++) {
            map2[i] = -1;
        }
        for (int i = 0; i < 64; i++) {
            map2[map1[i]] = (byte) i;
        }
    }

    /**
     * Encodes a byte array into Base64 format. No blanks or line breaks are
     * inserted in the output.
     *
     * @param in An array containing the data bytes to be encoded.
     * @return A String containing the Base64 encoded data.
     */
    private static String b64Eencode(byte[] in) {
        int iOff = 0;
        int iLen = in.length;

        int oDataLen = (iLen * 4 + 2) / 3;       // output length without padding
        int oLen = ((iLen + 2) / 3) * 4;         // output length including padding
        char[] out = new char[oLen];
        int ip = iOff;
        int iEnd = iOff + iLen;
        int op = 0;
        while (ip < iEnd) {
            int i0 = in[ip++] & 0xff;
            int i1 = ip < iEnd ? in[ip++] & 0xff : 0;
            int i2 = ip < iEnd ? in[ip++] & 0xff : 0;
            int o0 = i0 >>> 2;
            int o1 = ((i0 & 3) << 4) | (i1 >>> 4);
            int o2 = ((i1 & 0xf) << 2) | (i2 >>> 6);
            int o3 = i2 & 0x3F;
            out[op++] = map1[o0];
            out[op++] = map1[o1];
            out[op] = op < oDataLen ? map1[o2] : '=';
            op++;
            out[op] = op < oDataLen ? map1[o3] : '=';
            op++;
        }
        return String.valueOf(out);
    }

    /**
     * Decodes a byte array from Base64 format. No blanks or line breaks are
     * allowed within the Base64 encoded input data.
     *
     * @param s A Base64 String to be decoded.
     * @return An array containing the decoded data bytes.
     * @throws IllegalArgumentException If the input is not valid Base64 encoded
     * data.
     */
    private static byte[] b64Decode(String s) {
        char[] in = s.toCharArray();
        int iOff = 0;
        int iLen = in.length;

        if (iLen % 4 != 0) {
            throw new IllegalArgumentException("Length of Base64 encoded input string is not a multiple of 4.");
        }
        while (iLen > 0 && in[iOff + iLen - 1] == '=') {
            iLen--;
        }
        int oLen = (iLen * 3) / 4;
        byte[] out = new byte[oLen];
        int ip = iOff;
        int iEnd = iOff + iLen;
        int op = 0;
        while (ip < iEnd) {
            int i0 = in[ip++];
            int i1 = in[ip++];
            int i2 = ip < iEnd ? in[ip++] : 'A';
            int i3 = ip < iEnd ? in[ip++] : 'A';
            if (i0 > 127 || i1 > 127 || i2 > 127 || i3 > 127) {
                throw new IllegalArgumentException("Illegal character in Base64 encoded data.");
            }
            int b0 = map2[i0];
            int b1 = map2[i1];
            int b2 = map2[i2];
            int b3 = map2[i3];
            if (b0 < 0 || b1 < 0 || b2 < 0 || b3 < 0) {
                throw new IllegalArgumentException("Illegal character in Base64 encoded data.");
            }
            int o0 = (b0 << 2) | (b1 >>> 4);
            int o1 = ((b1 & 0xf) << 4) | (b2 >>> 2);
            int o2 = ((b2 & 3) << 6) | b3;
            out[op++] = (byte) o0;
            if (op < oLen) {
                out[op++] = (byte) o1;
            }
            if (op < oLen) {
                out[op++] = (byte) o2;
            }
        }
        return out;
    }

    private static String getfileNameString(String path, String fileName) {
        if (path == null || fileName == null) {
            return "";
        }

        String name = fileName;
        if (fileName.endsWith("/")) {
            name = fileName.substring(0, fileName.length() - 1);
        }

        if (path.endsWith("/")) {
            return path + name;
        }

        return path + "/" + name;
    }

    /**
     * creates a directory with the specified name if that directory does not
     * already exists.
     *
     * @param dirName The name of the directory
     * @return true if the directory exists or was created successfully, false
     * otherwise.
     */
    private static boolean createDir(String dirName) {
        if (dirName.endsWith("/")) {
            dirName = dirName.substring(0, dirName.length() - 1);
        }
        File dir = new File(dirName);
        if (!dir.exists()) {
            return dir.mkdirs();
        }
        return true;
    }

    private static byte[] readBinaryFile(File file) {
        List inp = new LinkedList<Byte>();
        try {
            FileInputStream fi = new FileInputStream(file);
            while (fi.available() > 0) {
                inp.add(fi.read());
            }
        } catch (IOException ex) {
            return new byte[0];
        }
        byte[] b = new byte[inp.size()];
        int i = 0;
        for (Object o : inp) {
            int val = (Integer) o;
            b[i++] = (byte) val;
        }
        return b;
    }

    public enum ReqType {

        GET, POST
    }
}
