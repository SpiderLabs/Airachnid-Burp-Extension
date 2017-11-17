package burp;

import org.apache.commons.lang3.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

class RequestSender {

//    private final static int      FUZZY_THRESHOLD = 5;
    private final static double   JARO_THRESHOLD = 0.8;
    private final static int      LEVENSHTEIN_THRESHOLD = 200;

    private final static String WORD = "test";

    protected final static String[] INITIAL_TEST_EXTENSIONS = {"css", "jpg", "js"};
    protected final static String[] OTHER_TEST_EXTENSIONS = {"html", "htm", "gif", "png", "cgi", "pl", "java", "class",
            "php", "php3", "shtm", "shtml", "cfm", "cfml", "doc", "log", "txt", "csv", "ppt", "m4a", "mid", "mp3", "flv",
            "m4v", "mov", "tif", "svg", "pdf", "xls", "sql", "bat", "exe", "jsp", "asp", "aspx", "jpeg"};

    private static byte[] orgResponse;

    /**
     * The initial test checks that the response is not the same for request with and without cookies (i.e. auth is
     * used). Then checks that appending "/test? returns the same page
     * @param message
     * @return
     */
    protected static boolean initialTest(IHttpRequestResponse message) {
        // Send the original request again
        byte[] orgRequest = buildHttpRequest(message, null, null, true);
        orgResponse = retrieveResponseBody(message.getHttpService(), orgRequest, true);

        // Send an unauthenticated - to root out fp's. Unauthenticated should not be the same as original
        byte[] unAuthedRequest = buildHttpRequest(message, null, null, false);
        byte[] unAuthedResponse = retrieveResponseBody(message.getHttpService(), unAuthedRequest, false);

        // Test that the original request and an unauthenticated request do not get the same response.
        // Same here is similar, according to the thresholds set
        boolean authed = testSimilar(new String(orgResponse), new String(unAuthedResponse));
        if (authed) {
            BurpExtender.print("Request not vulnerable");
            return false;
        }

        // Send with /test appended, check that everything after is ignored
        byte[] testRequest = buildHttpRequest(message, WORD, null, true);
        byte[] testResponse = retrieveResponseBody(message.getHttpService(), testRequest, true);

        boolean append = testSimilar(new String(orgResponse), new String(testResponse));
        if (!append) {
            BurpExtender.print("Request not vulnerable.");
        }
        return append;
    }

    protected static boolean getFileTypeCached(IHttpRequestResponse message, String extension) {
        // Send with extension, potentially create cached version of resource
        byte[] extRequest = buildHttpRequest(message, WORD, extension, true);
        byte[] extResponse = retrieveResponseBody(message.getHttpService(), extRequest, false);

        // Send an unauthenticated, test if vulnerable
        byte[] vulRequest = buildHttpRequest(message, WORD, extension, false);
        byte[] vulResponse = retrieveResponseBody(message.getHttpService(), vulRequest, false);

        boolean eq = testSimilar(new String(extResponse), new String(vulResponse)); //= new String(extResponse).equals(new String(vulResponse));
        if (!eq) {
            BurpExtender.print("Request is not vulnerable.");
        }

        return eq;
    }

    private static byte[] buildHttpRequest(final IHttpRequestResponse reqRes, final String additional, final String extension,
                                    boolean addCookies) {
        byte[] result;

        IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(reqRes);
        URL orgUrl = reqInfo.getUrl();
        List<IParameter> params = reqInfo.getParameters();
        List<String> headers = reqInfo.getHeaders();

        // Create GET message
        if ("GET".equals(reqInfo.getMethod())) {
            URL url = null;
            if (additional != null) {
                try {
                    url = createNewURL(orgUrl, additional, extension);
                } catch (MalformedURLException mue) {
                    mue.printStackTrace();
                }
            } else {
                url = reqInfo.getUrl();
            }

            result = BurpExtender.getHelpers().buildHttpRequest(url);

            if (addCookies) {
                for (IParameter p : params) {
                    if (IParameter.PARAM_COOKIE == p.getType()) {
                        result = BurpExtender.getHelpers().addParameter(result, p);
                    }
                }
            }
        } else { // Create POST message
            byte[] req = reqRes.getRequest();
            int len = req.length - reqInfo.getBodyOffset();
            byte[] body = new byte[len];
            System.arraycopy(req, reqInfo.getBodyOffset(), body, 0, len);
            List<String> newHeaders = new ArrayList<>();
            for (String header : headers) {
                if (header.toLowerCase().contains("cookie")) {
                    if (addCookies) {
                        newHeaders.add(header);
                    }
                } else if (header.contains("POST ")) {
                    int start = header.indexOf(" ") + 1;
                    int end = header.lastIndexOf("HTTP");
                    String url = header.substring(start, end).trim();
                    String newUrl = createNewUrl(url, additional, extension);
                    newHeaders.add("POST " + newUrl + " " + header.substring(end));
                } else {
                    newHeaders.add(header);
                }
            }

            result = BurpExtender.getHelpers().buildHttpMessage(newHeaders, body);
        }

        return result;
    }

    private static byte[] retrieveResponseBody(IHttpService service, byte[] request, boolean checkResponseCode) {
        byte[] result = null;

        IHttpRequestResponse test = BurpExtender.getCallbacks().makeHttpRequest(service, request);
        byte[] res = test.getResponse();
        IResponseInfo responseInfo = BurpExtender.getHelpers().analyzeResponse(res);

        if (checkResponseCode && responseInfo.getStatusCode() == 200) {
            int len = res.length - responseInfo.getBodyOffset();
            result = new byte[len];
            System.arraycopy(res, responseInfo.getBodyOffset(), result, 0, len);
        }

        return result;
    }


    private static URL createNewURL(URL orgURL, String additional, String extension) throws MalformedURLException {
        String urlStr = orgURL.toExternalForm();

        int pos = urlStr.indexOf("?");
        String path = pos >= 0 ? urlStr.substring(0, pos) : urlStr;
        String query = pos >= 0 ? urlStr.substring(pos) : "";
        char lastChar = urlStr.charAt(urlStr.length() - 1);
        if ('/' != lastChar) {
            path = path + "/";
        }

        path = path + additional;
        if (extension != null) {
            path = path + "." + extension;
        }
        path = path + query;

        return new URL(path);
    }

    private static String createNewUrl(String url, String additional, String extension) {
        StringBuilder result = new StringBuilder();

        int pos = url.indexOf("?");
        String path = pos >= 0 ? url.substring(0, pos) : url;
        String query = pos >= 0 ? url.substring(pos) : "";

        char lastChar = url.charAt(url.length() - 1);
        if ('/' != lastChar) {
            path = path + "/";
        }

        result.append(path);

        if (additional != null) {
            result.append(additional);
        }

        if (extension != null) {
            result.append(".").append(extension);
        }

        result.append(query);
        return result.toString();
    }

    /**
     * Testing if the responses of two requests are similar. This is the not the same as the same, rather there is a
     * threshold set in the static parameters of the class.
     * @param firstString
     * @param secondString
     * @return Test if similar
     */
    private static boolean testSimilar(String firstString, String secondString) {
//        int fuzzyDist = StringUtils.getFuzzyDistance(firstString, secondString, Locale.getDefault());
        double jaroDist = StringUtils.getJaroWinklerDistance(firstString, secondString);
        int levenDist = StringUtils.getLevenshteinDistance(firstString, secondString);

//        BurpExtender.print("============================================");
//        BurpExtender.print("Fuzzy Distance:" + fuzzyDist);
//        BurpExtender.print("        Jaro Winkler Distance:" + jaroDist);
//        BurpExtender.print("        Levenshtein Distance:" + levenDist);
//        BurpExtender.print("============================================");

        return jaroDist >= JARO_THRESHOLD || levenDist <= LEVENSHTEIN_THRESHOLD;
    }
}
