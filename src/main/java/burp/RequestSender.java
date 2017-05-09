package burp;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

public class RequestSender implements Runnable {

    private final static int FUZZY_THRESHOLD = 5;
    private final static double JARO_THRESHOLD = 0.8;
    private final static int LEVENSHTEIN_THRESHOLD = 200;

    private final static String[] INITIAL_TEST_EXTENSIONS = {"css", "jpg", "js"};
    private final static String[] OTHER_TEST_EXTENSIONS = {"html", "htm", "gif", "png", "cgi", "pl", "java", "class",
            "php", "php3", "shtm", "shtml", "cfm", "cfml", "doc", "log", "txt", "csv", "ppt", "m4a", "mid", "mp3", "flv",
            "m4v", "mov", "tif", "svg", "pdf", "xls", "sql", "bat", "exe", "jsp", "asp", "aspx", "jpeg"};
    private final static String[] ALL_TEST_EXTENSIONS = ArrayUtils.addAll(INITIAL_TEST_EXTENSIONS, OTHER_TEST_EXTENSIONS);

    private static IHttpRequestResponse message;

    public RequestSender(IHttpRequestResponse message) {
        this.message = message;
        Thread t = new Thread(this);
        t.start();
    }

    @Override
    public void run() {
        // Test One: Does appending to the URL return a similar response.
        if (isURLVulnerable()) {
            BurpExtender.getCallbacks().printOutput("URL is vulnerable, adding text gets the same response");
            // Test two: Check if caching is done by filetype
            Set<String> vulnExt = new HashSet<>();

//            // There are two ways to tackle this:
//            // 1. Test a sample set of extensions:
////            for (int i = 0; i < INITIAL_TEST_EXTENSIONS.length; i++) {
////                String test = INITIAL_TEST_EXTENSIONS[i];
////                if (isFileTypeCached(test)) {
////                    BurpExtender.getCallbacks().printOutput(test + " extension is vulnerable!");
////                    vulnExt.add(test);
////                } else {
////                    BurpExtender.getCallbacks().printOutput("." + test + " page is not cached.");
////                }
////            }
////
////            if (!vulnExt.isEmpty()) {
////                BurpExtender.getCallbacks().printOutput("Checking other extensions");
////                for (int i = 0; i < OTHER_TEST_EXTENSIONS.length; i++) {
////                    if (isFileTypeCached(OTHER_TEST_EXTENSIONS[i])) {
////                        vulnExt.add(OTHER_TEST_EXTENSIONS[i]);
////                    }
////                }
////
////                BurpExtender.getCallbacks().printOutput("Done checking other extensions");
////                BurpExtender.getCallbacks().printOutput("Adding issue");
////
////                WebCacheIssue issue = new WebCacheIssue(message);
////                issue.setVulnerableExtensions(vulnExt);
////
////                BurpExtender.getCallbacks().addScanIssue(issue);
////            }
//
//            // 2. Test all extensions
//            for (int i = 0; i < ALL_TEST_EXTENSIONS.length; i++) {
//                String test = ALL_TEST_EXTENSIONS[i];
//                if (isFileTypeCached(test)) {
//                    BurpExtender.getCallbacks().printOutput(test + " extension is vulnerable!");
//                    vulnExt.add(test);
//                } else {
//                    BurpExtender.getCallbacks().printOutput("." + test + " page is not cached.");
//                }
//            }
//
//            if (vulnExt.size() > 0) {
//                BurpExtender.getCallbacks().printOutput("Done testing, adding vuln");
//                WebCacheIssue issue = new WebCacheIssue(message);
//                issue.setVulnerableExtensions(vulnExt);
//
//                BurpExtender.getCallbacks().addScanIssue(issue);
//            }
//        } else {
//            BurpExtender.getCallbacks().printOutput("URL is not vulnerable");
        }
    }

    private boolean isURLVulnerable() {
        // Send the original request again
        byte[] orgRequest = buildHttpRequest(message, null, null, true);
        byte[] orgResponse = retrieveResponseBody(message.getHttpService(), orgRequest, true);

        // Send an unauthenticated - to root out fp's. Unauthenticated should not be the same as original
        byte[] unAuthedRequest = buildHttpRequest(message, null, null, false);
        byte[] unAuthedResponse = retrieveResponseBody(message.getHttpService(), unAuthedRequest, false);

        // Test that the original request and an unauthenticated request do not get the same response.
        // Same here is similar, according to the thresholds set
        if (testSimilar(new String(orgResponse), new String(unAuthedResponse))) {
            BurpExtender.printStdOut("This request does not use authentication.");
            return false;
        }

        // Send with /test appended
        byte[] testRequest = buildHttpRequest(message, "test", null, true);
        byte[] testResponse = retrieveResponseBody(message.getHttpService(), testRequest, true);

        return testSimilar(new String(orgResponse), new String(testResponse));
    }

    private boolean isFileTypeCached(String extension) {
        byte[] orgRequest = buildHttpRequest(message, "test", extension, true);
        byte[] orgResponse = retrieveResponseBody(message.getHttpService(), orgRequest, true);

        // Send an unauthenticated
        byte[] unAuthedRequest = buildHttpRequest(message, "test", extension, false);
        byte[] unAuthedResponse = retrieveResponseBody(message.getHttpService(), unAuthedRequest, false);

        return new String(orgResponse).equals(new String(unAuthedResponse));
    }

    private byte[] buildHttpRequest(final IHttpRequestResponse reqRes, final String additional, final String extension,
                                    boolean addCookies) {
        byte[] result;

        IRequestInfo reqInfo = BurpExtender.getHelpers().analyzeRequest(reqRes);
        URL orgUrl = reqInfo.getUrl();
        List<IParameter> params = reqInfo.getParameters();
        List<String> headers = reqInfo.getHeaders();

        if ("GET".equals(reqInfo.getMethod())) {
            // Create GET message

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
        } else {
            // Create POST message
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

    private byte[] retrieveResponseBody(IHttpService service, byte[] request, boolean checkResponseCode) {
        byte[] result = null;

        IHttpRequestResponse test = BurpExtender.getCallbacks().makeHttpRequest(service, request);
        byte[] res = test.getResponse();
        IResponseInfo responseInfo = BurpExtender.getHelpers().analyzeResponse(res);

        if (checkResponseCode && responseInfo.getStatusCode() != 200) {
            BurpExtender.printStdOut("Response message is not 200 OK, ignoring");
        } else {
            int len = res.length - responseInfo.getBodyOffset();
            result = new byte[len];
            System.arraycopy(res, responseInfo.getBodyOffset(), result, 0, len);
        }

        return result;
    }


    private URL createNewURL(URL orgURL, String additional, String extension) throws MalformedURLException {
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

    private String createNewUrl(String url, String additional, String extension) {
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

    private boolean testSimilar(String firstString, String secondString) {
        int fuzzyDist = StringUtils.getFuzzyDistance(firstString, secondString, Locale.getDefault());
        double jaroDist = StringUtils.getJaroWinklerDistance(firstString, secondString);
        int levenDist = StringUtils.getLevenshteinDistance(firstString, secondString);

        BurpExtender.getCallbacks().printOutput("============================================");
        BurpExtender.getCallbacks().printOutput("Fuzzy Distance:" + fuzzyDist);
        BurpExtender.getCallbacks().printOutput("Jaro Winkler Distance:" + jaroDist);
        BurpExtender.getCallbacks().printOutput("Levenshtein Distance:" + levenDist);
        BurpExtender.getCallbacks().printOutput("============================================");

        return jaroDist >= JARO_THRESHOLD || levenDist <= LEVENSHTEIN_THRESHOLD;
    }
}
