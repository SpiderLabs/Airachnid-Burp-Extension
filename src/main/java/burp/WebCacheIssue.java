package burp;

import java.net.URL;
import java.util.Set;

public class WebCacheIssue implements IScanIssue {

    private IHttpRequestResponse message;
    private Set<String> extensions;

    WebCacheIssue(IHttpRequestResponse message) {
        this.message = message;
    }

    void setVulnerableExtensions(Set<String> extensions) {
        this.extensions = extensions;
    }

    @Override
    public URL getUrl() {
        return BurpExtender.getHelpers().analyzeRequest(message).getUrl();
    }

    @Override
    public String getIssueName() {
        return "Web Cache Misconfiguration";
    }

    @Override
    public int getIssueType() {
        return 1337007;
    }

    @Override
    public String getSeverity() {
        return "High";
    }

    @Override
    public String getConfidence() {
        return "Tentative";
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        StringBuilder sb = new StringBuilder();
        sb.append("The web application may be vulnerable to a particularly damaging attack called \"Web Cache ");
        sb.append("Deception\" demonstrated by Omar Gil in February 2017.<br/><br/>");
        sb.append("Web cache deception occurs when sensitive data returned by the web server in an authenticated ");
        sb.append("user context is cached as public static content by supporting servers e.g. A proxy server.<br/>");
        sb.append("Such cached data can be retrieved by any anonymous party subsequent to it initially being ");
        sb.append("served to the authenticated requestor.<br/>");
        sb.append("The attack is similar to Cross-site Request Forgery (CSRF) in that the user must be coerced ");
        sb.append("into clicking on/submitting a malformed link.<br/><br/>");
        sb.append("In order to be vulnerable two conditions must be met:<br/>");
        sb.append("<ol><li>The application’s response remains the same when a request has appended characters forming ");
        sb.append("an additional extension at the end of a URL.  E.g.  http://www.example.com/account.jsp and ");
        sb.append("http://www.example.com/account.jsp/test.jpg return the same valid response.</li>");
        sb.append("<li>Caching of files is performed by file extension as opposed to caching headers.</li></ol>");
        sb.append("<br/>");
        sb.append("Caching is a technique to speed up the response times of web applications. This is done by ");
        sb.append("storing copies of static files at locations from where they can be retrieved when needed. An ");
        sb.append("application’s caching can also be configured to cache files by file type, rather than by the ");
        sb.append("preferred caching header values as is sometimes the case with reverse proxies. The intention ");
        sb.append("of the caching is to present a cached copy of the requested resource, without passing the ");
        sb.append("request back to the application server. This relieves the application server of some load and ");
        sb.append("lets it get on with preparing the dynamic pages that need to be returned. This works well ");
        sb.append("when we request http://www.example.com/images/test.jpg but what if we could get the reverse proxy ");
        sb.append("to cache http://www.example.com/account.jsp where a user’s account details are displayed?<br/><br/>");
        sb.append("Omer demonstrated was that this is possible if we find a situation where ");
        sb.append("http://http://www.example.com/account.jsp returns the same response as ");
        sb.append("http://www.example.com/account.jsp/test.jpg<br/><br/>");
        sb.append("How does this work in practice?<br/>");
        sb.append("Attacker --> http://www.example.com/account.jsp/test.jpg --> Authenticated user<br/>");
        sb.append("User opens link --> Account Page details returned --> Reverse proxy caches \"account.jsp/test.jpg\"<br/>");
        sb.append("Attacker --> Views http://www.example.com/account.jsp/test.jpg<br/><br/>");

        sb.append("URL's that can be used for caching deception:");
        sb.append("<ul>");

        for (String ext : extensions) {
            sb.append("<li>").append(getUrl().toExternalForm()).append("/test.").append(ext).append("</li>");
        }
        sb.append("</ul>");

        return sb.toString();
    }

    @Override
    public String getRemediationDetail() {
        StringBuilder sb = new StringBuilder();
        sb.append("Any web caches should disregard the filetype extension and respect all Cache Control headers.<br/>");
        sb.append("Application servers should inspect the URL and return error messages if superfluous ");
        sb.append("extensions are added to a legitimate URL.");
        return sb.toString();
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return new IHttpRequestResponse[]{message};
    }

    @Override
    public IHttpService getHttpService() {
        return message.getHttpService();
    }

}
