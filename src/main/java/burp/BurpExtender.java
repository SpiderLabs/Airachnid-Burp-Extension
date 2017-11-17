package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.concurrent.*;

/**
 * @author J Snyman
 * @author T Secker
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory {


    private final static float VERSION = 1.2f;

    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;

    protected static IExtensionHelpers getHelpers() {
        return helpers;
    }

    protected static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    protected static void print(String str) {
        callbacks.printOutput(str);
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        callbacks = iBurpExtenderCallbacks;
        callbacks.setExtensionName("Web Cache Deception Scanner");
        callbacks.registerContextMenuFactory(this);
        callbacks.registerScannerCheck(new WebCacheScannerCheck());
        callbacks.printOutput("Web Cache Deception Scanner Version " + VERSION);
        callbacks.printOutput("Johan Snyman <jsnyman@trustwave.com>");

        helpers = iBurpExtenderCallbacks.getHelpers();
    }

    private List<IScanIssue> runScannerForRequest(IHttpRequestResponse iHttpRequestResponse) {
        ExecutorService service = Executors.newFixedThreadPool(1);
        Future<List<IScanIssue>> task = service.submit(new ScannerThread(iHttpRequestResponse));
        List<IScanIssue> result = null;

        try {
            result = task.get();
        } catch(final InterruptedException ex) {
            ex.printStackTrace();
        } catch(final ExecutionException ex) {
            ex.printStackTrace();
        }

        return result;
    }

    /**
     * Context Sensitive menu item
     * @param iContextMenuInvocation
     * @return
     */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        List<JMenuItem> items = new ArrayList<>();

        // Only want the menu item to be created when:
        if (IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE == iContextMenuInvocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE == iContextMenuInvocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_PROXY_HISTORY == iContextMenuInvocation.getInvocationContext()) {
            IHttpRequestResponse[] arr = iContextMenuInvocation.getSelectedMessages();
            JMenuItem item = new JMenuItem("Web Cache Deception Test");
            MenuItemListener mil = new MenuItemListener(arr);
            item.addActionListener(mil);
            items.add(item);
        }
        return items;
    }

    /**
     * Class to handle menu actions
     */
    class MenuItemListener implements ActionListener {

        private final IHttpRequestResponse[] arr;

        MenuItemListener(IHttpRequestResponse[] arr) {
            this.arr = arr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            for (IHttpRequestResponse message : arr) {
                List<IScanIssue> result = runScannerForRequest(message);

                if (result != null) {
                    callbacks.addScanIssue(result.get(0));
                }
            }
        }
    }

    class WebCacheScannerCheck implements IScannerCheck {

        @Override
        public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
            // bugger all done here, no passive scanning
            return null;
        }

        @Override
        public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
            return runScannerForRequest(iHttpRequestResponse);
        }

        @Override
        public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
            if (existingIssue.getUrl().equals(newIssue.getUrl())) return -1;
            else return 0;
        }
    }

    class ScannerThread implements Callable<List<IScanIssue>> {

        private List<IScanIssue> result = null;
        private IHttpRequestResponse reqRes;

        ScannerThread(IHttpRequestResponse reqRes) {
            this.reqRes = reqRes;
        }

        public List<IScanIssue> call() {
            // Test One: Does appending to the URL return a similar response.
            if (RequestSender.initialTest(reqRes)) {
                Set<String> fileTypesCached = new HashSet<>();

                // Test two: Check if caching is done by file type
                for (String ext : RequestSender.INITIAL_TEST_EXTENSIONS) {
                    if (RequestSender.getFileTypeCached(reqRes, ext)) {
                        fileTypesCached.add(ext);
                    }
                }

                if (fileTypesCached.size() != 0) {
                    for (String ext : RequestSender.OTHER_TEST_EXTENSIONS) {
                        if (RequestSender.getFileTypeCached(reqRes, ext)) {
                            fileTypesCached.add(ext);
                        }
                    }

                    WebCacheIssue issue = new WebCacheIssue(reqRes);
                    issue.setVulnerableExtensions(fileTypesCached);

                    return Arrays.asList(issue);
                }
            }

            return result;
        }
    }
}
