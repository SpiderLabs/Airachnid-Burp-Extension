package burp;

import javax.swing.*;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * @author J Snyman
 * @author T Secker
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory {

    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        callbacks = iBurpExtenderCallbacks;
        callbacks.setExtensionName("Airachnid");
        callbacks.registerContextMenuFactory(this);
        helpers = iBurpExtenderCallbacks.getHelpers();

        callbacks.printOutput("Airachnid Version 1.0");
        callbacks.printOutput("Johan Snyman <jsnyman@trustwave.com>");
        callbacks.printOutput("");
        callbacks.printOutput("Check here for output from this extension.");
        callbacks.printOutput("");
    }

    protected static IExtensionHelpers getHelpers() {
        return helpers;
    }

    protected static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    protected static void printStdOut(String str) {
        callbacks.printOutput(str);
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
            JMenuItem item = new JMenuItem("Airachnid Web Cache Test");
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
                RequestSender rs = new RequestSender(message);
            }
        }
    }
}
