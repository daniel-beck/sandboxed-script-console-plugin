package io.jenkins.plugins.sandboxed_script_console;

import groovy.lang.Binding;
import hudson.Extension;
import hudson.Functions;
import hudson.model.AbstractModelObject;
import hudson.model.RootAction;
import hudson.model.TaskListener;
import hudson.security.Permission;
import hudson.security.PermissionGroup;
import hudson.security.PermissionScope;
import hudson.util.StreamTaskListener;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Collections;
import java.util.List;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import jenkins.model.Jenkins;
import jenkins.security.stapler.StaplerAccessibleType;
import org.apache.commons.io.IOUtils;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript;
import org.kohsuke.stapler.StaplerProxy;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.WebMethod;
import org.kohsuke.stapler.verb.POST;
import org.springframework.http.MediaType;

@Extension
public class SandboxedScriptConsoleRootAction implements RootAction, StaplerProxy {
    private static final PermissionGroup PERMISSION_GROUP = new PermissionGroup(SandboxedScriptConsoleRootAction.class, Messages._PermissionGroup_DisplayName());
    private static final Permission USE = new Permission(PERMISSION_GROUP, "Use", Messages._Permission_Description(), Jenkins.ADMINISTER, PermissionScope.JENKINS);
    public static final String FORM_PARAMETER_NAME = "script";

    @Override
    public String getIconFileName() {
        return Jenkins.get().hasPermission(USE) ? "terminal.png" : null;
    }

    @Override
    public String getDisplayName() {
        return Messages.RootAction_DisplayName();
    }

    @Override
    public String getUrlName() {
        return "sandboxedScript";
    }

    @POST
    @WebMethod(name = "")
    public void doSubmit(StaplerRequest req, StaplerResponse rsp) throws ServletException, IOException {
        String script;
        if (req.hasParameter(FORM_PARAMETER_NAME)) {
            script = req.getParameter(FORM_PARAMETER_NAME);
        } else {
            script = IOUtils.toString(req.getInputStream(), req.getCharacterEncoding());
        }
        // TODO Figure out how to make this work with pure GroovyShell + GroovySandbox + ClassLoaderWhitelist
        SecureGroovyScript secureGroovyScript = new SecureGroovyScript(script, true, Collections.emptyList()).configuringWithNonKeyItem();
        StringWriter out = new StringWriter();
        PrintWriter pw = new PrintWriter(out);
        try {
            Binding binding = new Binding();
            binding.setVariable("out", pw);
            Object returnValue = secureGroovyScript.evaluate(getClass().getClassLoader(), binding, new StreamTaskListener(pw));
            pw.println("Result: " + returnValue);
        } catch (Exception ex) {
            if (Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                Functions.printStackTrace(ex, pw);
            } else {
                pw.println(ex.toString());
            }
        }
        req.setAttribute("output", out.toString());

        final RequestDispatcher view = req.getView(this, shouldReturnTextPlainResponse(req) ? "_text.jelly" : "index.jelly");
        view.forward(req, rsp);
    }

    /**
     * Determine whether to return an HTML or plain text response based on the Accept request header.
     *
     * @param req the request
     * @return {@code true} if and only if we should render a {@code text/plain} response
     */
    private static boolean shouldReturnTextPlainResponse(StaplerRequest req) {
        String header = req.getHeader("Accept");
        final List<MediaType> mediaTypes = MediaType.parseMediaTypes(header); // TODO sort?
        for (MediaType mediaType : mediaTypes) {
            if (mediaType.isCompatibleWith(MediaType.TEXT_PLAIN)) {
                // curl sends `Accept: */*` by default, so prefer plain
                return true;
            }
            if (mediaType.isCompatibleWith(MediaType.TEXT_HTML)) {
                return false;
            }
        }
        // Neither option found means it's unlikely a web browser
        return true;
    }

    @Override
    public Object getTarget() {
        Jenkins.get().checkPermission(USE);
        return this;
    }

    public ConsoleApi getApi() {
        return new ConsoleApi();
    }

    // Try to recreate the UX of the hudson.model.Api type, just without being backed by a bean
    @StaplerAccessibleType
    public static class ConsoleApi extends AbstractModelObject {
        @Override
        public String getDisplayName() {
            return Messages.API_DisplayName();
        }

        @Override
        public String getSearchUrl() {
            return "api";
        }
    }
}
