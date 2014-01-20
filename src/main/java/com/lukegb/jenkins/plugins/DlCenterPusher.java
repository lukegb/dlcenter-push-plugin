package com.lukegb.jenkins.plugins;
import hudson.Launcher;
import hudson.Extension;
import hudson.maven.MavenBuild;
import hudson.maven.MavenReporter;
import hudson.maven.reporters.MavenArtifactRecord;
import hudson.model.*;
import hudson.plugins.git.GitSCM;
import hudson.tasks.*;
import hudson.util.FormValidation;
import hudson.maven.MavenModuleSetBuild;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.apache.commons.net.util.Base64;
import org.apache.http.*;
import org.apache.http.auth.*;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.auth.BasicSchemeFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Sample {@link Builder}.
 *
 * <p>
 * When the user configures the project and enables this builder,
 * {@link DescriptorImpl#newInstance(StaplerRequest)} is invoked
 * and a new {@link DlCenterPusher} is created. The created
 * instance is persisted to the project configuration XML by using
 * XStream, so this allows you to use instance fields (like #name)
 * to remember the configuration.
 *
 * <p>
 * When a build is performed, the @link #perform(AbstractBuild, Launcher, BuildListener)
 * method will be invoked. 
 *
 * @author Kohsuke Kawaguchi
 */
public class DlCenterPusher extends Recorder {

    private final String projectSlug;
    private final String devChannelSlug;
    private final String betaChannelSlug;
    private final String rbChannelSlug;

    // Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
    @DataBoundConstructor
    public DlCenterPusher(String projectSlug, String devChannelSlug, String betaChannelSlug, String rbChannelSlug) {
        this.projectSlug = projectSlug;
        this.devChannelSlug = devChannelSlug;
        this.betaChannelSlug = betaChannelSlug;
        this.rbChannelSlug = rbChannelSlug;
    }

    /**
     * We'll use this from the <tt>config.jelly</tt>.
     */
    public String getProjectSlug() {
        return projectSlug;
    }

    /**
     * We'll use this from the <tt>config.jelly</tt>.
     */
    public String getDevChannelSlug() {
        return devChannelSlug;
    }
    public String getBetaChannelSlug() {
        return betaChannelSlug;
    }
    public String getRbChannelSlug() {
        return rbChannelSlug;
    }

    public BuildStepMonitor getRequiredMonitorService() {
        return BuildStepMonitor.NONE;
    }

    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) throws InterruptedException, IOException {
        listener.getLogger().println("!!! I AM RUNNING !!!");

        if (!build.getResult().isBetterOrEqualTo(Result.SUCCESS)) {
            listener.getLogger().println("The build failed. I'm just going to go cry in a corner.</dlcenterpusher>");
        }
        
        List<String> buildText = build.getLog(70); // should be within the last 70 lines.
        String artifactFinalFilename = "FAILURE";
        for (String buildTextLine : buildText) {
            if (buildTextLine.startsWith("Uploaded: ") && buildTextLine.contains(".jar (")) {
                // whoop whoop
                // read from final / to end
                int finalBracketBit = buildTextLine.lastIndexOf(" (");
                // adding 1 to remove the / which is found by lastIndexOf
                artifactFinalFilename = buildTextLine.substring(buildTextLine.lastIndexOf('/', finalBracketBit) + 1, finalBracketBit);
                break;
            }
        }
        if (artifactFinalFilename.equals("FAILURE")) {
            throw new IOException("Failed to deploy to dlcenter. No Uploaded: line that also contains .jar ( could be found in the last 70 lines of log.");
        }
        
        MavenModuleSetBuild mvnBuild = (MavenModuleSetBuild)build;
        MavenBuild mvnModuleBuild = mvnBuild.getModuleLastBuilds().get(mvnBuild.getParent().getModules().toArray()[0]);
        MavenArtifactRecord mvnAr = mvnModuleBuild.getMavenArtifacts();
        
        List listOfUpstreamBuildProjectsAndBuildNumbers = new ArrayList<UpstreamProjectAndBuildNumber>();
        
        // list all upstream builds:
        for (hudson.model.AbstractProject upstreamProject : build.getProject().getUpstreamProjects()) {
            // neato
            listener.getLogger().println("Upstream project found: " + upstreamProject.getDisplayName());
            listener.getLogger().println("It has: " + upstreamProject.getPublishersList().toMap().size() + " publishers registered.");
            for (Object oupstreamProjectPublisher : upstreamProject.getPublishersList().toMap().values()) {
                Publisher upstreamProjectPublisher = (Publisher)oupstreamProjectPublisher;
                listener.getLogger().println(" - " + upstreamProjectPublisher.toString());
                if (upstreamProjectPublisher.getClass().equals(this.getClass())) {
                    DlCenterPusher upstreamDlCenterPusher = (DlCenterPusher) upstreamProjectPublisher;
                    String projectSlug = upstreamDlCenterPusher.getProjectSlug();
                    int buildNumber = mvnModuleBuild.getUpstreamRelationship(upstreamProject); 
                    listener.getLogger().println(" - * project slug: " + projectSlug);
                    listener.getLogger().println(" - * build number was: " + buildNumber);
                    if (buildNumber == -1 || projectSlug.length() == 0) {
                        listener.getLogger().println(" - ! nope.");
                        continue;
                    }
                    listOfUpstreamBuildProjectsAndBuildNumbers.add(new UpstreamProjectAndBuildNumber(projectSlug, buildNumber));
                }
            }
        }
        
        listener.getLogger().println("Pinging dlcenter:");
        listener.getLogger().println("Hostname: " + getDescriptor().hostName());
        listener.getLogger().println("Port: " + getDescriptor().hostPort());
        listener.getLogger().println("Username: " + getDescriptor().userName());
        
        // we need to set up some basic HTTP things
        //HttpHost proxy = new HttpHost("127.0.0.1", 8888, "http");
        
        HttpHost target = new HttpHost(getDescriptor().hostName(), getDescriptor().hostPort(), "http");
        DefaultHttpClient httpClient = new DefaultHttpClient();
        try {
            //httpClient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);

            // here goes: make the HTTP POST request...
            HttpPost addRequest = new HttpPost("/api/1.0/downloads/projects/" + projectSlug + "/artifacts/");
            
            HttpRequestInterceptor preemptiveAuth = new HttpRequestInterceptor() {
                public void process(final HttpRequest request, final HttpContext context) throws HttpException, IOException {
                    AuthState authState = (AuthState) context.getAttribute(ClientContext.TARGET_AUTH_STATE);
                    CredentialsProvider credsProvider = (CredentialsProvider) context.getAttribute(
                            ClientContext.CREDS_PROVIDER);
                    HttpHost targetHost = (HttpHost) context.getAttribute(ExecutionContext.HTTP_TARGET_HOST);

                    if (authState.getAuthScheme() == null) {
                        AuthScope authScope = new AuthScope(targetHost.getHostName(), targetHost.getPort());
                        Credentials creds = credsProvider.getCredentials(authScope);
                        if (creds != null) {
                            authState.setAuthScheme(new BasicScheme());
                            authState.setCredentials(creds);
                        }
                    }
                }
            };
            httpClient.addRequestInterceptor(preemptiveAuth, 0);
            
            httpClient.getCredentialsProvider().setCredentials(new AuthScope(target.getHostName(), target.getPort()), new UsernamePasswordCredentials(getDescriptor().userName(), getDescriptor().password()));



            // preinitialise some Strings for those REALLY long things
            String newRepoUrl = getDescriptor().baseRepoUrl() + "/" + mvnAr.mainArtifact.groupId.replace('.', '/') + "/" + mvnAr.mainArtifact.artifactId + "/" + mvnAr.mainArtifact.version + "/" + artifactFinalFilename;
            String commitRef = ((GitSCM)build.getProject().getScm()).getBuildData(build, true).getLastBuiltRevision().getSha1String();

            // start building the list of upload parameters
            List<NameValuePair> uploadParameters = new ArrayList<NameValuePair>();

            // gogogo!
            uploadParameters.add(new BasicNameValuePair("project", projectSlug));
            uploadParameters.add(new BasicNameValuePair("channel", getChannelForVersion(mvnAr.mainArtifact.version)));
            uploadParameters.add(new BasicNameValuePair("build_number", Integer.toString(build.getNumber())));
            uploadParameters.add(new BasicNameValuePair("created", build.getTimestampString2().replace('T', ' ').replace("Z", "")));
            uploadParameters.add(new BasicNameValuePair("commit_ref", commitRef));
            uploadParameters.add(new BasicNameValuePair("file_url", newRepoUrl));
            uploadParameters.add(new BasicNameValuePair("file_size", Long.toString(mvnAr.mainArtifact.getFile(mvnModuleBuild).length())));
            uploadParameters.add(new BasicNameValuePair("file_checksum_md5", mvnAr.mainArtifact.md5sum));
            uploadParameters.add(new BasicNameValuePair("version", mvnAr.mainArtifact.version.replace("-SNAPSHOT", "")));

            for (Object oupabn : listOfUpstreamBuildProjectsAndBuildNumbers) {
                UpstreamProjectAndBuildNumber upabn = (UpstreamProjectAndBuildNumber)oupabn;

                uploadParameters.add(new BasicNameValuePair("upstream_artifacts", upabn.getProject() + "!" + upabn.getBuildNumber()));
            }

            UrlEncodedFormEntity uefe = new UrlEncodedFormEntity(uploadParameters, "UTF-8");

            addRequest.setEntity(uefe);

            // Just bloody well do it manually
            //addRequest.setHeader("Authorization", "Basic " + Base64.encodeBase64String((getDescriptor().userName() + ":" + getDescriptor().password()).getBytes()));

            // okay, so:
            IOException ex = null;
            for (int retryCount = 0; retryCount < 3; retryCount++) {
                listener.getLogger().println("dlcenter <-- upload (retry " + retryCount + ")...");
                
                HttpResponse resp = httpClient.execute(target, addRequest);
                HttpEntity returnEntity = resp.getEntity();
                returnEntity.consumeContent();
                if (resp.getStatusLine().getStatusCode() != 201) {
                    ex = new IOException("Unexpected status code from dlcenter: got " + resp.getStatusLine());
                    continue;
                } else {
                    ex = null;
                    listener.getLogger().println("dlcenter --> " + resp.getHeaders("Location")[0].getValue());
                    break;
                }
            }
            if (ex != null) {
                throw ex;
            }
        } finally {
            httpClient.getConnectionManager().shutdown();
        }
        
        
        
        return true;
    }

    private String getChannelForVersion(String artifactVersion) {
        if (artifactVersion.endsWith("-SNAPSHOT"))
            return devChannelSlug;
        else if (!artifactVersion.endsWith(".0"))
            return betaChannelSlug;
        else
            return rbChannelSlug;
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl)super.getDescriptor();
    }

    @Override
    public boolean prebuild(AbstractBuild<?, ?> build, BuildListener listener) {
        return true;
    }

    /**
     * Descriptor for {@link DlCenterPusher}. Used as a singleton.
     * The class is marked as public so that it can be accessed from views.
     *
     * <p>
     * See <tt>src/main/resources/hudson/plugins/hello_world/DlCenterPusher/*.jelly</tt>
     * for the actual HTML fragment for the configuration screen.
     */
    @Extension // This indicates to Jenkins that this is an implementation of an extension point.
    public static class DescriptorImpl extends BuildStepDescriptor<Publisher> {
        /**
         * To persist global configuration information,
         * simply store it in a field and call save().
         *
         * <p>
         * If you don't want fields to be persisted, use <tt>transient</tt>.
         */
        public DescriptorImpl() {
            load();
        }
        
        private String userName;
        private String password;
        private String hostName;

        private int hostPort;
        private String baseRepoUrl;

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        /**
         * This human readable name is used in the configuration screen.
         */
        public String getDisplayName() {
            return "dlcenter Pusher";
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            // To persist global configuration information,
            // set that to properties and call save().
            userName = formData.getString("userName");
            password = formData.getString("password");
            hostName = formData.getString("hostName");
            hostPort = formData.getInt("hostPort");
            baseRepoUrl = formData.getString("baseRepoUrl");
            // ^Can also use req.bindJSON(this, formData);
            save();
            return super.configure(req,formData);
        }

        /**
         * This method returns the global configuration's username.
         * @return String User name
         */
        public String userName() {
            return userName;
        }

        /**
         * This method returns the global configuration's password.
         * @return String Password
         */
        public String password() {
            return password;
        }



        /**
         * This method returns the global configuration's hostname.
         * @return String Hostname
         */
        public String hostName() {
            return hostName;
        }
        
        public String baseRepoUrl() {
            return baseRepoUrl;
        }

        public int hostPort() {
            return hostPort;
        }

        @Override
        public DlCenterPusher newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            return req.bindJSON(DlCenterPusher.class, formData);
        }
    }
    
    protected class UpstreamProjectAndBuildNumber {
        private String project = "";
        private int buildNumber = -1;
        
        public UpstreamProjectAndBuildNumber(String newProject, int newBuildNumber) {
            project = newProject;
            buildNumber = newBuildNumber;
        }
        
        public String getProject() {
            return project;
        }
        
        public int getBuildNumber() {
            return buildNumber;
        }
        
    }
}
