package burp;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Burp Extender to analyze the output from REST services for common vulnerabilities
 * 
 * Code Features: 
 * Check to make sure the API secret isn't passed in
 * Check for the existence of a CSRF Token
 * Check all HTTP Verbs
 * Check for direct object references by iterating through URL parameters
 * Check for mass-assignment vulnerability
 * Check for auto select parameters

* @author Bill Sempf <bill@pointweb.net>
 */
public class BurpExtender implements IBurpExtender, IScannerCheck {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private OutputStream output;
    
    //Check for apisecret
    //This is hard, but I can look for the common variable names
    private static final Pattern FACEBOOK_API = Pattern.compile("&[aA][pP][pP][sS][eE][cC][rR][eE][tT]=");
    private static final Pattern FACEBOOK_API_2 = Pattern.compile("&[aA][pP][pP]_[sS][eE][cC][rR][eE][[tT]=");
    private static final Pattern GOOGLE_API = Pattern.compile("&[aA][pP][iI][sS][eE][cC][rR][eE][tT]=");
    private static final Pattern GOOGLE_API_2 = Pattern.compile("&[aA][pP][iI]_[sS][eE][cC][rR][eE][tT]=");

    private static final List<MatchRule> rules = new ArrayList<MatchRule>();
    static {
	rules.add(new MatchRule(FACEBOOK_API, 1, "Facebook API Secret"));
	rules.add(new MatchRule(FACEBOOK_API_2, 1, "Facebook API Secret"));
	rules.add(new MatchRule(GOOGLE_API, 1, "Google API Secret"));
	rules.add(new MatchRule(GOOGLE_API_2, 1, "Google API Secret"));
    }
    /**
     * implement IBurpExtender
     */
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
	// keep a reference to our callbacks object
	this.callbacks = callbacks;

	// obtain an extension helpers object
	helpers = callbacks.getHelpers();

	// set our extension name
	callbacks.setExtensionName("ReST Service Analysis");

	// register ourselves as a custom scanner check
	callbacks.registerScannerCheck(this);
	
	//get the output stream for info messages
	output = callbacks.getStdout();
	
	println("Loaded ReST Service Analysis");
    }

    /**
    * implement IScannerCheck
    */
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        //Secrets in the URL can be here.
        List<ScannerMatch> matches = new ArrayList<ScannerMatch>();
	List<IScanIssue> issues = new ArrayList<IScanIssue>();

	//get the URL of the requst
	URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
	println("Scanning for API Secrets in the URL: " + url.toString());
        
	for (MatchRule rule : rules) {
	    Matcher matcher = rule.getPattern().matcher(url.toString());
	    while (matcher.find()) {
		println("FOUND " + rule.getType() + "!");
		
		//get the actual match 
		String group;
		if (rule.getMatchGroup() != null) {
		    group = matcher.group(rule.getMatchGroup());
		} else {
		    group = matcher.group();
		}

		println("start: " + matcher.start() + " end: " + matcher.end() + " group: " + group);

		matches.add(new ScannerMatch(matcher.start(), matcher.end(), group, rule.getType()));
	    }
	}

        	// report the issues ------------------------
	if (!matches.isEmpty()) {
	    Collections.sort(matches);  //matches must be in order 
	    StringBuilder description = new StringBuilder(matches.size() * 256);
	    description.append("Values that are labeled as API secrets are appearing in the URLs or ReST service calls.<br>");
	    description.append("The API Secret should be kept out of direct requests to the API. Any value in a URL can be intercepted by and attacker, even under SSL. URLs with parameters are regularly cached in routers, servers, and bookmark lists.<br><br>");
	    description.append("The following API Secrets appear to be in the URL:<br><br>");
	    
	    List<int[]> startStop = new ArrayList<int[]>(1);
	    for (ScannerMatch match : matches) {
		println("Processing match: " + match);
		println("    start: " + match.getStart() + " end: " + match.getEnd() + " match: " + match.getMatch() + " match: " + match.getMatch());

		//add a marker for code highlighting
		startStop.add(new int[]{match.getStart(), match.getEnd()});

		//add a description
		description.append("<li>");

		description.append(match.getType()).append(": ").append(match.getMatch());

	    }

	    println("    Description: " + description.toString());

	    issues.add(new CustomScanIssue(
			baseRequestResponse.getHttpService(),
			helpers.analyzeRequest(baseRequestResponse).getUrl(),
			new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, startStop)},
			"ReST API Secret found in URL",
			description.toString(),
			"High",
                        "Firm"));

	    println("issues: " + issues.size());

        }
    	return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        //In here be the goodness.
        
	return null;

    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
	// This method is called when multiple issues are reported for the same URL 
	// path by the same extension-provided check. The value we return from this 
	// method determines how/whether Burp consolidates the multiple issues
	// to prevent duplication
	//
	// Since the issue name is sufficient to identify our issues as different,
	// if both issues have the same name, only report the existing issue
	// otherwise report both issues
	if (existingIssue.getIssueDetail().equals(newIssue.getIssueDetail())) {
	    println("DUPLICATE ISSUE! Consolidating...");
	    return -1;
	} else {
	    return 0;
	}
    }
    
    private void println(String toPrint) {
	try {
	    output.write(toPrint.getBytes());
	    output.write("\n".getBytes());
	    output.flush();
	} catch (IOException ioe) {
	    ioe.printStackTrace();
	} 
    }
}



/**
 * class implementing IScanIssue to hold our custom scan issue details
 */
class CustomScanIssue implements IScanIssue {

    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;

    public CustomScanIssue(
	    IHttpService httpService,
	    URL url,
	    IHttpRequestResponse[] httpMessages,
	    String name,
	    String detail,
	    String severity,
	    String confidence) {
	this.httpService = httpService;
	this.url = url;
	this.httpMessages = httpMessages;
	this.name = name;
	this.detail = detail;
	this.severity = severity;
	this.confidence = confidence;
    }

    @Override
    public URL getUrl() {
	return url;
    }

    @Override
    public String getIssueName() {
	return name;
    }

    @Override
    public int getIssueType() {
	return 0;
    }

    @Override
    public String getSeverity() {
	return severity;
    }

    @Override
    public String getConfidence() {
	return confidence;
    }

    @Override
    public String getIssueBackground() {
	return null;
    }

    @Override
    public String getRemediationBackground() {
	return null;
    }

    @Override
    public String getIssueDetail() {
	return detail;
    }

    @Override
    public String getRemediationDetail() {
	return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
	return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
	return httpService;
    }

}


class ScannerMatch implements Comparable<ScannerMatch> {

    private Integer start;
    private int end;
    private String match;
    private String type;

    public ScannerMatch(int start, int end, String match, String type) {
	this.start = start;
	this.end = end;
	this.match = match;
	this.type = type;
    }

    public int getStart() {
	return start;
    }

    public int getEnd() {
	return end;
    }

    public String getMatch() {
	return match;
    }

    public String getType() {
	return type;
    }    
    
    @Override
    public int compareTo(ScannerMatch m) {
        return start.compareTo(m.getStart());
    }
}


class MatchRule {
    private Pattern pattern;
    private Integer matchGroup;
    private String type;

    public MatchRule(Pattern pattern, Integer matchGroup, String type) {
	this.pattern = pattern;
	this.matchGroup = matchGroup;
	this.type = type;
    }

    public Pattern getPattern() {
	return pattern;
    }

    public Integer getMatchGroup() {
	return matchGroup;
    }

    public String getType() {
	return type;
    }
}