package burp;

import java.io.PrintWriter;
import java.util.List;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.text.DateFormat;

public class BurpExtender implements burp.IBurpExtender, burp.IHttpListener
{
    private burp.IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    private String nextToken = "";
    private String tempToken = "";
    private int nextTokenLen = 0;

    // implement IBurpExtender
    @Override
    public void registerExtenderCallbacks(burp.IBurpExtenderCallbacks callbacks)
    {
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(),true);

        // set our extension name
        callbacks.setExtensionName("Update-CSRF-Token");

        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);

        stdout.println("-----Plugin Loaded-------");
    }


    // implement IHttpListener
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, burp.IHttpRequestResponse messageInfo)
    {
        boolean updated = false;
        // Set the token prefix in response, allow to set multiple
        String[] tokenPrefixes = new String[]{ "Set-Cookie: XSRF-TOKEN=",};

        // only process requests
        if (messageIsRequest) {
            // get the HTTP service for the request
            burp.IHttpService httpService = messageInfo.getHttpService();
            burp.IRequestInfo iRequest = helpers.analyzeRequest(messageInfo);

            String request = new String(messageInfo.getRequest());

            List<String> headers = iRequest.getHeaders();
            // get the request body
            String reqBody = request.substring(iRequest.getBodyOffset());

            //Get all the data needed
            String[] pieces = headers.get(0).split(" ", 3);
            String httpmethod = pieces[0];
            String uri = pieces[1];

            //Update Token in request header
            if (!nextToken.equals("")) {
                for (int i = 0; i < headers.size(); i++)
                {
                    String H = headers.get(i);
                    if (H.toLowerCase().startsWith("x-xsrf-token:")) {
                        pieces = H.split(" ", 2);
                        String token = pieces[1];
                        stdout.println("Replacing " + token
                                + " with " +  nextToken );
                        H = pieces[0] + " " + nextToken;
                        headers.set(i, H);
                        updated = true;
                        break;
                    }
                }
            }

            if (updated) {

                byte[] message = helpers.buildHttpMessage(headers, reqBody.getBytes());
                messageInfo.setRequest(message);

            }
        }
        else//it's a response - grab a new token
        {
            burp.IRequestInfo iResponse = helpers.analyzeRequest(messageInfo);
            String response = new String(messageInfo.getResponse());


            //start at Set-Cookie: XSRF-TOKEN=
            //end at ; Path=/
            for (String tokenPrefix: tokenPrefixes) {
                while (response.contains(tokenPrefix)) {
                    //get next csrf token
                    String startMatch = tokenPrefix;
                    String endMatch = "; Path=/";

                    int tokenStartIndex = response.indexOf(startMatch) + startMatch.length();
                    int tokenEndIndex = response.indexOf(endMatch, tokenStartIndex+1);

                    tempToken = response.substring(tokenStartIndex, tokenEndIndex);
                    response = response.substring(tokenEndIndex+1);

                    //filter wrong format token
                    if (!tempToken.startsWith(";")&&!tempToken.startsWith("\""))
                        nextToken = tempToken;
                        nextTokenLen = nextToken.length();

                        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
                        Date date = new Date();

                        stdout.println(dateFormat.format(date));
                        stdout.println("grabbed new CSRF token " + nextToken);
                        break;
                }
            }
        }
    }
}
