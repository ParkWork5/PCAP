

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.*;
import java.lang.reflect.Array;
import java.net.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

public class VirusTotalAPIStuff {
    private int k=0,harmless,malicious;
    private String encodedUrl,url,urlId;
    private URLConnection connection;
    private HttpURLConnection http;
    private URL vtUrl;
    private int responseCode,goodSend;
    private ArrayList<VTUrlReportModel> urlReports;
    private VTUrlReportModel report;
    private JSONObject object,valueGrabber;
    private JSONParser parser;
    private HashMap<String,Integer> results;


    public VirusTotalAPIStuff() {
    }

    public Boolean sendURL(String[] url,String api) {

         goodSend = 0; // Request that went through
        try {
            vtUrl = new URL(" https://www.virustotal.com/api/v3/urls");
            connection = vtUrl.openConnection();        // Contacting Virus Total api v3. No v3 libraries out so i had to figure it out
            http = (HttpURLConnection)connection;       // Use VPN kids since we have http here
            http.setRequestMethod("POST"); // PUT is another valid option
            http.setDoOutput(true);
            http.setRequestProperty("x-apikey",api); // Puts api key in header

        } catch (MalformedURLException e) {
            System.out.println("ERROR!! Something wrong with Virus Total url");
            e.getMessage();

        } catch (IOException e) {
            System.out.println("ERROR!! Something wrong with opening url connection");
        }

        for(String element : url)
        {
            encodedUrl = element; // Url not changed just derpy var name

            Map<String,String> arguments = new HashMap<>();
            arguments.put("url", encodedUrl); // Puts url in form
            StringJoiner sj = new StringJoiner("&");
            for(Map.Entry<String,String> entry : arguments.entrySet()) {
                try {
                    sj.add(URLEncoder.encode(entry.getKey(), "UTF-8") + "="
                            + URLEncoder.encode(entry.getValue(), "UTF-8"));
                } catch (UnsupportedEncodingException e) {
                    System.out.println("ERROR!! Issue with converting to proper API spec format");
                    System.out.println(e.getMessage());
                }
            }

            byte[] out = sj.toString().getBytes();
            int length = out.length;

            http.setFixedLengthStreamingMode(length); // Some http options setting

            try {
                http.connect();
            } catch (IOException e) {
                System.out.println("ERROR!! Issue with connecting to Virus Total ");
                System.out.println(e.getMessage());
            }



            try(OutputStream os = http.getOutputStream()) {
                os.write(out); // Writes out outputstream to out

                os.flush();

            } catch (IOException e) {
               // System.out.println("Connection closed with vt"); This exception will trigger everytime connection is closed not sure why
               // System.out.println(e.getMessage());
            }


            try {
                responseCode =  http.getResponseCode(); // Grabs response code to ensure POST request went through
            } catch (IOException e) {
                e.printStackTrace();
            }

            if(responseCode == 200)
            {
                goodSend++;

            }
            else
            {
                System.out.print("ERROR: webhost: " + element + "issue with analysis. " + "HTTP Code: " + responseCode);
            }

            http.disconnect();
            //System.out.println("Webhost:" + element + " Code:" + responseCode);
            //System.out.println("");

        }

        System.out.println(goodSend + "/" + url.length + " web hosts were succesfully sent to VT for analysis");

        return true;

    }

    public ArrayList<VTUrlReportModel> getUrlReports(ArrayList<String> urlIds,String api)
    {
        urlReports = new ArrayList<>();
        parser = new JSONParser();

        for(String element : urlIds) {
            try {

                vtUrl = new URL("https://www.virustotal.com/api/v3/urls/" + element);
                connection = vtUrl.openConnection();  //Get request to get results of webhost analysis from vt
                http = (HttpURLConnection)connection;  // Use VPN!!
                http.setRequestMethod("GET");
                http.setDoOutput(true);
                http.setRequestProperty("x-apikey",api);

                responseCode = ((HttpURLConnection) connection).getResponseCode();

                if(responseCode == 200) // Only good downloads are stored
                {

                    System.out.println("webhost:" + element +" Code:" +http.getResponseMessage());

                    BufferedReader in = new BufferedReader(new InputStreamReader(
                            connection.getInputStream()));
                    String inputLine;
                    StringBuffer response = new StringBuffer();

                    while ((inputLine = in.readLine()) != null) {
                        response.append(inputLine);
                    }

                    connection.getInputStream();
                    in.close();

                    try {
                         object = (JSONObject)parser.parse(response.toString());
                    } catch (ParseException e) {
                        System.out.println("ERROR!! Issue with parsing json from api response");
                        System.out.println(e.getMessage());
                    }

                    object = (JSONObject)parser.parse(object.get("data").toString()); // Parse JSON object till desired section is reached
                    object = (JSONObject)parser.parse(object.get("attributes").toString());

                   report =  makeReport(object,element); // Parses json response in function
                   urlReports.add(report); // Adds compelted report to list of reports
                }

            } catch (MalformedURLException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (ParseException e) {
                e.printStackTrace();
            }

            http.disconnect();
        }


     return urlReports;
    }

    public VTUrlReportModel makeReport(JSONObject jObject,String urlId)
    {
        results = new HashMap<>();
        url = jObject.get("last_final_url").toString();

        try {
            valueGrabber = (JSONObject)parser.parse(jObject.get("total_votes").toString()); // Grabs values from JSON object and fills model
            harmless = Integer.parseInt(valueGrabber.get("harmless").toString());
            malicious = Integer.parseInt(valueGrabber.get("malicious").toString());

            valueGrabber = (JSONObject)parser.parse(jObject.get("last_analysis_stats").toString());

            results.put("malicious",Integer.parseInt(valueGrabber.get("malicious").toString()));
            results.put("undetected",Integer.parseInt(valueGrabber.get("undetected").toString()));
            results.put("suspicious",Integer.parseInt(valueGrabber.get("suspicious").toString()));
            results.put("harmless",Integer.parseInt(valueGrabber.get("harmless").toString()));
            results.put("timeout",Integer.parseInt(valueGrabber.get("timeout").toString()));


        } catch (ParseException e) {
            e.printStackTrace();
        }

         report = new VTUrlReportModel(url,urlId,results,malicious,harmless);

        return report;
    }
}
