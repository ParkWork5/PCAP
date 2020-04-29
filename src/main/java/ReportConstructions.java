import java.util.ArrayList;
import java.util.HashMap;

public class ReportConstructions {
    private String urlId, url,report;
    private int maliciousVote, harmlessVote, maliciousR, harmlessR,timeoutR,undetectedR,suspiciousR;
    private HashMap<String,Integer> analysisResults;

    public ReportConstructions() {
        report = "";
    }

    public String constructWebhostsReport(ArrayList<VTUrlReportModel> models)
    {


        for(int i=0; i < models.size(); i++)
        {
            urlId = models.get(i).getUrlID(); // Gets info from arraylist of returned data from virus total
            url = models.get(i).getWebhost();
            maliciousVote = models.get(i).getMalicous();
            harmlessVote = models.get(i).getHarmless();
            analysisResults = models.get(i).getAnalysis();

            maliciousR = analysisResults.get("malicious");
            harmlessR = analysisResults.get("harmless");
            timeoutR = analysisResults.get("timeout");
            undetectedR = analysisResults.get("undetected");
            suspiciousR = analysisResults.get("suspicious");

          report = report + "#####################################################\n";
          report = report + "URL:" + url +"\n";
          report = report + "URL ID:" + urlId +"\n";
          report = report + "Malicicous Community Votes:" + maliciousVote + "\n";
          report = report + "Harmless Community Votes:" + harmlessVote + "\n";
          report = report + "\n";
          report = report + "Analysis Results \n";
          report = report + "Identified Malicious:" + maliciousR + "\n";
          report = report + "Identified Suspicious:" + suspiciousR + "\n";
          report = report + "Identified Harmless:" + harmlessR + "\n";
          report = report + "Undetected:" + undetectedR + "\n";
          report = report + "Timed Out:" + timeoutR + "\n";
          report = report + "#####################################################\n";




        }
        return report;
    }

}
