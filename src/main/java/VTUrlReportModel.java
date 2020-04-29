import java.util.HashMap;

public class VTUrlReportModel {

    private String webhost, urlID;
    private HashMap<String, Integer> analysis;
    private int malicous, harmless;

    public VTUrlReportModel(String webhost, String urlID, HashMap<String, Integer> analysis, int malicous, int harmless) {
        this.webhost = webhost;    // Model for taking api return and shoving it into data structure
        this.urlID = urlID;
        this.analysis = analysis;
        this.malicous = malicous;
        this.harmless = harmless;
    }

    public String getWebhost() {
        return webhost;
    }

    public void setWebhost(String webhost) {
        this.webhost = webhost;
    }

    public String getUrlID() {
        return urlID;
    }

    public void setUrlID(String urlID) {
        this.urlID = urlID;
    }

    public HashMap<String, Integer> getAnalysis() {
        return analysis;
    }

    public void setAnalysis(HashMap<String, Integer> analysis) {
        this.analysis = analysis;
    }

    public int getMalicous() {
        return malicous;
    }

    public void setMalicous(int malicous) {
        this.malicous = malicous;
    }

    public int getHarmless() {
        return harmless;
    }

    public void setHarmless(int harmless) {
        this.harmless = harmless;
    }
}
