import java.util.*;

public class Analysis {

    private String[] webHosts;
    private int k=0;
    private String id;
    private VirusTotalAPIStuff vtAPI = new VirusTotalAPIStuff();
    private ArrayList<String> urlIds;
    private ArrayList<AnalysisArpModel> arpMappings;
    private List<AnalysisArpModel> mappedArps;
    private String sourceIP, sourceMAC,currentMAC;


    public Analysis() {   // Default constructor

        urlIds = new ArrayList<>();

    }

    public void getRequestAnalysis(Set<String> uniqueWebHost,String api) { // Sends unique webhost urls to virus total for analysis

        k=0;
        webHosts = new String[uniqueWebHost.size()];
        for(String element : uniqueWebHost)
        {
            webHosts[k] = element;
            k++;
            id = Base64.getEncoder().encodeToString(element.getBytes()); // Virus Total uses base64 encoding to identify urls
            id = id.replace("=","");
            urlIds.add(id);
        }
        vtAPI.sendURL(webHosts,api); // Sends the urls


    }

    public List<AnalysisArpModel> arpAnalysis(ArrayList<ArpModel> arpList, Set<String> uniqueMACS)
    {
        arpMappings = new ArrayList<>();
        mappedArps = new ArrayList<>();


        for(String element : uniqueMACS)
        {
            AnalysisArpModel arpModel = new AnalysisArpModel(element);
            mappedArps.add(arpModel); // Adds mac address to model
        }


        for(int i=0; i < arpList.size();i++)
        {
            sourceIP = arpList.get(i).getSourceIp();
            sourceMAC = arpList.get(i).getSourceMACAddress();


            for(int r=0; r< mappedArps.size(); r++)    // Instead of mapping ip to macs we are doing the oppisite mac to ips
            {
             currentMAC = mappedArps.get(r).getSourceMAC();

             if(currentMAC.equals(sourceMAC))    //If the current unique mac address is the same as the mac address in model list then add to set
             {
                 mappedArps.get(r).addIpAddresses(sourceIP); // The second list is a Set. We don't have to worry about duplicate values
             }

            }

        }

        for(AnalysisArpModel element : mappedArps)
        {
            if(element.getIpAddresses().size() > 1)
            {
                element.setSpoofing(true);  //Spoofing check
            }
            else
            {
                element.setSpoofing(false);
            }
        }


        return mappedArps;

    }

    public ArrayList<String> getUrlIds() {
        return urlIds;
    }



}
