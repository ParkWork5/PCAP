
import io.pkts.Pcap;
import io.pkts.buffer.Buffer;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.protocol.Protocol;
import netscape.javascript.JSObject;

import java.io.*;
import java.net.*;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

public class Analysis {

    private String[] webHosts;
    private int k=0;
    private String encodedUrl,id;
    private URLConnection connection;
    private HttpURLConnection http;
    private URL vtUrl;
    private VirusTotalAPIStuff vtAPI = new VirusTotalAPIStuff();
    private ArrayList<String> urlIds;

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

    public ArrayList<String> getUrlIds() {
        return urlIds;
    }


}
