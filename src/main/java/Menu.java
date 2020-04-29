import io.pkts.Pcap;

import java.io.IOException;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Scanner;

public class Menu {
    private String arg,pcapPath="null";
    private int i=0,menuBoi=0;
    private Pcap pcap;
    private Boolean goodToGo = true;
    private Scanner userInput = new Scanner(System.in);
    private ArrayList<HttpGetModel> httpGetModels;
    private ArrayList<TCPPacketModel> foundTcpPackets;
    private String virusTotalAPI,email,emailPassword;
    private ArrayList<String> urlIds;
    private VirusTotalAPIStuff virusTotal;
    private ArrayList<VTUrlReportModel> models;
    private Gmail gmail;



    Boolean preCheck(String[] args)
    {
        while(i < args.length && args[i].startsWith("-")){
            arg = args[i++];

            // Arguements defined here for pcappath, gmail, etc

            if(arg.equals("-pcappath")){
                pcapPath = args[i++];

                try {
                    pcap = Pcap.openStream(pcapPath);
                } catch (IOException e) {
                    System.out.println("ERROR!! Invalid pcap file path provided");
                    goodToGo = false;
                }

            }
            else if(arg.equals("-vtapi")){
                virusTotalAPI = args[i++];

                if(virusTotalAPI.length() == 0) {
                    goodToGo = false;
                }

            }
            else if(arg.equals("-email")){
                email = args[i++];
            }
            else if(arg.equals("-emailPassword")){
                emailPassword = args[i++];
            }
            else if(arg.equals("-help")){
                System.out.println("-pcappath [pcap file path] //Sets pcap file path");
                System.out.println("-vtapi [Virus total api key] //Sets Virus total api key to use in program");
                System.out.println("-help //Shows help menu");
                System.out.println("-email [Dest email] // Sets email for recieving report");
                System.out.println("-emailPassword [Password] // Sets email password");
            }
            else
            {
                goodToGo = false;
                System.out.println("ERROR!! Check arguements");

            }


        }
        return goodToGo;
    }

    void menu(Boolean menuCheck) {
        if(menuCheck != false) // Menu check to ensure pcap is loaded
        {
            PcapParsing pcapParsing = new PcapParsing(pcap);
            Analysis analysis = new Analysis();
            httpGetModels = new ArrayList<>();
            foundTcpPackets = new ArrayList<>();
            urlIds = new ArrayList<>();
            virusTotal = new VirusTotalAPIStuff();
            models= new ArrayList<>();
            gmail = new Gmail();

            foundTcpPackets = pcapParsing.tcpPacketParsing();

            System.out.println("Pcap file found at: " + pcapPath);
            System.out.println("Virus Total API key found: " + virusTotalAPI);
            System.out.println("");
            System.out.println("Parsed for TCP packets, found:" + foundTcpPackets.size());
            System.out.println("Parsed for UDP packets, found:" );
            System.out.println("");



            System.out.println("Welcome to PCAP(Pcap Content Analysis and Processing)");
            System.out.println("What would you like to search for today?");
            System.out.println("");

            while(menuBoi != -1)
            {

                System.out.println("(1) Look for and send webhosts recieving http request to VT");
                System.out.println("(2) Grab results from (1) from VT and email webhost analysis report to gmail.");
                System.out.println("(-1) Quit :(");
                System.out.println("");


                menuBoi = userInput.nextInt();


                if(menuBoi == 1)
                {
                    //http get request stuff goes here
                  System.out.println("Starting GET request analysis.");
                  httpGetModels = pcapParsing.getRequestParsing(foundTcpPackets); // Grabs GET request from TCP packets

                  System.out.println("Parsed for GET request, found:" + httpGetModels.size());

                  System.out.println("");
                  System.out.println("Found " + pcapParsing.getUniqueWebhost().size() + " unique web domains"); // Grabs unique webhost from GET request
                  System.out.println("Sending web domains to Virus Total for analysis");
                  System.out.println("");

                 analysis.getRequestAnalysis(pcapParsing.getUniqueWebhost(),virusTotalAPI); // Sends webhost to Virus Total
                 urlIds = analysis.getUrlIds();

                }
                else if(menuBoi == 2)
                {
                    if(urlIds.size() != 0)
                    {


                   models =  virusTotal.getUrlReports(urlIds,virusTotalAPI); // Gets reports from Virus Total
                   gmail.sendReports(models,email,emailPassword); // Preps and sends report to gmail



                    }
                    else
                    {
                        System.out.println("Run option 1 before trying to grab reports");
                    }
                }
                else if(menuBoi == 3)
                {

                }

            }
        }
        else
        {
            System.out.println("No analysis for you");
        }
    }
}
