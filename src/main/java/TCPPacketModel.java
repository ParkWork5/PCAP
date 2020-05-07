import java.util.ArrayList;

public class TCPPacketModel {

    private String sourceIP, destIP,payload;
    private int sourcePort, destPort,headerLength;
    private long acknowledgementNumber,sequenceNumber,arrivalTime;
    private ArrayList<String> flagsSet;


    public TCPPacketModel(String sourceIP, String destIP, String payload, int sourcePort, int destPort, long acknowledgementNumber,long sequenceNumber,ArrayList<String> flagsSet,long arrivalTime,int headerLength) {
        this.sourceIP = sourceIP;    // Data model for TCP packets
        this.destIP = destIP;
        this.payload = payload;
        this.flagsSet = flagsSet;
        this.sourcePort = sourcePort;
        this.destPort = destPort;
        this.acknowledgementNumber = acknowledgementNumber;
        this.sequenceNumber = sequenceNumber;
        this.arrivalTime = arrivalTime;
        this.headerLength = headerLength;


    }

    public String getSourceIP() {
        return sourceIP;
    }

    public void setSourceIP(String sourceIP) {
        this.sourceIP = sourceIP;
    }

    public String getDestIP() {
        return destIP;
    }

    public void setDestIP(String destIP) {
        this.destIP = destIP;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(int sourcePort) {
        this.sourcePort = sourcePort;
    }

    public int getDestPort() {
        return destPort;
    }

    public void setDestPort(int destPort) {
        this.destPort = destPort;
    }

    public long getAcknowledgementNumber() {
        return acknowledgementNumber;
    }

    public void setAcknowledgementNumber(long acknowledgementNumber) {
        this.acknowledgementNumber = acknowledgementNumber;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public ArrayList<String> getFlagsSet() {
        return flagsSet;
    }

    public void setFlagsSet(ArrayList<String> flagsSet) {
        this.flagsSet = flagsSet;
    }

    public int getHeaderLength() {
        return headerLength;
    }

    public void setHeaderLength(int headerLength) {
        this.headerLength = headerLength;
    }

    public long getArrivalTime() {
        return arrivalTime;
    }

    public void setArrivalTime(long arrivalTime) {
        this.arrivalTime = arrivalTime;
    }
}
