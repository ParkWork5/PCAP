public class ArpModel {

    private String destIp, sourceIp, destMACAddress, sourceMACAddress; // Model for stoirng general informaiton about arp packet
    private long arrivalTime;

    public ArpModel(String destIp, String sourceIp, String destMACAddress, String sourceMACAddress, long arrivalTime) {
        this.destIp = destIp;
        this.sourceIp = sourceIp;
        this.destMACAddress = destMACAddress;
        this.sourceMACAddress = sourceMACAddress;
        this.arrivalTime = arrivalTime;
    }

    public String getDestIp() {
        return destIp;
    }

    public void setDestIp(String destIp) {
        this.destIp = destIp;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public String getDestMACAddress() {
        return destMACAddress;
    }

    public void setDestMACAddress(String destMACAddress) {
        this.destMACAddress = destMACAddress;
    }

    public String getSourceMACAddress() {
        return sourceMACAddress;
    }

    public void setSourceMACAddress(String sourceMACAddress) {
        this.sourceMACAddress = sourceMACAddress;
    }

    public long getArrivalTime() {
        return arrivalTime;
    }

    public void setArrivalTime(long arrivalTime) {
        this.arrivalTime = arrivalTime;
    }
}

