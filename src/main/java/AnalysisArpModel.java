import java.util.HashSet;
import java.util.Set;

public class AnalysisArpModel {  // Model for arp spoofing analysis

    private String macAddress;
    private Set<String> ipAddresses;
    private Boolean spoofing;

    public AnalysisArpModel(String macAddress) {
        this.macAddress = macAddress;
        ipAddresses = new HashSet<>();
    }

    public void addIpAddresses(String ipAddress)
    {
        ipAddresses.add(ipAddress);
    }

    public String getSourceMAC() {
        return macAddress;
    }

    public Set<String> getIpAddresses() {
        return ipAddresses;
    }

    public Boolean getSpoofing() {
        return spoofing;
    }

    public void setSpoofing(Boolean spoofing) {
        this.spoofing = spoofing;
    }
}
