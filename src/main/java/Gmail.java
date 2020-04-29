import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.ArrayList;
import java.util.Properties;

public class Gmail {
    private String report;
    private Properties properties;
    private Session session;
    private Message message;
    private Transport transport;


    public void sendReports(ArrayList<VTUrlReportModel> models, String gmail, String password) // Sends report via gmail
    {
        properties = new Properties();
        ReportConstructions constructions = new ReportConstructions();
        report = constructions.constructWebhostsReport(models);

        properties.put("mail.smtp.host", "smtp.gmail.com"); // Setups email service properties
        properties.put("mail.smtp.port", "587");
        properties.put("mail.smtp.auth", "true");
        properties.put("mail.smtp.starttls.enable", "true");

        session = Session.getInstance(properties,new javax.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() { // Sets up username and password
                return new PasswordAuthentication(gmail, password);
            }
        });

        message = new MimeMessage(session);
        try {

            message.setFrom(new InternetAddress(gmail));    // Create new message
            message.setRecipient(Message.RecipientType.TO,new InternetAddress(gmail));
            message.setSubject("Webhost Analysis Report from PCAP");
            message.setText(report);
            transport = session.getTransport("smtp");

            transport.connect("smtp.gmail.com",gmail,password); // Also needs username and password here too. Sets up actual connection
            transport.sendMessage(message,message.getAllRecipients());
            transport.close();
        } catch (MessagingException e) {
            System.out.println("Error!! Issue with emailing report");
            System.out.println(e.getMessage());
        }

        System.out.print("Report sent successfully check for gmail @: " + gmail + "\n");


    }





}
