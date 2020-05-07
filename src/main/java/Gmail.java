import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Properties;

public class Gmail {
    private Properties properties;
    private Session session;
    private Message message;
    private Transport transport;


    public void sendReports(String report, String gmail, String password, String emailSubject) // Sends report via gmail
    {
        properties = new Properties();


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
            message.setSubject(emailSubject);
            message.setText(report);
            transport = session.getTransport("smtp");

            transport.connect("smtp.gmail.com",gmail,password); // Also needs username and password here too. Sets up actual connection
            System.out.println("Sending email");
            transport.sendMessage(message,message.getAllRecipients());
            transport.close();
        } catch (MessagingException e) {
            System.out.println("Error!! Issue with emailing report");
            System.out.println(e.getMessage());
        }

        System.out.print("Report sent successfully check for gmail @: " + gmail + "\n");


    }





}
