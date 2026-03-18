import java.io.Serializable;
import java.util.Map;

public class Packet implements Serializable {

    public String type;
    public String senderId;

    public String publicKeyBase64;

    public String encryptedData;

    public String encryptedPayloadBase64;

    public String encryptedGroupKeyBase64;

    public String signatureBase64;

    public Map<String,String> clientPublicKeys;
}