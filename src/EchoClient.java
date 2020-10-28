

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

public class EchoClient {

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private KeyStore cybr372KeyStore;
    private SecretKey sessionKey;
    private SecretKey clienttoserver;
    private SecretKey servertoclient;
    private String keyString = null;
    private int messageCount = 0;
    private String encrpytion = "RSA/ECB/PKCS1Padding";
    private String signing = "SHA256withRSA";
    private int sessionLength;

    /**
     * Setup the two way streams.
     *
     * @param ip the address of the server
     * @param port port used by the server
     *
     */
    public void startConnection(String ip, int port){
        try {
            clientSocket = new Socket(ip, port);
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
        } catch (IOException e) {
            System.out.println("Error when initializing connection");
        }
    }

    /**
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     * @param clientPass - the client password for the keystore
     */
    public String sendMessage(String msg, String clientPass) throws  KeyManagementException, ShortBufferException, InvalidAlgorithmParameterException, KeyStoreException, UnrecoverableKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException {
        if(sessionLength <= messageCount) {
            throw new java.security.KeyManagementException();
        }
        System.out.println("Client sending cleartext "+msg);
        msg = padMessage(msg);
        byte[] data = msg.getBytes("UTF-8");

        messageCount++;
        int myTLen = 128;
        byte[] initVector = new byte[16];
        new SecureRandom().nextBytes(initVector);

        //Create the GCM parameter
        GCMParameterSpec gcm = new GCMParameterSpec(myTLen,initVector);
        String messageC = Integer.toString(messageCount);
        //Add padding to string when required to make it the right size.
        while(messageC.length() < 4) {
            messageC = "0" + messageC;
        }
        String authen = "authentication";

        String extraLength = Integer.toString(authen.length() + msg.length());
        while(extraLength.length() < 4) {
            extraLength = "0" + extraLength;
        }
        String authentication = messageC + extraLength + authen + msg;
        //Hash the authentication
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(authentication.getBytes("UTF-8"));
        BigInteger number = new BigInteger(1, hash);
        StringBuilder hexString = new StringBuilder(number.toString(16));
        while (hexString.length() < 32)
        {
            hexString.insert(0, '0');
        }
        String clientS = hexString.toString();

        //Encrypt with the derived session key for client to server
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,clienttoserver,gcm);
        cipher.updateAAD(clientS.getBytes());
        byte[] cipherBytes = new byte[cipher.getOutputSize(data.length)];
        cipher.doFinal(data,0,data.length,cipherBytes);

        Base64.Encoder en = Base64.getEncoder();
        System.out.println("Client sending ciphertext "+ new String(en.encode(cipherBytes)));

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        //Send to the server
        outputStream.write(initVector);
        outputStream.write(messageC.getBytes());
        outputStream.write(cipherBytes);
        outputStream.write(clientS.getBytes());
        int length = outputStream.toByteArray().length;
        String padding = "";
        while(length <256) {
            padding = padding +" ";
            length++;
        }

        out.write(outputStream.toByteArray());
        out.flush();

        byte[] incoming = new byte[256];
        in.read(incoming);

        //Read in the incoming data
        byte[] aad = null;
        byte[] outinitVector = Arrays.copyOfRange(incoming,0,16);
        byte[] inputData = Arrays.copyOfRange(incoming,20,68);
        byte[] mess = Arrays.copyOfRange(incoming,16,20);
        int messageCounter = Integer.parseInt(new String(mess,"UTF-8"));
        //Check that the message count matches
        if (messageCounter < messageCount) {
            //Replay attack
            throw new SecurityException();
        } else if (messageCounter != messageCount) {
            //Out of order
            throw new AssertionError();
        }
        aad = Arrays.copyOfRange(incoming,68,132);
        GCMParameterSpec outgcm = new GCMParameterSpec(128,outinitVector);
        //Decrypt with the derived session key for server to client
        cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,servertoclient,outgcm);
        cipher.updateAAD(aad);
        byte[] outcipherBytes = cipher.doFinal(inputData);
        String output = new String(outcipherBytes,"UTF-8");
        System.out.println("Client received cleartext " + output);



        return output;

    }

    /**
     * Pad a message so that the message is always 32 bytes
     * @param message - message to send
     * @return
     */
    public String padMessage(String message) {
        while (message.length()<32) {
            message = message + " ";
        }
        return message;
    }

    /**
     * Close down our streams.
     *
     */
    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            System.out.println("error when closing");
        }
    }

    /**
     * Initialise the keystore from the location provided
     * @param location - privided location
     * @param password - key store location
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public void keyStoring(String location, String password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException{
        File keyStoreLocation = null;
        KeyStore keyStore = KeyStore.getInstance("JKS");
        if(location != null) {
            keyStoreLocation = new File(location);
            keyStore.load(new FileInputStream(keyStoreLocation),password.toCharArray());
        }
        System.out.println("Stored keys at " + keyStoreLocation);
        cybr372KeyStore = keyStore;


    }

    /**
     * Generate the session key and send it to the server before verifying that the server sent it back.
     * @param clientPass - key store password for the client
     * @param session - length of the session that the key is valid for.
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws SignatureException
     * @throws IOException
     */
    public void generateAndSendKey(String clientPass,int session) throws KeyStoreException, UnrecoverableKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException {
        //Generate a random key for the session
        SecureRandom random = SecureRandom.getInstanceStrong();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128, random);
        SecretKey key = keyGen.generateKey();


        sessionKey = key;
        Base64.Encoder en = Base64.getEncoder();
        keyString = en.encodeToString(sessionKey.getEncoded());
        byte[] data = key.getEncoded();
        Cipher cipher = Cipher.getInstance(encrpytion);

        //Get the keys required from the key store.
        PublicKey serverPub =cybr372KeyStore.getCertificate("server").getPublicKey();
        PrivateKey clientPrivate = null;

        Key clientkey = cybr372KeyStore.getKey("client", clientPass.toCharArray());
        if(clientkey instanceof PrivateKey) {
            clientPrivate = (PrivateKey) clientkey;
        }
        cipher.init(Cipher.ENCRYPT_MODE, serverPub);

        byte[] cipherBytes = cipher.doFinal(data);
        System.out.println("Client sending ciphertext "+ new String(en.encode(cipherBytes)));

        //Sign the message
        Signature sig = Signature.getInstance(signing);
        sig.initSign(clientPrivate);
        sig.update(data);
        byte[] signatureBytes = sig.sign();
        out.write(cipherBytes);
        out.write(signatureBytes);
        out.flush();
        byte[] incoming = new byte[256];
        byte [] insignatureBytes = new byte[256];
        in.read(incoming);
        // decrypt data
        in.read(insignatureBytes);
        cipher = Cipher.getInstance(encrpytion);
        cipher.init(Cipher.DECRYPT_MODE, clientPrivate);
        byte[] decryptedBytes = cipher.doFinal(incoming);
        String decOut = new String(decryptedBytes, "UTF-8");
        //Verify the signature
        Signature insig = Signature.getInstance(signing);
        insig.initVerify(serverPub);
        insig.update(decryptedBytes);
        boolean signatureValid = insig.verify(insignatureBytes);
        if(signatureValid) {
            System.out.println("Signature Valid");
        } else {
            System.out.println("Signature Invalid");
            throw new SignatureException();
        }
        generateKeys();
        sessionLength = session;
    }

    /**
     * Generate the keys that are derived from the session key
     */
    public void generateKeys(){
        Base64.Encoder en = Base64.getEncoder();

        String input = keyString + "toserver";

        clienttoserver = new SecretKeySpec(input.getBytes(),"AES");
        input = keyString + "toclient";
        servertoclient = new SecretKeySpec(input.getBytes(),"AES");
    }


    /**
     * Arguments in order keyStorageLocation, keyStorage password, client password, session length
     * @param args
     */
    public static void main(String[] args) {
        EchoClient client = new EchoClient();

        if(args.length != 4) {
            System.out.println("Please enter the correct parameters. keyStorageLocation, keyStorage password, client password, session length");
            return;
        }
        String location = args[0];
        String keyPassword = args[1];
        String clientpass = args[2];
        int session = Integer.parseInt(args[3]);

        try {
            client.keyStoring(location, keyPassword);

            client.startConnection("127.0.0.1", 4444);
            client.generateAndSendKey(clientpass, session);
            System.out.println("Keys exchanged");
            client.sendMessage("12345678901234567890123456789012", clientpass);
            client.sendMessage("ABCDEFGH", clientpass);
            client.sendMessage("87654321", clientpass);
            client.sendMessage("1",clientpass);
            client.sendMessage("HGFEDCBA", clientpass);

            client.stopConnection();
        } catch (NoSuchAlgorithmException e){
            System.out.println("That algorithm can't be found. Please try again");
        } catch (NoSuchPaddingException e) {
            System.out.println("There isn't enough padding for this encryption. Please try again");
        } catch (InvalidKeyException e) {
            System.out.println("That isn't a valid key. Please try again and enter a valid key");
        } catch (IllegalBlockSizeException e) {
            System.out.println("There is not enough space for this cipher. Please try again");
        } catch (BadPaddingException e) {
            System.out.println("There isn't enough padding for this encryption. Please try again.");
        } catch (SignatureException e) {
            System.out.println("The signature doesn't match. This message may not be from the right person");
        } catch (IOException e) {
            System.out.println("There is an issue reading or writing. Please check that the location provided for the key store is correct and the client is functioning correctly and try again");
        } catch (IllegalArgumentException e) {
            System.out.println("A Key should be longer than 2 bytes. Please try again with a valid key");
        } catch (NullPointerException e) {
            System.out.println("Please start the Server before the Client. Please give the public key to the server first");
        } catch (KeyStoreException e) {
            System.out.println("That isn't a valid key. Please try again and enter a valid key.");
        }catch (CertificateException e) {
            System.out.println("There is an issue with the Key Store. Please try again and enter a valid key");
        } catch (UnrecoverableKeyException e) {
            System.out.println("That key isn't valid. Please try again");
        } catch (InvalidAlgorithmParameterException e ) {
            System.out.println("Invalid Alogrithm. Please try again");
        } catch (ShortBufferException e) {
            System.out.println("There is an error with the buffer. Please try again");
        } catch (AssertionError e) {
            System.out.println("The message count doesn't match so the messages are out of order. Please try again");
        } catch (SecurityException e) {
            System.out.println("Replay Attack Detected. This message has be received before");
        } catch (KeyManagementException e ) {
            System.out.println("This session key has been used for as long as possible. Please choose a new session key");
        }
    }
}
