import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;

public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private SecretKey sessionKey = null;
    private String keyString = null;
    private int messageCount = 0;
    private SecretKey clienttoserver;
    private SecretKey servertoclient;
    private KeyStore cybr372KeyStore;
    private String encrpytion = "RSA/ECB/PKCS1Padding";
    private String signing = "SHA256withRSA";

    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port, String serverPass) throws  ShortBufferException, InvalidAlgorithmParameterException, KeyStoreException, UnrecoverableKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException{
        serverSocket = new ServerSocket(port);
        clientSocket = serverSocket.accept();
        out = new DataOutputStream(clientSocket.getOutputStream());
        in = new DataInputStream(clientSocket.getInputStream());
        byte[] data = new byte[256];
        byte[] insignatureBytes = new byte[256];
        int numBytes;
        while ((numBytes = in.read(data)) != -1) {
            //If this is the first message from the client, then it is the session key
            if(sessionKey == null) {
                exchangeMasterKey(insignatureBytes, serverPass,data);
                generateKeys();
            } else {
                //Else it is a general message
                messageCount++;
                byte[] aad = null;
                //Read in the incoming data
                byte[] initVector = Arrays.copyOfRange(data,0,16);
                byte[] inputData = Arrays.copyOfRange(data,20,68);
                byte[] mess = Arrays.copyOfRange(data,16,20);
                int messageC = Integer.parseInt(new String(mess,"UTF-8"));
                if (messageC < messageCount) {
                    //Replay attack
                    throw new SecurityException();
                } else if (messageC != messageCount) {
                    //Out of order
                    throw new AssertionError();
                }
                aad = Arrays.copyOfRange(data,68,132);

                //Decrpyt the message
                Base64.Encoder en = Base64.getEncoder();
                GCMParameterSpec gcm = new GCMParameterSpec(128,initVector);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE,clienttoserver,gcm);
                cipher.updateAAD(aad);
                byte[] cipherBytes = cipher.doFinal(inputData);
                String output = new String(cipherBytes,"UTF-8");
                System.out.println("Server received cleartext "+output);

                //Encryption
                byte[] outData = output.getBytes("UTF-8");
                int myTLen = 128;
                byte[] outinitVector = new byte[16];
                new SecureRandom().nextBytes(outinitVector);

                GCMParameterSpec outgcm = new GCMParameterSpec(myTLen,outinitVector);
                String messageCounter = Integer.toString(messageCount);
                //Add padding where required
                while(messageCounter.length() < 4) {
                    messageCounter = "0" + messageCounter;
                }
                String authen = "authentication";

                String extraLength = Integer.toString(authen.length() + output.length());
                while(extraLength.length() < 4) {
                    extraLength = "0" + extraLength;
                }
                String authentication = messageCounter + extraLength + authen + output;
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
                //Encrypt with the derived session key for server to client
                cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE,servertoclient,outgcm);

                cipher.updateAAD(clientS.getBytes());
                byte[] outcipherBytes = new byte[cipher.getOutputSize(outData.length)];
                cipher.doFinal(outData,0,outData.length,outcipherBytes);
                System.out.println("Server sending ciphertext "+ new String(en.encode(outcipherBytes)));
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                outputStream.write(outinitVector);
                outputStream.write(messageCounter.getBytes());
                outputStream.write(outcipherBytes);
                outputStream.write(clientS.getBytes());

                out.write(outputStream.toByteArray());
                out.flush();

            }


        }
        stop();


    }

    /**
     * Generate the derived keys for the session
     */
    public void generateKeys() {
        Base64.Encoder en = Base64.getEncoder();
        String input = keyString + "toserver";

        clienttoserver = new SecretKeySpec(input.getBytes(),"AES");
        input = keyString + "toclient";
        servertoclient = new SecretKeySpec(input.getBytes(),"AES");

    }

    /**
     * Read in the session key that the client has provided and send it back to the client
     * @param insignatureBytes
     * @param serverPass
     * @param data
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
    public void exchangeMasterKey(byte[] insignatureBytes, String serverPass, byte[] data)  throws  KeyStoreException, UnrecoverableKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException {
        in.read(insignatureBytes);
        Key key = cybr372KeyStore.getKey("server", serverPass.toCharArray());
        PrivateKey serverPri = null;

        if(key instanceof PrivateKey) {
            serverPri = (PrivateKey) key;
        }

        PublicKey clientPub =  cybr372KeyStore.getCertificate("client").getPublicKey();



        Cipher cipher = Cipher.getInstance(encrpytion);
        cipher.init(Cipher.DECRYPT_MODE, serverPri);

        byte[] decryptedBytes = cipher.doFinal(data);
        sessionKey = new SecretKeySpec(decryptedBytes, "AES");
        System.out.println("Key Received");
        Base64.Encoder en = Base64.getEncoder();
        keyString = en.encodeToString(sessionKey.getEncoded());

        Signature insig = Signature.getInstance(signing);
        insig.initVerify(clientPub);
        insig.update(decryptedBytes);
        boolean signatureValid = insig.verify(insignatureBytes);

        if(signatureValid) {
            System.out.println("Signature Valid");
        } else {
            System.out.println("Signature Invalid");
            throw new SignatureException();
        }

        // encrypt response

        cipher = Cipher.getInstance(encrpytion);
        cipher.init(Cipher.ENCRYPT_MODE, clientPub);

        byte[] cipherBytes = cipher.doFinal(decryptedBytes);
        System.out.println("Server sending ciphertext "+ new String(en.encode(cipherBytes)));

        Signature sig = Signature.getInstance(signing);
        sig.initSign(serverPri);
        sig.update(decryptedBytes);
        byte[] signatureBytes = sig.sign();
        out.write(cipherBytes);
        out.write(signatureBytes);
        out.flush();
    }

    /**
     * Close the streams and sockets.
     *
     */
    public void stop() {
        try {
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    /**
     * Find the key Storage
     * @param location
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public void keyStoring(String location, String keyPass) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        File keyStoreLocation = null;
        KeyStore keyStore = KeyStore.getInstance("JKS");
        if(location != null) {
            keyStoreLocation = new File(location);
            keyStore.load(new FileInputStream(keyStoreLocation),keyPass.toCharArray());
        }

        System.out.println("Stored keys at " + keyStoreLocation);

        cybr372KeyStore = keyStore;

    }

    /**
     * Arguments in order keyStorageLocation, keyStorage password, server password
     * @param args
     */
    public static void main(String[] args){
        EchoServer server = new EchoServer();
        try {
            if (args.length != 3) {
                System.out.println(args);
                System.out.println("Please enter the correct parameters. keyStorageLocation, keyStorage password, server password");
                return;
            }
            String location = args[0];
            String keyPassword = args[1];
            String serverPass = args[2];
            server.keyStoring(location, keyPassword);
            System.out.println("Waiting to complete Exchange");
            server.start(4444, serverPass);
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
            System.out.println("There is an issue reading or writing. Please check that the location provided for the key store is correct and the server is functioning correctly and try again");
        } catch (IllegalArgumentException e) {
            System.out.println("A Key should be longer than 2 bytes. Please try again with a valid key");
        } catch (KeyStoreException e) {
            System.out.println("There is an issue with the key store. Please try again");
        } catch (CertificateException e) {
            System.out.println("There is an issue with the Certificate. Please try again");
        } catch (ShortBufferException e) {
            System.out.println("There is an error with the buffer. Please try again");
        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("There is an issue with the encryption. Please try again");
        } catch (UnrecoverableKeyException e) {
            System.out.println("That key can't be recovered. Please try again");
        } catch (AssertionError e) {
            System.out.println("The message count doesn't match so the messages are out of order. Please try again");
        } catch (SecurityException e) {
            System.out.println("Replay Attack Detected. This message has be received before");
        }

    }

}



