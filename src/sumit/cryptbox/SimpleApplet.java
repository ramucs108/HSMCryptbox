/*
 * PACKAGEID: 4C 61 62 61 6B
 * APPLETID: 4C 61 62 61 6B 41 70 70 6C 65 74
 */

 //STG3 - WITH JAVACARD - 04MAY2017 0930HRS,1050HRS, 11HRS

package applets;

/*
 * Imported packages
 */
// specific import for Javacard API access
//import java.util.Arrays;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import javacard.security.KeyBuilder;
//import simpleapdu.CardMngr;

    /**
     *THIS IS THE MAIN APPLETOF JAVA SIMPLEAPPLET
     */
public class SimpleApplet extends javacard.framework.Applet
{
     //  CardMngr cardmanager = new CardMngr();
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET                = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_ENCRYPT                    = (byte) 0x5f;
    final static byte INS_DECRYPT                    = (byte) 0x51;
    final static byte INS_SETKEY                     = (byte) 0x52;
    final static byte INS_HASH                       = (byte) 0x53;
    final static byte INS_RANDOM                     = (byte) 0x54;
    final static byte INS_VERIFYPIN                  = (byte) 0x55;
    final static byte INS_SETPIN                     = (byte) 0x56;
    final static byte INS_RETURNDATA                 = (byte) 0x57;
    final static byte INS_SIGNDATA                   = (byte) 0x58;
    final static byte INS_GETAPDUBUFF                = (byte) 0x59;
    final static byte INS_SETKEY_MAC                 = (byte) 0x5a;
    final static byte INS_MAC                        = (byte) 0x5b;  
    final static byte INS_SK                         = (byte) 0x50;
    final static byte INS_PASSWORD                    = (byte) 0x65;
    
    final static short ARRAY_LENGTH                   = (short) 0xff;
    final static byte  AES_BLOCK_LENGTH               = (short) 0x16;

    final static short SW_BAD_TEST_DATA_LEN          = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD             = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD     = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE       = (short) 0x6711;
    final static short SW_BAD_PIN                    = (short) 0x6900;
    final static short SW_BAD_NONCE                  = (short) 0x6901;
    final static short SW_BAD_MAC                    = (short) 0x6902;

    private   AESKey         m_aesKey = null;
    private   AESKey         m_aesKey_mac = null;
    private   Cipher         m_encryptCipher = null;
    private   Cipher         m_decryptCipher = null;
    private   Cipher         m_encryptCipher_mac = null;
    private   Cipher         m_decryptCipher_mac = null;
    private   RandomData     m_secureRandom = null;
    private   MessageDigest  m_hash = null;  
   // private   Signature      m_sign = null;
   
    private   short               m_apduLogOffset = (short) 0;
    // TEMPORARRY ARRAY IN RAM
    private   byte                m_ramArray[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private   byte                m_dataArray[] = null;
    private   byte    RP[] = new byte[16]; 
    private   byte    PIN[] = new byte[16]; // Including Padding (4 + 12)
    private   byte    RC[] = new byte[16];
    private   byte sessionkey[] = new byte[32];
   private   static Cipher       rsaCipher = null;
    private   static RSAPublicKey pubkey = null;

    /**
     * LabakApplet default constructor
     * Only this class's install method should create the applet object.
     */
    protected SimpleApplet(byte[] buffer, short offset, byte length)
    {
        // data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        short dataOffset = offset;
        boolean isOP2 = false;

        if(length > 9) {
            // Install parameter detail. Compliant with OP 2.0.1.

            // | size | content
            // |------|---------------------------
            // |  1   | [AID_Length]
            // | 5-16 | [AID_Bytes]
            // |  1   | [Privilege_Length]
            // | 1-n  | [Privilege_Bytes] (normally 1Byte)
            // |  1   | [Application_Proprietary_Length]
            // | 0-m  | [Application_Proprietary_Bytes]

            // shift to privilege offset
            dataOffset += (short)( 1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short)( 1 + buffer[dataOffset]);

           // <IF NECESSARY, USE COMMENTS TO CHECK LENGTH >
           // // checks wrong data length
           // if(buffer[dataOffset] !=  <PUT YOUR PARAMETERS LENGTH> )
           //     // return received proprietary data length in the reason
           //     ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH + offset + length - dataOffset));

            // go to proprietary data
            dataOffset++;

            m_dataArray = new byte[ARRAY_LENGTH];
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);

            // CREATE AES KEY OBJECT
            m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
            m_aesKey_mac = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
            // CREATE OBJECTS FOR CBC CIPHERING
            m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_encryptCipher_mac = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_decryptCipher_mac = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            
            // CREATE RANDOM DATA GENERATORS
             m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);

            // SET KEY VALUE
            m_aesKey.setKey(m_dataArray, (short) 0);
            m_aesKey_mac.setKey(m_dataArray, (short) 0);

            // INIT CIPHERS WITH NEW KEY
            m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
            m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
            m_encryptCipher_mac.init(m_aesKey_mac, Cipher.MODE_ENCRYPT);
            m_decryptCipher_mac.init(m_aesKey_mac, Cipher.MODE_DECRYPT);           

           
            // INIT HASH ENGINE
            try {
                m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            }
            catch (CryptoException e) {
               // HASH ENGINE NOT AVAILABLE
            }

            // update flag
            isOP2 = true;

        } else {
           // <IF NECESSARY, USE COMMENTS TO CHECK LENGTH >
           // if(length != <PUT YOUR PARAMETERS LENGTH> )
           //     ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH + length));
       }

        // <PUT YOUR CREATION ACTION HERE>

        // register this instance
          register();
    }

    /**
     * Method installing the applet.
     * @param bArray the array constaining installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        // applet  instance creation 
        new SimpleApplet (bArray, bOffset, bLength);
    }

    /**
     * Select method returns true if applet selection is supported.
     * @return boolean status of selection.
     */
    public boolean select()
    {
        // <PUT YOUR SELECTION ACTION HERE>
        
      return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect()
    {

        // <PUT YOUR DESELECTION ACTION HERE>

        return;
    }

    /**
     * Method processing an incoming APDU.
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
    public void process(APDU apdu) throws ISOException
    {
        // get the APDU buffer
        byte[] apduBuffer = apdu.getBuffer();
        //short dataLen = apdu.setIncomingAndReceive();
        //Util.arrayCopyNonAtomic(apduBuffer, (short) 0, m_dataArray, m_apduLogOffset, (short) (5 + dataLen));
        //m_apduLogOffset = (short) (m_apduLogOffset + 5 + dataLen);

        // ignore the applet select command dispached to the process
        if (selectingApplet())
            return;
        //System.out.println("INS="+apduBuffer[ISO7816.OFFSET_INS]);
        // APDU instruction parser
        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
            switch ( apduBuffer[ISO7816.OFFSET_INS] )
            {
                case INS_SETKEY: SetKey(apdu); break;
                case INS_SETKEY_MAC: SetMACKey(apdu); break;
                case INS_MAC: computeMAC(apdu); break;
                case INS_ENCRYPT: Encrypt(apdu); break;
                case INS_DECRYPT: Decrypt(apdu); break;
                case INS_HASH: Hash(apdu); break;
                case INS_RANDOM: Random(apdu); break;
                case INS_RETURNDATA: ReturnData(apdu); break;
                case INS_GETAPDUBUFF: GetAPDUBuff(apdu); break;
                case INS_SK: Hash_SK(apdu); break;
                case INS_PASSWORD: genPassword(apdu); break;
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;
            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    // SET ENCRYPTION & DECRYPTION KEY
    void SetKey(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // CHECK EXPECTED LENGTH
      if ((short) (dataLen * 8) != KeyBuilder.LENGTH_AES_256) ISOException.throwIt(SW_KEY_LENGTH_BAD);

      // SET KEY VALUE
      m_aesKey.setKey(apdubuf, ISO7816.OFFSET_CDATA);

      // INIT CIPHERS WITH NEW KEY
      m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
      m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
    }
    
    
    // SET ENCRYPTION & DECRYPTION KEY
    void SetMACKey(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // CHECK EXPECTED LENGTH
      if ((short) (dataLen * 8) != KeyBuilder.LENGTH_AES_256) ISOException.throwIt(SW_KEY_LENGTH_BAD);

      // SET KEY VALUE
      m_aesKey_mac.setKey(apdubuf, ISO7816.OFFSET_CDATA);

      // INIT CIPHERS WITH NEW KEY
      m_encryptCipher_mac.init(m_aesKey_mac, Cipher.MODE_ENCRYPT);
      m_encryptCipher_mac.init(m_aesKey_mac, Cipher.MODE_DECRYPT);
    }
    

    
    // ENCRYPT INCOMING BUFFER
     void Encrypt(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      short     i;

      // CHECK EXPECTED LENGTH (MULTIPLY OF 64 bites)
      if ((dataLen % 16) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);

      // ENCRYPT INCOMING BUFFER
      m_encryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);

      // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
      Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

      // SEND OUTGOING BUFFER
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

    // DECRYPT INCOMING BUFFER
    void Decrypt(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      short     i;

      // CHECK EXPECTED LENGTH (MULTIPLY OF 64 bites)
      if ((dataLen % 8) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);

      // ENCRYPT INCOMING BUFFER
      m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);

      // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
      Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

      // SEND OUTGOING BUFFER
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

    
    // ENCRYPT INCOMING BUFFER
     void computeMAC(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      short     i;

      // CHECK EXPECTED LENGTH (MULTIPLY OF 64 bites)
      if ((dataLen % 16) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);

      // ENCRYPT INCOMING BUFFER
      m_encryptCipher_mac.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);

      // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
      Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

      // SEND OUTGOING BUFFER
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }    
     
     // HASH INCOMING BUFFER
     void Hash_SK(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      //short     dataLen = apdu.setIncomingAndReceive();
      byte[]    apdubuf_mac = new byte[32];
      byte[]    ReceivedRP = new byte[16]; 
      
      // APDU data is (PIN+RP), MAC
      //System.out.println("PIN+RP: " +cardmanager.bytesToHex(apdubuf));      
      byte [] hashOut = new byte[32];
      byte [] hashIn = new byte[20];
      byte [] RPandRC = new byte[32];
      byte [] encOut = new byte[32];
      byte [] macOut = new byte[32];
      //byte [] bufOut = new byte[32];
      
      Util.arrayCopyNonAtomic(apdubuf, (short)ISO7816.OFFSET_CDATA, hashIn, (short)0, (short)20);
       //System.out.println("input data for hash engine in applet:" +cardmanager.bytesToHex(hashIn));
      
      if (m_hash != null) {
          //m_hash.doFinal(apdubuf, (short)5, (short)20, m_ramArray, (short) 0);
          m_hash.doFinal(hashIn, (short)0, (short)20, hashOut, (short) 0);          
      }
      else ISOException.throwIt(SW_OBJECT_NOT_AVAILABLE);
      
      Util.arrayCopyNonAtomic(apdubuf, (short)25, apdubuf_mac, (short)0, (short)32);
      //System.out.println("\nOrignal MAC=" +cardmanager.bytesToHex(apdubuf_mac));
      //System.out.println("\nCalculated MAC=" +cardmanager.bytesToHex(hashOut));
      
      //check MAC of the incoming apdu payload
	 //CBHSM  if(java.util.Arrays.equals(hashOut, apdubuf_mac))
	  if( Util.arrayCompare(hashOut,(short)0, apdubuf_mac,(short)0,(short)32)==0)
		 {
          //System.out.println("Integrity check on received apdu is successful in applet!!");          
          //copy RP from apdu
          Util.arrayCopyNonAtomic(apdubuf, (short)(ISO7816.OFFSET_CDATA + 4), ReceivedRP, (short)0, (short)16);
          Util.arrayCopyNonAtomic(ReceivedRP, (short)0, RP, (short)0, (short)16);
          Util.arrayCopyNonAtomic(apdubuf, (short)ISO7816.OFFSET_CDATA, PIN, (short)0, (short)4);
          
            // For Padding
            Util.arrayCopyNonAtomic(apdubuf, (short)ISO7816.OFFSET_CDATA, PIN, (short)4, (short)4);
            Util.arrayCopyNonAtomic(apdubuf, (short)ISO7816.OFFSET_CDATA, PIN, (short)8, (short)4);
            Util.arrayCopyNonAtomic(apdubuf, (short)ISO7816.OFFSET_CDATA, PIN, (short)12, (short)4);
            
          ReceivedRP[15]++;
          m_secureRandom.generateData(RC, (short) 0, (short) 16);
          //System.out.println("nonce generated by javacard is: "+cardmanager.bytesToHex(RC));
          
          Util.arrayCopyNonAtomic(ReceivedRP, (short) 0, RPandRC, (short)0, (short)16);
          Util.arrayCopyNonAtomic(RC, (short) 0, RPandRC, (short)16, (short)16);
          //System.out.println("Session key in applet is: " +cardmanager.bytesToHex(hashOut));
          sessionkey = hashOut;
          
          //encrypt the outgoing apdu with sessionkey
          m_aesKey.setKey(sessionkey, (short)0);
          m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
          m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
          if ((RPandRC.length % 16) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);       
          m_encryptCipher.doFinal(RPandRC, (short) 0, (short) RPandRC.length, encOut, (short) 0); 
          //System.out.println("encryption output is: " +cardmanager.bytesToHex(encOut));
          
          //Calculate the MAC of outgoing encrypted apdu
          if (m_hash != null) {
          //m_hash.doFinal(apdubuf, (short)5, (short)20, m_ramArray, (short) 0);
          m_hash.doFinal(encOut, (short)0, (short)32, macOut, (short) 0);          
          }
          else ISOException.throwIt(SW_OBJECT_NOT_AVAILABLE);

          // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
          Util.arrayCopyNonAtomic(encOut, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short)32);
          Util.arrayCopyNonAtomic(macOut, (short) 0, apdubuf, (short)(ISO7816.OFFSET_CDATA + 32), (short)32);

          // SEND OUTGOING BUFFER
          apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 64);       
        }
        else ISOException.throwIt(SW_BAD_MAC);
   }  
     
    
    void genPassword(APDU apdu){ 
      byte[]    apdubuf = apdu.getBuffer();
      byte[]    apdubuf_mac = new byte[32];  
      byte[]    ReceivedRP = new byte[16]; 
      byte[]    ReceivedRC = new byte[16];    
      byte [] hashOut = new byte[32];
      byte [] hashIn = new byte[32];
      byte [] Password = new byte[32];      
      byte [] decOut = new byte[32];
      byte [] macOut = new byte[32];   
      byte [] bufOut = new byte[48];
      byte [] bufOutEnc = new byte[48];
      byte [] PINandRP = new byte[32];
      

      //System.out.println("Inside Send_Password function");
      Util.arrayCopyNonAtomic(apdubuf, (short)ISO7816.OFFSET_CDATA, hashIn, (short)0, (short)32);
      //System.out.println("input for hash engine in applet in Send_Password:" +cardmanager.bytesToHex(hashIn));
       
      //Calculate MAC
      if (m_hash != null) {
          //m_hash.doFinal(apdubuf, (short)5, (short)20, m_ramArray, (short) 0);
          m_hash.doFinal(hashIn, (short)0, (short)32, hashOut, (short) 0);          
      }
      else ISOException.throwIt(SW_OBJECT_NOT_AVAILABLE);
      
      Util.arrayCopyNonAtomic(apdubuf, (short)(ISO7816.OFFSET_CDATA + 32), apdubuf_mac, (short)0, (short)32);
      //System.out.println("\nOrignal MAC=" +cardmanager.bytesToHex(apdubuf_mac));
      //System.out.println("\nCalculated MAC=" +cardmanager.bytesToHex(hashOut));
   
	  
		//CBHSM  if(java.util.Arrays.equals(hashOut, apdubuf_mac)){
	   if( Util.arrayCompare(hashOut,(short)0, apdubuf_mac,(short)0,(short)32)==0){
          //System.out.println("Password: Integrity check on received apdu is successful in applet!!");          
          //decrypt
          //m_aesKey.setKey(sessionkey, (short)0);
          //m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
          if ((hashIn.length % 16) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
          m_decryptCipher.doFinal(hashIn, (short) 0, (short) 32, decOut, (short) 0);
          
          //copy from decrypted
          Util.arrayCopyNonAtomic(decOut, (short) 0, ReceivedRP, (short)0, (short)16);     
          ReceivedRP[15] = (byte)(ReceivedRP[15]+ (short)1); // RP++
          Util.arrayCopyNonAtomic(decOut, (short) 16, ReceivedRC, (short)0, (short)16);
          RC[15] = (byte)(RC[15] + (short)1);//RC[15]++;
          
        //Freshness check
        //CBHSM  if(!(java.util.Arrays.equals(ReceivedRC, RC)))ISOException.throwIt(SW_BAD_NONCE);  
          if( Util.arrayCompare(ReceivedRC,(short)0, RC,(short)0,(short)16)!=0)ISOException.throwIt(SW_BAD_NONCE); 
          
           //what to go as input to AES engine need to be modified
           //Util.arrayCopyNonAtomic(ReceivedRP, (short) 0, RPandRC, (short)0, (short)16);
           //Util.arrayCopyNonAtomic(RC, (short) 0, RPandRC, (short)16, (short)16);           
            
           //Generate Password
           //m_aesKey.setKey(sessionkey, (short)0);
           //m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
           Util.arrayCopyNonAtomic(RP, (short) 0, PINandRP, (short)0, (short)16);
           Util.arrayCopyNonAtomic(PIN, (short) 0, PINandRP, (short)16, (short)16);
           
           
           if ((PINandRP.length % 16) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);       
           m_encryptCipher.doFinal(PINandRP, (short) 0, (short) PINandRP.length, Password, (short) 0); 
           //System.out.println("encryption output is: " +cardmanager.bytesToHex(encOut));

           //preparing apdu to send.
           Util.arrayCopyNonAtomic(ReceivedRP, (short) 0, bufOut, (short)0, (short)16);
           Util.arrayCopyNonAtomic(Password, (short) 0, bufOut, (short)16, (short)32);
           //System.out.println("Payload in applet in Set_Password: " +cardmanager.bytesToHex(bufOut));
           
           //m_aesKey.setKey(sessionkey, (short)0);
           //m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
           if ((bufOut.length % 16) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);       
           m_encryptCipher.doFinal(bufOut, (short) 0, (short) bufOut.length, bufOutEnc, (short) 0); 
           
           //calculate MAC
           if (m_hash != null) {            
              m_hash.doFinal(bufOutEnc, (short)0, (short)48, macOut, (short) 0);          
           }
           else ISOException.throwIt(SW_OBJECT_NOT_AVAILABLE);

           // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
           Util.arrayCopyNonAtomic(bufOutEnc, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short)48);
           Util.arrayCopyNonAtomic(macOut, (short) 0, apdubuf, (short)(ISO7816.OFFSET_CDATA + 48), (short)32);

           // SEND OUTGOING BUFFER
           apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 80);   
        }
        else ISOException.throwIt(SW_BAD_MAC);
    }    
     
     
     // HASH INCOMING BUFFER
     void Hash(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      
      
      if (m_hash != null) {
          m_hash.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);
      }
      else ISOException.throwIt(SW_OBJECT_NOT_AVAILABLE);

      // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
      Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, m_hash.getLength());
      if(ISO7816.OFFSET_P1==0){ // TO SET SK
        //if ((short) (dataLen * 8) != KeyBuilder.LENGTH_AES_256) ISOException.throwIt(SW_KEY_LENGTH_BAD);

        // SET KEY VALUE
        m_aesKey.setKey(apdubuf, ISO7816.OFFSET_CDATA);

        // INIT CIPHERS WITH NEW KEY
        m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
        m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
      }
      else{ // TO SET MK 
        //if ((short) (dataLen * 8) != KeyBuilder.LENGTH_AES_256) ISOException.throwIt(SW_KEY_LENGTH_BAD);

        // SET KEY VALUE
        m_aesKey_mac.setKey(apdubuf, ISO7816.OFFSET_CDATA);

        // INIT CIPHERS WITH NEW KEY
        m_encryptCipher_mac.init(m_aesKey_mac, Cipher.MODE_ENCRYPT);  
        m_decryptCipher_mac.init(m_aesKey_mac, Cipher.MODE_DECRYPT);
      } 
          
      // SEND OUTGOING BUFFER
      //apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, m_hash.getLength());
    }

    // GENERATE RANDOM DATA
     void Random(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // GENERATE DATA
      m_secureRandom.generateData(apdubuf, ISO7816.OFFSET_CDATA, apdubuf[ISO7816.OFFSET_P1]);

      // SEND OUTGOING BUFFER
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, apdubuf[ISO7816.OFFSET_P1]);
    }

     
     void ReturnData(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // RETURN INPU DATA UNCHANGED
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

   void GetAPDUBuff(APDU apdu) {
    byte[]    apdubuf = apdu.getBuffer();

    // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
    Util.arrayCopyNonAtomic(m_dataArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, m_apduLogOffset);
    short tempLength = m_apduLogOffset;
    m_apduLogOffset = 0;
    // SEND OUTGOING BUFFER
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, tempLength);
  }
  
   
}

