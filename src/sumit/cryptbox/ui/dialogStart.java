
package sumit.cryptbox.ui;

import javax.swing.JOptionPane;
import java.security.SecureRandom;
import javacardx.crypto.*;
import javacard.security.*;

//import applets.SimpleApplet;
import java.io.UnsupportedEncodingException;
import static java.lang.System.exit;
import simpleapdu.CardMngr;
import javax.smartcardio.ResponseAPDU;
import java.security.NoSuchAlgorithmException;

import javacard.framework.ISO7816;
//import javacard.framework.ISOException;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;

/*THIS IS THE FIRST INIT DIALOG CLASS WHICH GETS INVOKED*/
public class dialogStart extends javax.swing.JDialog
{   

    /**
     *
     */
    public String strMessageDigestAlgorithm;
    public int intPasswordHashIteration;
    public String strPassword;
    public boolean boolCryptAction;
    public boolean boolOriginalFileDelete;
    public boolean boolStart;
    
    
    /*JAVA CARD DETAILS*/
    static CardMngr cardManager = new CardMngr();
       private static byte APPLET_AID[] = {(byte) 0x73, (byte) 0x69, (byte) 0x6D, (byte) 0x70, (byte) 0x6C, 
        (byte) 0x65, (byte) 0x61, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    private static byte SELECT_SIMPLEAPPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, 
        (byte) 0x73, (byte) 0x69, (byte) 0x6D, (byte) 0x70, (byte) 0x6C,
        (byte) 0x65, (byte) 0x61, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    
    // INSTRUCTIONS
    final static byte CLA_SIMPLEAPPLET               = (byte) 0xB0;
    final static byte INS_ENCRYPT                    = (byte) 0x50;
    final static byte INS_DECRYPT                    = (byte) 0x51;
    final static byte INS_SETKEY                     = (byte) 0x52;
    final static byte INS_HASH                       = (byte) 0x53;
    final static byte INS_RANDOM                     = (byte) 0x54;
    final static byte INS_SETKEY_MAC                 = (byte) 0x5a;
    final static byte INS_MAC                        = (byte) 0x5b;
    final static byte INS_SK                        = (byte) 0x50; 
    final static byte INS_PASSWORD                   = (byte) 0x65; 
    private static AESKey m_aesKey                  = null;
    private static Cipher m_encryptCipher           = null;
    private static Cipher m_decryptCipher           = null;
  
    
    public static final int AES_KEY_LEN = 32;
    public static final int MAC_LEN = 16;
    public static final int CT_LEN = 80;
    public static final int RX_CMD_ERR = 0;
    public static final int CMD_DECODE_SUCCESS = 1;
    
    
    private static byte PIN[] = new byte[4];
    private static byte NEW_PIN[] = new byte[4];
    private static byte RP[] = new byte[MAC_LEN];       
    private static byte RC[] = new byte[MAC_LEN];       
    private static byte SK[] = new byte[AES_KEY_LEN];   
    private static byte MK[] = new byte[AES_KEY_LEN];   
    private static byte hash[] = new byte[AES_KEY_LEN]; 
    private static byte tag[] = new byte[MAC_LEN];      
    private static byte PL[] = new byte[CT_LEN];        
    private static byte Password[] = new byte[AES_KEY_LEN];   
    private static byte decmessage[] = new byte[48];   
    private static byte encmessage[] = new byte[AES_KEY_LEN];


    
    //Random data generation
    public static byte[] CryptRandGen(int len_cryptrand){
        SecureRandom secureRandomGen = new SecureRandom();
        byte randnum[] = new byte[len_cryptrand];
        secureRandomGen.nextBytes(randnum);
        System.out.println("generated random no: " +cardManager.bytesToHex(randnum));
        return randnum;
    }
   
    //****************************************************
    private static boolean checknonces(byte[] res_nonce) {
       try{
            if((byte)(RP[15]+1) == res_nonce[15])
                return true;
        }
        catch (Exception ex) {
            System.out.println("Exception checknonces: " + ex);
        }
       return false;
    }

    
    private static void sendtoJC(byte[] message, String type) {
        try {           
            // TODO: prepare proper APDU command
            short additionalDataLen = (short) message.length;
            byte apdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
            apdu[CardMngr.OFFSET_CLA] = (byte) CLA_SIMPLEAPPLET;
            if(type.equals("SessionKey"))
                apdu[CardMngr.OFFSET_INS] = (byte) INS_SK;
            if(type.equals("Password"))
                apdu[CardMngr.OFFSET_INS] = (byte) INS_PASSWORD;
            apdu[CardMngr.OFFSET_P1] = (byte) 0x00;
            apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
            apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
            //System.out.println("additionalDataLen:" +additionalDataLen);
            System.arraycopy(message, 0, apdu, ISO7816.OFFSET_CDATA, additionalDataLen);

            //byte [] response = new byte[16];
            ResponseAPDU output = cardManager.sendAPDU(apdu);
            byte [] response = output.getData();          
        
            if(type.equals("SessionKey"))
                System.arraycopy(response, 0, PL, 0, 64);
            if(type.equals("Password"))                 
                System.arraycopy(response, 0, PL, 0, 80);         
                        
        } catch (Exception ex) {
            System.out.println("Exception SendtoJC: " + ex);
        }
    }
    public static void aes256Encrypt(byte[] message) {
        try{            
            //m_aesKey.setKey(SK, (short) 0); 
            //if ((message.length % 16) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);             
            m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);            
            m_encryptCipher.doFinal(message, (short) 0, (short) message.length, encmessage, (short) 0);
        }
        catch (Exception ex) {
            System.out.println("Exception aes_enc: " + ex);
        }        
        
    }
    
    
    public static void aes256Decrypt(byte[] ciphertext) {
        try{
            
            m_aesKey.setKey(SK, (short) 0);
            //System.out.println("session key that was set is:" +cardManager.bytesToHex(SK));
            //System.out.println("ciphertext received is:" +cardManager.bytesToHex(ciphertext));
            //if ((ciphertext.length % 16) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);            
            m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
            m_decryptCipher.doFinal(ciphertext, (short) 0, (short) ciphertext.length, decmessage, (short) 0);
            System.out.println("decrypted message is:" +cardManager.bytesToHex(decmessage));
        }
        catch (Exception ex) {
            System.out.println("Exception aes_dec : " + ex);
        }
    }
     public static boolean decryptJCResponse(byte[] PL, String type) {
        try{
            
            byte response_p1[] = new byte[32];
            byte response_p11[] = new byte[48];
            byte response_p2[] = new byte[32];
            byte response_RP[] = new byte[16];            
            byte response_mac[] = new byte [32];
            
            if(type.equals("SessionKey")){
                System.arraycopy(PL, 0, response_p1, 0, 32); //encrypted[(RP+1) followed by RC]
                System.arraycopy(PL, 32, response_p2, 0, 32); //MAC
            }
            else if (type.equals("Password")){
                System.arraycopy(PL, 0, response_p11, 0, 48); //encrypte[(RP+3) followed by Password]
                System.arraycopy(PL, 48, response_p2, 0, 32); //MAC
            }
            else
                System.out.println("Unknown Command Type");
            
            // Check MAC
            MessageDigest hash2;// = null;
            hash2 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            if(type.equals("SessionKey"))
                hash2.doFinal(response_p1, (short)0, (short)32, response_mac, (short)0 );
            else if (type.equals("Password"))
                hash2.doFinal(response_p11, (short)0, (short)48, response_mac, (short)0 );            
            //System.out.println("\nOrignal MAC in decryptJCResponse=" +cardManager.bytesToHex(response_p2));
            //System.out.println("\nCalculated MAC in decryptJCResponse=" +cardManager.bytesToHex(response_mac));
            else
                System.out.println("Unknown Command Type");
            
            if(!(java.util.Arrays.equals(response_mac, response_p2)))
            {
               System.out.println("JC Response Error for Integrity");
               return false;
            }
            //Decrypt AES payload            
            System.out.println("decrypting the received payload....");
            if(type.equals("SessionKey")){
                aes256Decrypt(response_p1);
                System.arraycopy(decmessage, 16, RC, 0, 16);
            }
            else if (type.equals("Password")){
                aes256Decrypt(response_p11);
                System.arraycopy(decmessage, 16, Password, 0, 32);
            }            
            else
                System.out.println("Unknown Command Type");
            
            System.arraycopy(decmessage, 0, response_RP, 0, 16);            
            
            //Check nonces
            if(checknonces(response_RP)){
                return true;
            }    
            else return false;
        } catch (Exception ex) {
            System.out.println("Exception nonces: " + ex);
        }    
        return false;
    }
     
    public static int JavaCardProtocol(  ) throws UnsupportedEncodingException, NoSuchAlgorithmException{
                      
            System.out.println("JavaCardProtocol Function");
            
            // FOR KEY SETUP  
            System.out.println("------------------Setting up session key------------------");
            byte cmdBuf[] = new byte[20];
            //byte skapdu[] = new byte[160];
            byte challenge1_buf[] = new byte[52];
            byte challenge2_mac[] =  new byte[32];
            byte challenge2_buf[] = new byte[64];            
            RP = CryptRandGen(16);
            System.arraycopy(PIN, 0, cmdBuf, 0, 4);
            System.arraycopy(RP, 0, cmdBuf, 4, 16);
            System.out.println("input for generating Session key: " +cardManager.bytesToHex(cmdBuf));
            
            //calculate SessionKey
            MessageDigest hash1; //= null;
            hash1 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            hash1.doFinal(cmdBuf, (short)0, (short)20, hash, (short)0 );
   
            System.out.println("sha256 hashed output: " +cardManager.bytesToHex(hash));
            //System.arraycopy(encCmdBuf, 0, skapdu, 0, 128);
            System.arraycopy(cmdBuf, 0, challenge1_buf, 0, 20);
            System.arraycopy(hash, 0, challenge1_buf, 20, 32); 
            sendtoJC(challenge1_buf,"SessionKey");
   
            SK = hash;//hash IS the sessionkey.
            m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
            m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false); 
            m_decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);            
            m_aesKey.setKey(SK, (short) 0);

            if(decryptJCResponse(PL,"SessionKey"))
                System.out.println("Session Key is set Successfully");
            else System.out.println("Failed to Set Session Key");

            // To get Password
            System.out.println("---------------Getting file encryption key------------------");
            byte buf[] = new byte[32];
            RP[15]++;
            RP[15]++;
            System.arraycopy(RP, 0, buf, 0, 16);
            RC[15]++;
            System.arraycopy(RC, 0, buf, 16, 16);
            System.out.println("Encrypting the payload for sending....");
            
            //encrypt the payload
            aes256Encrypt(buf);
            System.arraycopy(encmessage, 0, challenge2_buf, 0, 32);
            
            //find the MAC of the encrypted message
            MessageDigest hash2; //= null;
            hash2 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            hash2.doFinal(encmessage, (short)0, (short)32, challenge2_mac, (short)0 );
            System.arraycopy(challenge2_mac, 0, challenge2_buf, 32, 32);
            sendtoJC(challenge2_buf, "Password");

            if(decryptJCResponse(PL, "Password"))
                System.out.println("Successfully generated Password from javacard");
            else System.out.println("Failed to generate Password");             
       
        return 1;    
        
    }
 
    
    
    public dialogStart(boolean blnArgCryptAction)
    {
        initComponents();
        
        this.setLocationRelativeTo(null);
        getRootPane().setDefaultButton(btnCancel);
        
        //Set Crypt Action radio button
        if(blnArgCryptAction == true)
        {
            rdoEncrypt.setSelected(true);
            rdoDecrypt.setSelected(false);
        }
        else
        {
            rdoEncrypt.setSelected(false);
            rdoDecrypt.setSelected(true);
        }
        
        /*Set Initial Value*/
        intPasswordHashIteration = 100;
        strPassword = "";
        boolOriginalFileDelete = true;
        boolStart = false;
        
        /*Assign Values to UI Control*/
        txtPasswordHashIteration.setText(String.valueOf(intPasswordHashIteration));
        passFieldPassword.setText(strPassword);
        passFieldRePassword.setText(strPassword);
        rdBtnYes.setSelected(boolOriginalFileDelete);
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">                          
    private void initComponents() {

        btnGroupCryptAction = new javax.swing.ButtonGroup();
        btnGroupOriginalFileOption = new javax.swing.ButtonGroup();
        panelNote = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        panelCryptographyOption = new javax.swing.JPanel();
        lblMessageDigestAlgorithm = new javax.swing.JLabel();
        cmbMessageDigestAlgorithm = new javax.swing.JComboBox();
        lblPasswordHashIteration = new javax.swing.JLabel();
        txtPasswordHashIteration = new javax.swing.JTextField();
        lblPassword = new javax.swing.JLabel();
        passFieldPassword = new javax.swing.JPasswordField();
        lblRePassword = new javax.swing.JLabel();
        passFieldRePassword = new javax.swing.JPasswordField();
        paneloriginalFileOption = new javax.swing.JPanel();
        lblOriginalFileOption = new javax.swing.JLabel();
        rdBtnNo = new javax.swing.JRadioButton();
        rdBtnYes = new javax.swing.JRadioButton();
        btnCancel = new javax.swing.JButton();
        btnOK = new javax.swing.JButton();
        panelCryptAction = new javax.swing.JPanel();
        rdoEncrypt = new javax.swing.JRadioButton();
        rdoDecrypt = new javax.swing.JRadioButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Start");
        setModal(true);

        panelNote.setBorder(javax.swing.BorderFactory.createTitledBorder("Note"));

        jLabel1.setText("<html>\n<b>PBE (Password Based Encryption) = hashing + symmetric encryption</b>\n<br></br>\n<br></br>\nA 64 bit random number (the salt) is added to the password and hashed using a Message Digest Algorithm (e.g. MD5).\n<br></br>\nNumber of times the password is hashed is determined by the interation count.  Adding a random number and hashing multiple times enlarges the key space.\n<br></br>\n<br></br>\n<b>Be carefull while setting the password to encrypt file</b>\n<br></br>\n<br></br>\nIf password is lost, then there may not be any possibililty to retrive the password.\n<br></br>\nThis will lead to unsuccessful decryption of encrypted file and hence encrypted file may not be used forever.\n</html>");

        javax.swing.GroupLayout panelNoteLayout = new javax.swing.GroupLayout(panelNote);
        panelNote.setLayout(panelNoteLayout);
        panelNoteLayout.setHorizontalGroup(
            panelNoteLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelNoteLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(20, Short.MAX_VALUE))
        );
        panelNoteLayout.setVerticalGroup(
            panelNoteLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
        );

        panelCryptographyOption.setBorder(javax.swing.BorderFactory.createTitledBorder("Cryptography Option"));

        lblMessageDigestAlgorithm.setText("Message Digest Algorithm");

        cmbMessageDigestAlgorithm.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "PBEWithMD5AndDES" }));

        lblPasswordHashIteration.setText("Password Hash Iteration");

        lblPassword.setText("PIN");

        lblRePassword.setText("Re PIN");

        javax.swing.GroupLayout panelCryptographyOptionLayout = new javax.swing.GroupLayout(panelCryptographyOption);
        panelCryptographyOption.setLayout(panelCryptographyOptionLayout);
        panelCryptographyOptionLayout.setHorizontalGroup(
            panelCryptographyOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelCryptographyOptionLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(panelCryptographyOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(lblPassword, javax.swing.GroupLayout.PREFERRED_SIZE, 99, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(panelCryptographyOptionLayout.createSequentialGroup()
                        .addGroup(panelCryptographyOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lblPasswordHashIteration)
                            .addComponent(lblMessageDigestAlgorithm)
                            .addComponent(lblRePassword))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(panelCryptographyOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(passFieldPassword)
                            .addComponent(txtPasswordHashIteration)
                            .addComponent(passFieldRePassword)
                            .addComponent(cmbMessageDigestAlgorithm, 0, 274, Short.MAX_VALUE))))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        panelCryptographyOptionLayout.setVerticalGroup(
            panelCryptographyOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelCryptographyOptionLayout.createSequentialGroup()
                .addGap(14, 14, 14)
                .addGroup(panelCryptographyOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblMessageDigestAlgorithm)
                    .addComponent(cmbMessageDigestAlgorithm, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(panelCryptographyOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblPasswordHashIteration)
                    .addComponent(txtPasswordHashIteration, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(panelCryptographyOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lblPassword)
                    .addComponent(passFieldPassword, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(panelCryptographyOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(passFieldRePassword, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblRePassword))
                .addContainerGap(15, Short.MAX_VALUE))
        );

        paneloriginalFileOption.setBorder(javax.swing.BorderFactory.createTitledBorder("Original File Option"));

        lblOriginalFileOption.setText("<html>Do you want to <b>delete the original file</b> after cryptography?\n<br></br>\n<br></br>\nIf Yes is selected, then original file will be deleted after successful\n<br></br>\ncryptographic action.</html>");

        btnGroupOriginalFileOption.add(rdBtnNo);
        rdBtnNo.setText("No");
        rdBtnNo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdBtnNoActionPerformed(evt);
            }
        });

        btnGroupOriginalFileOption.add(rdBtnYes);
        rdBtnYes.setSelected(true);
        rdBtnYes.setText("Yes");
        rdBtnYes.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rdBtnYesActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout paneloriginalFileOptionLayout = new javax.swing.GroupLayout(paneloriginalFileOption);
        paneloriginalFileOption.setLayout(paneloriginalFileOptionLayout);
        paneloriginalFileOptionLayout.setHorizontalGroup(
            paneloriginalFileOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(paneloriginalFileOptionLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(paneloriginalFileOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(paneloriginalFileOptionLayout.createSequentialGroup()
                        .addComponent(lblOriginalFileOption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addContainerGap(24, Short.MAX_VALUE))
                    .addGroup(paneloriginalFileOptionLayout.createSequentialGroup()
                        .addComponent(rdBtnYes)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(rdBtnNo)
                        .addGap(112, 112, 112))))
        );
        paneloriginalFileOptionLayout.setVerticalGroup(
            paneloriginalFileOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(paneloriginalFileOptionLayout.createSequentialGroup()
                .addComponent(lblOriginalFileOption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(paneloriginalFileOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(rdBtnYes)
                    .addComponent(rdBtnNo)))
        );

        btnCancel.setText("Cancel");
        btnCancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCancelActionPerformed(evt);
            }
        });

        btnOK.setText("OK");
        btnOK.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnOKActionPerformed(evt);
            }
        });

        panelCryptAction.setBorder(javax.swing.BorderFactory.createTitledBorder("Crypt Action"));

        btnGroupCryptAction.add(rdoEncrypt);
        rdoEncrypt.setSelected(true);
        rdoEncrypt.setText("Encrypt");

        btnGroupCryptAction.add(rdoDecrypt);
        rdoDecrypt.setText("Decrypt");

        javax.swing.GroupLayout panelCryptActionLayout = new javax.swing.GroupLayout(panelCryptAction);
        panelCryptAction.setLayout(panelCryptActionLayout);
        panelCryptActionLayout.setHorizontalGroup(
            panelCryptActionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelCryptActionLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(rdoEncrypt)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(rdoDecrypt)
                .addGap(90, 90, 90))
        );
        panelCryptActionLayout.setVerticalGroup(
            panelCryptActionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelCryptActionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(rdoEncrypt)
                .addComponent(rdoDecrypt))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(btnOK)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnCancel))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(panelCryptographyOption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(paneloriginalFileOption, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(panelCryptAction, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                    .addComponent(panelNote, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(panelNote, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(panelCryptographyOption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(panelCryptAction, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(paneloriginalFileOption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnCancel)
                    .addComponent(btnOK))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>                        

    //<editor-fold defaultstate="collapsed" desc="Close dialogStart - btnCancelActionPerformed">
    private void btnCancelActionPerformed(java.awt.event.ActionEvent evt) {                                          
        try
        {
            this.dispose();
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(this, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
        }
    }                                         
    //</editor-fold>
    
        
    //BVG
            public void initJavaCard() {
        try {
                     //CHECK THE CONNECTIVITY. IF YES, PROCEED, ELSE THROUW ERROR
                System.out.println("**************INITIALIAING JAVA CARD");      
              
          if (cardManager.ConnectToCard()) 
         {
                // Select our application on card
                cardManager.sendAPDU(SELECT_SIMPLEAPPLET);
                
           //    ResponseAPDU output = cardManager.sendAPDU(apdu); //send set key command
                   
                //discontnnect the card
             //  cardManager.DisconnectFromCard();
             
            } 
            
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
       //   JOptionPane.showMessageDialog(this, ex, "JAVA CARD INIT FAILED", JOptionPane.ERROR_MESSAGE);
         //   JOptionPane.showMessageDialog(this, ex, "JAVA CARD INIT FAILED", "JAVA CARD INIT FAILED");
                JOptionPane.showMessageDialog(this, "JAVA CARD INIT FAILED.\n\nTHE PROGRAM WILL TERMINATE NOW", "CryptBox Password Mismatch", JOptionPane.ERROR_MESSAGE);
                
                exit(0);
        }
    }
    
    
    //<editor-fold defaultstate="collapsed" desc="OK dialogStart - btnOKActionPerformed">
    private void btnOKActionPerformed(java.awt.event.ActionEvent evt) {                                      
        try
        {
            //if(CheckPassword(new String(passFieldPassword.getPassword()), new String(passFieldRePassword.getPassword())) == 0 && CheckPasswordHashIteration(txtPasswordHashIteration.getText()) == 0)
            if( (new String(passFieldPassword.getPassword())).length() == 4 && (new String(passFieldRePassword.getPassword())).length() == 4 && CheckPasswordHashIteration(txtPasswordHashIteration.getText()) == 0)
            {
            //    initSimulator();

                String strPin = new String(passFieldPassword.getPassword());
                System.arraycopy(strPin.getBytes(), 0, PIN, 0, 4);
                
                String strNewPin = new String(passFieldRePassword.getPassword());
                System.arraycopy(strNewPin.getBytes(), 0, NEW_PIN, 0, 4);

                
                PIN[0] = (byte) (PIN[0] - 0x30);
                PIN[1] = (byte) (PIN[1] - 0x30);
                PIN[2] = (byte) (PIN[2] - 0x30);
                PIN[3] = (byte) (PIN[3] - 0x30);
                
                NEW_PIN[0] = (byte) (NEW_PIN[0] - 0x30);
                NEW_PIN[1] = (byte) (NEW_PIN[1] - 0x30);
                NEW_PIN[2] = (byte) (NEW_PIN[2] - 0x30);
                NEW_PIN[3] = (byte) (NEW_PIN[3] - 0x30);       
              
               //BVG
              initJavaCard();
              
             // *********************************
                JavaCardProtocol( );
             //****************************
             
                       
                  
                strMessageDigestAlgorithm = cmbMessageDigestAlgorithm.getSelectedItem().toString();
                intPasswordHashIteration = Integer.parseInt(txtPasswordHashIteration.getText());
             //   strPassword = new String(toHex(Password));
             
                strPassword = new String(Password.toString());
                System.out.println("Password generated in card for file encryption is: "+ cardManager.bytesToHex(Password));
                if(rdoEncrypt.isSelected() == true)
                {
                    boolCryptAction = true;
                }
                else
                {
                    boolCryptAction = false;
                }
                if(rdBtnYes.isSelected() == true)
                {
                    boolOriginalFileDelete = true;
                }
                else
                {
                    boolOriginalFileDelete = false;
                }
                
                boolStart = true;
                
                this.dispose();
            }
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(this, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
        }
    }                                     

    private void rdBtnYesActionPerformed(java.awt.event.ActionEvent evt) {                                         
        // TODO add your handling code here:
        
    }                                        

    private void rdBtnNoActionPerformed(java.awt.event.ActionEvent evt) {                                        
        // TODO add your handling code here:
       
    }                                       
    //</editor-fold>
    
    //<editor-fold defaultstate="collapsed" desc="Check Password and RePassword match - CheckPassword">
    private int CheckPassword(String strPassword, String strRePassword)
    {
        int intStatus = 1;
        
        try
        {
            if(strPassword.compareTo(strRePassword) == 0)
            {
                intStatus = 0;
            }
            else
            {
                intStatus = 1;
                
                JOptionPane.showMessageDialog(this, "Password and Re Password does not matches.\n\nPlease try again.", "CryptBox Password Mismatch", JOptionPane.ERROR_MESSAGE);
            }
            
            return intStatus;
        }
        catch (Exception ex)
        {
            JOptionPane.showMessageDialog(this, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
            
            return intStatus;
        }
    }
    //</editor-fold>
    
    //<editor-fold defaultstate="collapsed" desc="Check PasswordHashIteration is within 1 - 1000 - CheckPasswordHashIteration">
    private int CheckPasswordHashIteration(String strValue)
    {
        try
        {
            int intValue;
            
            intValue = Integer.parseInt(strValue);
            
            if(intValue < 1 || intValue > 1000)
            {
                JOptionPane.showMessageDialog(this, "Please enter integer value between 1 to 1000", "CryptBox Error", JOptionPane.ERROR_MESSAGE);
                
                return 1;
            }
            
            return 0;
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(this, ex + "\n\nPlease enter integer number and retry", "CryptBox Error", JOptionPane.ERROR_MESSAGE);
            
            return 1;
        }
    }
    //</editor-fold>
    
    // Variables declaration - do not modify                     
    private javax.swing.JButton btnCancel;
    private javax.swing.ButtonGroup btnGroupCryptAction;
    private javax.swing.ButtonGroup btnGroupOriginalFileOption;
    private javax.swing.JButton btnOK;
    private javax.swing.JComboBox cmbMessageDigestAlgorithm;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel lblMessageDigestAlgorithm;
    private javax.swing.JLabel lblOriginalFileOption;
    private javax.swing.JLabel lblPassword;
    private javax.swing.JLabel lblPasswordHashIteration;
    private javax.swing.JLabel lblRePassword;
    private javax.swing.JPanel panelCryptAction;
    private javax.swing.JPanel panelCryptographyOption;
    private javax.swing.JPanel panelNote;
    private javax.swing.JPanel paneloriginalFileOption;
    private javax.swing.JPasswordField passFieldPassword;
    private javax.swing.JPasswordField passFieldRePassword;
    private javax.swing.JRadioButton rdBtnNo;
    private javax.swing.JRadioButton rdBtnYes;
    private javax.swing.JRadioButton rdoDecrypt;
    private javax.swing.JRadioButton rdoEncrypt;
    private javax.swing.JTextField txtPasswordHashIteration;
    // End of variables declaration                   
}
