package sumit.cryptbox.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.swing.JOptionPane;

public class Utility
{
    //<editor-fold defaultstate="collapsed" desc="Encrypt File - EncryptFile">
    public int EncryptFile(String strFileName, String strMessageDigestAlgorithm, int intPasswordHashIteration, String strPassword, String strExtension) throws Exception
    {
        FileInputStream objFileInputStream;
        FileOutputStream objFileOutputStream;
        
        try
        {
            // File to encrypt.  It does not have to be a text file!
            // Password must be at least 8 characters (bytes) long
            objFileInputStream = new FileInputStream(strFileName);
            objFileOutputStream = new FileOutputStream(strFileName + "." + strExtension);

            // Use PBEKeySpec to create a key based on a password.
            // The password is passed as a character array
            PBEKeySpec objPBEKeySpec = new PBEKeySpec(strPassword.toCharArray());
            //SecretKeyFactory objSecretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKeyFactory objSecretKeyFactory = SecretKeyFactory.getInstance(strMessageDigestAlgorithm);
            SecretKey objSecretKey = objSecretKeyFactory.generateSecret(objPBEKeySpec);

            // PBE = hashing + symmetric encryption.  A 64 bit random
            // number (the salt) is added to the password and hashed
            // using a Message Digest Algorithm (MD5 in this example.).
            // The number of times the password is hashed is determined
            // by the interation count.  Adding a random number and
            // hashing multiple times enlarges the key space.
            byte[] byteSalt = new byte[8];
            Random objRandom = new Random();
            objRandom.nextBytes(byteSalt);
            //int intIteration = 100;
            int intIteration = intPasswordHashIteration;

            //Create the parameter spec for this salt and interation count
            PBEParameterSpec objPBEParameterSpec = new PBEParameterSpec(byteSalt, intIteration);

            // Create the cipher and initialize it for encryption.
            Cipher objCipher = Cipher.getInstance("PBEWithMD5AndDES");
            objCipher.init(Cipher.ENCRYPT_MODE, objSecretKey, objPBEParameterSpec);

            // Need to write the salt to the (encrypted) file.  The
            // salt is needed when reconstructing the key for decryption.
            objFileOutputStream.write(byteSalt);

            // Read the file and encrypt its bytes.
            byte[] byteInput = new byte[64];
            int intRead;
            while ((intRead = objFileInputStream.read(byteInput)) != -1)
            {
                byte[] byteOutput = objCipher.update(byteInput, 0, intRead);
                if (byteOutput != null)
                {
                    objFileOutputStream.write(byteOutput);
                }
            }

            byte[] byteOutput = objCipher.doFinal();
            if (byteOutput != null)
            {
                objFileOutputStream.write(byteOutput);
            }

            objFileInputStream.close();
            objFileOutputStream.flush();
            objFileOutputStream.close();

            return 0;
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(null, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
            
            return 1;
        }
    }
    //</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="Decrypt File - DecryptFile">
    public int DecryptFile(String strFileName, String strMessageDigestAlgorithm, int intPasswordHashIteration, String strPassword, String strExtension) throws Exception
    {
        FileInputStream objFileInputStream;
        FileOutputStream objFileOutputStream;
        
        try
        {
            // File to decrypt.
            // Password must be at least 8 characters (bytes) long
            objFileInputStream = new FileInputStream(strFileName);
            objFileOutputStream = new FileOutputStream(strFileName.substring(0, strFileName.length() - strExtension.length() - 1));
            
            PBEKeySpec objPBEKeySpec = new PBEKeySpec(strPassword.toCharArray());
            //SecretKeyFactory objSecretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKeyFactory objSecretKeyFactory = SecretKeyFactory.getInstance(strMessageDigestAlgorithm);
            SecretKey objSecretKey = objSecretKeyFactory.generateSecret(objPBEKeySpec);
            
            // Read in the previouly stored salt and set the iteration count.
            byte[] byteSalt = new byte[8];
            objFileInputStream.read(byteSalt);
            //int intIteration = 100;
            int intIteration = intPasswordHashIteration;
            
            PBEParameterSpec objPBEParameterSpec = new PBEParameterSpec(byteSalt, intIteration);
            
            // Create the cipher and initialize it for decryption.
            Cipher objCipher = Cipher.getInstance("PBEWithMD5AndDES");
            objCipher.init(Cipher.DECRYPT_MODE, objSecretKey, objPBEParameterSpec);
            
            byte[] byteInput = new byte[64];
            int intRead;
            while ((intRead = objFileInputStream.read(byteInput)) != -1)
            {
                byte[] byteOutput = objCipher.update(byteInput, 0, intRead);
                if (byteOutput != null)
                {
                    objFileOutputStream.write(byteOutput);
                }
            }
            
            byte[] byteOutput = objCipher.doFinal();
            if (byteOutput != null)
            {
                objFileOutputStream.write(byteOutput);
            }
            
            objFileInputStream.close();
            objFileOutputStream.flush();
            objFileOutputStream.close();

            return 0;
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(null, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
            
            return 1;
        }
    }
    //</editor-fold>
    
    //<editor-fold defaultstate="collapsed" desc="Delete File - DeleteFile">
    public int DeleteFile(String strFileName) throws Exception
    {
        int intStatus = 1;
        
        try
        {
            File objFile = new File(strFileName);
            
            if(objFile.delete() == true)
            {
                intStatus = 0;
            }
            else
            {
                intStatus = 1;
            }
            
            return intStatus;
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(null, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
            
            return 1;
        }
    }
    //</editor-fold>
}
