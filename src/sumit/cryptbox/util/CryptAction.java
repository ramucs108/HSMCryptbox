package sumit.cryptbox.util;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import javax.swing.JOptionPane;
import javax.swing.JProgressBar;
import javax.swing.JTable;
import javax.swing.SwingWorker;
import javax.swing.table.TableModel;
import sumit.cryptbox.ui.dialogReEnter;

public class CryptAction extends SwingWorker<Integer, String>
{
    DateFormat objDateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
    Date objDate = new Date();
    
    Utility objUtility = new Utility();
    
    String strMessageDigestAlgorithm;
    int intPasswordHashIteration;
    String strPassword;
    String strCryptAction;
    boolean boolOriginalFileDelete;
    String strCryptExtension;
    StringBuilder strBuilderMessage = new StringBuilder();
    JTable objJTable;
    TableModel objTableModel;
    JProgressBar objJProgressBar;
    
    public CryptAction(String strArgMessageDigestAlgorithm, int intArgPasswordHashIteration, String strArgPassword, String strArgCryptAction, boolean boolArgOriginalFileDelete, String strArgCryptExtension, StringBuilder strArgBuilderMessage, JTable objArgJTable, JProgressBar objArgJProgressBar)
    {
        this.strMessageDigestAlgorithm = strArgMessageDigestAlgorithm;
        this.intPasswordHashIteration = intArgPasswordHashIteration;
        this.strPassword = strArgPassword;
        this.strCryptAction = strArgCryptAction;
        this.boolOriginalFileDelete = boolArgOriginalFileDelete;
        this.strCryptExtension = strArgCryptExtension;
        this.strBuilderMessage = strArgBuilderMessage;
        this.objJTable = objArgJTable;
        this.objTableModel = this.objJTable.getModel();
        this.objJProgressBar = objArgJProgressBar;
    }
    
    // This method is invoked when the worker is finished its task
    @Override
    protected void done()
    {
        try
        {
            // Get the number of matches. Note that the 
            // method get will throw any exception thrown 
            // during the execution of the worker.
            int intTotalFileCount = get();
            publish(objDateFormat.format(objDate) + "  " + "Cryptography action for " + intTotalFileCount + " files are completed");
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(null, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    @Override
    protected void process(List<String> chunks)
    {
        for(String message : chunks)
        {
            strBuilderMessage.append(message + "\n");
        }
    }
    
    @Override
    protected Integer doInBackground() throws Exception
    {
        int intTotalFileCount = objTableModel.getRowCount();
        
        try
        {
            for(int i=0; i<objTableModel.getRowCount(); i++)
            {
                if(objTableModel.getValueAt(i, 1).toString().compareTo("In Queue") == 0)
                {
                    int intCryptAction = 0;
                    int intDelete = 0;
                    
                    objJTable.setValueAt("In progress", i, 1);
                    publish(objDateFormat.format(objDate) + "  " + "Cryptography action is in progress for \"" + objTableModel.getValueAt(i, 0).toString() + "\"");
                    
                    String strSelectedFileExtension = objTableModel.getValueAt(i, 0).toString().substring(objTableModel.getValueAt(i, 0).toString().lastIndexOf('.') + 1);
                    
                    if(strCryptAction.compareTo("encrypt") == 0)
                    {
                        if(strSelectedFileExtension.compareTo(strCryptExtension) == 0)
                        {
                            int intUserOption = JOptionPane.showConfirmDialog(null, "Are you sure to encrypt an encrypted file?\n\nYES - Encrypt an encrypted file\nNO - Decrypt an encrypted file\nCANCEL - Cancel encryption of an encrypted file", "CryptBox", JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.INFORMATION_MESSAGE);
                            if(intUserOption == JOptionPane.YES_OPTION)
                            {
                                EncryptAction(objTableModel.getValueAt(i, 0).toString(), strMessageDigestAlgorithm, intPasswordHashIteration, strPassword, i);
                            }
                            else if(intUserOption == JOptionPane.NO_OPTION)
                            {
                                DecryptAction(objTableModel.getValueAt(i, 0).toString(), strMessageDigestAlgorithm, intPasswordHashIteration, strPassword, i);
                            }
                            else if(intUserOption == JOptionPane.CANCEL_OPTION)
                            {
                                objJTable.setValueAt("Encrypting failed", i, 1);
                                objJTable.setValueAt("Encrypting file was terminated by user", i, 2);
                                publish(objDateFormat.format(objDate) + "  " + "Encrypting file was terminated by user");
                            }
                        }
                        else
                        {
                            EncryptAction(objTableModel.getValueAt(i, 0).toString(), strMessageDigestAlgorithm, intPasswordHashIteration, strPassword, i);
                        }
                    }
                    if(strCryptAction.compareTo("decrypt") == 0)
                    {
                        if(strSelectedFileExtension.compareTo(strCryptExtension) != 0)
                        {
                            int intUserOption = JOptionPane.showConfirmDialog(null, "Are you sure to decrypt a normal file?\n\nYES - Decrypt a normal file\nNO - Encrypt a normal file\nCANCEL - Cancel decryption of a normal file", "CryptBox", JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.INFORMATION_MESSAGE);
                            if(intUserOption == JOptionPane.YES_OPTION)
                            {
                                DecryptAction(objTableModel.getValueAt(i, 0).toString(), strMessageDigestAlgorithm, intPasswordHashIteration, strPassword, i);
                            }
                            else if(intUserOption == JOptionPane.NO_OPTION)
                            {
                                EncryptAction(objTableModel.getValueAt(i, 0).toString(), strMessageDigestAlgorithm, intPasswordHashIteration, strPassword, i);
                            }
                            else if(intUserOption == JOptionPane.CANCEL_OPTION)
                            {
                                objJTable.setValueAt("Decrypting failed", i, 1);
                                objJTable.setValueAt("Decrypting file was terminated by user", i, 2);
                                publish(objDateFormat.format(objDate) + "  " + "Decrypting file was terminated by user");
                            }
                        }
                        else
                        {
                            DecryptAction(objTableModel.getValueAt(i, 0).toString(), strMessageDigestAlgorithm, intPasswordHashIteration, strPassword, i);
                        }
                    }
                }
                else
                {
                    objJTable.setValueAt("No action taken", i, 1);
                    objJTable.setValueAt("The file is not in queue", i, 2);
                    publish(objDateFormat.format(objDate) + "  " + "No action taken because the file is not in queue");
                }
                
                // update the progress
                objJProgressBar.setValue((i+1) * 100 / intTotalFileCount);
                publish(objDateFormat.format(objDate) + "  " + "-----------------------------------------------");
            }
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(null, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
        }
        
        return intTotalFileCount;
    }
    
    private void EncryptAction(String strFileName, String strInterMessageDigestAlgorithm, int intInterPasswordHashIteration, String strInterPassword, int intTableRowNo)
    {
        int intCryptAction = 1;
        int intDelete = 1;
        
        try
        {
            do
            {
                objJTable.setValueAt("Encrypting file", intTableRowNo, 2);
                publish(objDateFormat.format(objDate) + "  " + "Encrypting file is in progress");
                
                intCryptAction = objUtility.EncryptFile(strFileName, strInterMessageDigestAlgorithm, intInterPasswordHashIteration, strInterPassword, strCryptExtension);
                
                if(intCryptAction == 0)
                {
                    objJTable.setValueAt("Encrypting file is successful", intTableRowNo, 2);
                    publish(objDateFormat.format(objDate) + "  " + "Encrypting file is successful");
                    
                    if(boolOriginalFileDelete == true)
                    {
                        objJTable.setValueAt("Deleting file", intTableRowNo, 2);
                        publish(objDateFormat.format(objDate) + "  " + "Deleting file is in progress");
                        
                        intDelete = objUtility.DeleteFile(strFileName);
                        
                        if(intDelete == 0)
                        {
                            objJTable.setValueAt("Encryption completed successfully", intTableRowNo, 1);
                            objJTable.setValueAt("Deleting file is successful", intTableRowNo, 2);
                            publish(objDateFormat.format(objDate) + "  " + "Encryption completed successfully and deleting file is successful");
                        }
                        else
                        {
                            objJTable.setValueAt("Encryption completed successfully with error", intTableRowNo, 1);
                            objJTable.setValueAt("Deleting file has failed", intTableRowNo, 2);
                            publish(objDateFormat.format(objDate) + "  " + "Encryption completed successfully with error because deleting file has failed");
                        }
                    }
                    else
                    {
                        objJTable.setValueAt("Encryption completed successfully", intTableRowNo, 1);
                        objJTable.setValueAt("File is not deleted", intTableRowNo, 2);
                        publish(objDateFormat.format(objDate) + "  " + "Encryption completed successfully and file is not deleted");
                    }
                }
                else
                {
                    objJTable.setValueAt("Encrypting file has failed. Waiting for user response", intTableRowNo, 2);
                    publish(objDateFormat.format(objDate) + "  " + "Encrypting file has failed. Waiting for user response");

                    dialogReEnter objDialogReEnter = new dialogReEnter();
                    objDialogReEnter.setVisible(true);

                    if(objDialogReEnter.boolReEnter == true)
                    {
                        strInterMessageDigestAlgorithm = objDialogReEnter.strMessageDigestAlgorithm;
                        intInterPasswordHashIteration = objDialogReEnter.intPasswordHashIteration;
                        strInterPassword = objDialogReEnter.strPassword;
                    }
                    else
                    {
                        objJTable.setValueAt("Encryption failed", intTableRowNo, 1);
                        objJTable.setValueAt("Encrypting file was terminated by user", intTableRowNo, 2);
                        publish(objDateFormat.format(objDate) + "  " + "Encrypting file was terminated by user");

                        intCryptAction = 0;
                    }
                }
            }while(intCryptAction == 1);
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(null, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
            
            try
            {
                objUtility.DeleteFile(strFileName + "." + strCryptExtension);
            }
            catch(Exception ex1)
            {
                JOptionPane.showMessageDialog(null, ex1, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    private void DecryptAction(String strFileName, String strInterMessageDigestAlgorithm, int intInterPasswordHashIteration, String strInterPassword, int intTableRowNo)
    {
        int intCryptAction = 1;
        int intDelete = 1;
        
        try
        {
            do
            {
                objJTable.setValueAt("Decrypting file", intTableRowNo, 2);
                publish(objDateFormat.format(objDate) + "  " + "Decrypting file is in progress");
                
                intCryptAction = objUtility.DecryptFile(strFileName, strInterMessageDigestAlgorithm, intInterPasswordHashIteration, strInterPassword, strCryptExtension);
                
                if(intCryptAction == 0)
                {
                    objJTable.setValueAt("Decrypting file is successful", intTableRowNo, 2);
                    publish(objDateFormat.format(objDate) + "  " + "Decrypting file is successful");
                    
                    if(boolOriginalFileDelete == true)
                    {
                        objJTable.setValueAt("Deleting file", intTableRowNo, 2);
                        publish(objDateFormat.format(objDate) + "  " + "Deleting file is in progress");
                        
                        intDelete = objUtility.DeleteFile(strFileName);
                        
                        if(intDelete == 0)
                        {
                            objJTable.setValueAt("Decryption completed successfully", intTableRowNo, 1);
                            objJTable.setValueAt("Deleting file is successful", intTableRowNo, 2);
                            publish(objDateFormat.format(objDate) + "  " + "Decryption completed successfully and deleting file is successful");
                        }
                        else
                        {
                            objJTable.setValueAt("Decryption completed successfully with error", intTableRowNo, 1);
                            objJTable.setValueAt("Deleting file has failed", intTableRowNo, 2);
                            publish(objDateFormat.format(objDate) + "  " + "Decryption completed successfully with error because deleting file has failed");
                        }
                    }
                    else
                    {
                        objJTable.setValueAt("Decryption completed successfully", intTableRowNo, 1);
                        objJTable.setValueAt("File is not deleted", intTableRowNo, 2);
                        publish(objDateFormat.format(objDate) + "  " + "Decryption completed successfully and file is not deleted");
                    }
                }
                else
                {
                    objJTable.setValueAt("Decrypting file has failed. Waiting for user response", intTableRowNo, 2);
                    publish(objDateFormat.format(objDate) + "  " + "Decrypting file has failed. Waiting for user response");

                    dialogReEnter objDialogReEnter = new dialogReEnter();
                    objDialogReEnter.setVisible(true);

                    if(objDialogReEnter.boolReEnter == true)
                    {
                        strInterMessageDigestAlgorithm = objDialogReEnter.strMessageDigestAlgorithm;
                        intInterPasswordHashIteration = objDialogReEnter.intPasswordHashIteration;
                        strInterPassword = objDialogReEnter.strPassword;
                    }
                    else
                    {
                        objJTable.setValueAt("Decryption failed", intTableRowNo, 1);
                        objJTable.setValueAt("Decrypting file was terminated by user", intTableRowNo, 2);
                        publish(objDateFormat.format(objDate) + "  " + "Decrypting file was terminated by user");

                        intCryptAction = 0;
                    }
                }
            }while(intCryptAction == 1);
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(null, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
            
            try
            {
                objUtility.DeleteFile(strFileName.substring(0, strFileName.length() - strCryptExtension.length() - 1));
            }
            catch(Exception ex1)
            {
                JOptionPane.showMessageDialog(null, ex1, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
