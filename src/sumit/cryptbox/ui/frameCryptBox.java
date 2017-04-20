package sumit.cryptbox.ui;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDropEvent;
import java.io.File;
import java.util.List;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import sumit.cryptbox.util.CryptAction;

public class frameCryptBox extends javax.swing.JFrame
{
    //<editor-fold defaultstate="collapsed" desc="Global Variables">
    /*Global Variable*/
    final String strCryptExtension = "enc";
    StringBuilder strBuilderMessage = new StringBuilder();
    //</editor-fold>
        
    public frameCryptBox()
    {
        initComponents();
        
        //<editor-fold defaultstate="collapsed" desc="Maximize the JFrame">
        /*Maximize the JFrame*/
        this.setExtendedState(this.getExtendedState() | this.MAXIMIZED_BOTH);
        //</editor-fold>
        
        //<editor-fold defaultstate="collapsed" desc="Set Column Names for tableFileAction">
        /*Set Column Names for tableFileAction*/
        tableFileAction.setModel(new DefaultTableModel(
            new Object [][] { },
            new String [] 
            {
                "File(s)", "Status", "Sub Status"
            }
        ));
        //</editor-fold>
        
        //<editor-fold defaultstate="collapsed" desc="Set Column Width for tableFileActionn">
        /*Set Column Width for tableFileActionn*/
        tableFileAction.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        tableFileAction.getColumnModel().getColumn(0).setPreferredWidth(800);
        tableFileAction.getColumnModel().getColumn(1).setPreferredWidth(300);
        tableFileAction.getColumnModel().getColumn(2).setPreferredWidth(300);
        //</editor-fold>
        
        //<editor-fold defaultstate="collapsed" desc="Darg and Drop file(s) from Windows Explorer to scrollFileAction for tableFileAction">
        /*Darg and Drop file(s) from Windows Explorer to scrollFileAction for tableFileAction*/
        scrollFileAction.setDropTarget(new DropTarget()
        {
            @Override
            public synchronized void drop(DropTargetDropEvent dtde)
            {
                try
                {
                    /*Clear Values*/
                    btnClearActionPerformed(null);
                
                    dtde.acceptDrop(DnDConstants.ACTION_COPY_OR_MOVE);
                    Transferable t = dtde.getTransferable();
                    List fileList = (List)t.getTransferData(DataFlavor.javaFileListFlavor);
                    Object[][] objectFiles = new Object[fileList.size()][3];
                    
                    for(int i=0; i<fileList.size(); i++)
                    {
                        File objFile = (File)fileList.get(i);
                        objectFiles[i][0] = objFile;
                        objectFiles[i][1] = "In Queue";
                    }
                    
                    tableFileAction.setModel(new DefaultTableModel(
                    objectFiles,
                    new String [] {"File(s)", "Status", "Sub Status"}));
                    
                    tableFileAction.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
                    tableFileAction.getColumnModel().getColumn(0).setPreferredWidth(800);
                    tableFileAction.getColumnModel().getColumn(1).setPreferredWidth(300);
                    tableFileAction.getColumnModel().getColumn(2).setPreferredWidth(300);
                }
                catch(Exception ex)
                {
                    JOptionPane.showMessageDialog(frameCryptBox.this, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        //</editor-fold>
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        btnGroupCryptAction = new javax.swing.ButtonGroup();
        scrollFileAction = new javax.swing.JScrollPane();
        tableFileAction = new javax.swing.JTable();
        panelStatus = new javax.swing.JPanel();
        progressBarStatus = new javax.swing.JProgressBar();
        btnStatus = new javax.swing.JButton();
        panelCryptAction = new javax.swing.JPanel();
        rdoEncrypt = new javax.swing.JRadioButton();
        rdoDecrypt = new javax.swing.JRadioButton();
        btnClose = new javax.swing.JButton();
        btnStart = new javax.swing.JButton();
        btnSelect = new javax.swing.JButton();
        btnClear = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("CryptBox");

        tableFileAction.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        scrollFileAction.setViewportView(tableFileAction);

        panelStatus.setBorder(javax.swing.BorderFactory.createTitledBorder("Status"));

        btnStatus.setText("Detail");
        btnStatus.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnStatusActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout panelStatusLayout = new javax.swing.GroupLayout(panelStatus);
        panelStatus.setLayout(panelStatusLayout);
        panelStatusLayout.setHorizontalGroup(
            panelStatusLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelStatusLayout.createSequentialGroup()
                .addComponent(progressBarStatus, javax.swing.GroupLayout.DEFAULT_SIZE, 221, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnStatus)
                .addContainerGap())
        );
        panelStatusLayout.setVerticalGroup(
            panelStatusLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelStatusLayout.createSequentialGroup()
                .addComponent(btnStatus)
                .addGap(0, 0, Short.MAX_VALUE))
            .addComponent(progressBarStatus, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

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
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(rdoDecrypt)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        panelCryptActionLayout.setVerticalGroup(
            panelCryptActionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelCryptActionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(rdoEncrypt)
                .addComponent(rdoDecrypt))
        );

        btnClose.setText("Close");
        btnClose.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCloseActionPerformed(evt);
            }
        });

        btnStart.setText("Start");
        btnStart.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnStartActionPerformed(evt);
            }
        });

        btnSelect.setText("Select");
        btnSelect.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSelectActionPerformed(evt);
            }
        });

        btnClear.setText("Clear");
        btnClear.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnClearActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(scrollFileAction)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(panelStatus, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(panelCryptAction, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 47, Short.MAX_VALUE)
                        .addComponent(btnClear)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnSelect)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnStart)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnClose)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(scrollFileAction, javax.swing.GroupLayout.DEFAULT_SIZE, 284, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(panelStatus, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(panelCryptAction, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addContainerGap())
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(btnClose)
                            .addComponent(btnStart)
                            .addComponent(btnSelect)
                            .addComponent(btnClear))
                        .addGap(22, 22, 22))))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    //<editor-fold defaultstate="collapsed" desc="Exit CryptBox application - btnCloseActionPerformed">
    private void btnCloseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCloseActionPerformed
        try
        {
            System.exit(0);
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(this, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnCloseActionPerformed
    //</editor-fold>
    
    //<editor-fold defaultstate="collapsed" desc="Select Files - btnSelectActionPerformed">
    private void btnSelectActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSelectActionPerformed
        try
        {
            JFileChooser fileopen = new JFileChooser();
            
            if(rdoEncrypt.isSelected() == true)
            {
                fileopen.setDialogTitle("Open Files to encrypt");
            }
            else if(rdoDecrypt.isSelected() == true)
            {
                FileFilter objFileFilter = new FileNameExtensionFilter("encrypted file", strCryptExtension);
                fileopen.addChoosableFileFilter(objFileFilter);
                fileopen.setAcceptAllFileFilterUsed(false);
                
                fileopen.setDialogTitle("Open Files to decrypt");
            }
            
            fileopen.setMultiSelectionEnabled(true);
            int ret = fileopen.showDialog(this, "Open");
            
            if (ret == JFileChooser.APPROVE_OPTION)
            {
                /*Clear Values*/
                btnClearActionPerformed(null);
                
                File[] objFiles = fileopen.getSelectedFiles();
                Object[][] objectFiles = new Object[objFiles.length][5];
                
                for(int i=0; i<objFiles.length; i++)
                {
                    objectFiles[i][0] = objFiles[i];
                    objectFiles[i][1] = "In Queue";
                }

                tableFileAction.setModel(new DefaultTableModel(
                    objectFiles,
                    new String [] {"File(s)", "Status", "Sub Status"}));
                
                tableFileAction.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
                tableFileAction.getColumnModel().getColumn(0).setPreferredWidth(800);
                tableFileAction.getColumnModel().getColumn(1).setPreferredWidth(300);
                tableFileAction.getColumnModel().getColumn(2).setPreferredWidth(300);
            }
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(this, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnSelectActionPerformed
    //</editor-fold>
    
    //<editor-fold defaultstate="collapsed" desc="Open dialogStatus - btnStatusActionPerformed">
    private void btnStatusActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnStatusActionPerformed
        try
        {
            dialogStatus objdialogStatus = new dialogStatus(strBuilderMessage.toString());
            objdialogStatus.setVisible(true);
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(this, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnStatusActionPerformed
    //</editor-fold>
    
    //<editor-fold defaultstate="collapsed" desc="Open dialogStart - btnStartActionPerformed">
    private void btnStartActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnStartActionPerformed
        try
        {
            boolean boolCryptAct = true;
            
            TableModel objTableModel = tableFileAction.getModel();
            if(objTableModel.getRowCount() != 0)
            {
                if(rdoEncrypt.isSelected() == true)
                {
                    boolCryptAct = true;
                }
                else if(rdoDecrypt.isSelected() == true)
                {
                    boolCryptAct = false;
                }

                dialogStart objdialogStart = new dialogStart(boolCryptAct);
                objdialogStart.setVisible(true);
                
                if(objdialogStart.boolStart == true)
                {
                    final String strMessageDigestAlgorithm = objdialogStart.strMessageDigestAlgorithm;
                    final int intPasswordHashIteration = objdialogStart.intPasswordHashIteration;
                    final String strPassword = objdialogStart.strPassword;
                    final boolean boolCryptAction = objdialogStart.boolCryptAction;
                    final boolean boolOriginalFileDelete = objdialogStart.boolOriginalFileDelete;
                    
                    if(boolCryptAction == true)
                    {
                        rdoEncrypt.setSelected(true);
                        rdoDecrypt.setSelected(false);
                    }
                    else
                    {
                        rdoEncrypt.setSelected(false);
                        rdoDecrypt.setSelected(true);
                    }
                    
                    if(boolCryptAction == true)
                    {
                        SwingUtilities.invokeLater(new Runnable()
                        {
                            public void run()
                            {
                                // The worker
                                CryptAction objCryptAction = new CryptAction(strMessageDigestAlgorithm, intPasswordHashIteration, strPassword, "encrypt", boolOriginalFileDelete, strCryptExtension, strBuilderMessage, tableFileAction, progressBarStatus);

                                // Start the worker. Note that control is returned immediately
                                objCryptAction.execute();
                            }
                        });
                    }
                    else
                    {
                        SwingUtilities.invokeLater(new Runnable()
                        {
                            public void run()
                            {
                                // The worker
                                CryptAction objCryptAction = new CryptAction(strMessageDigestAlgorithm, intPasswordHashIteration, strPassword, "decrypt", boolOriginalFileDelete, strCryptExtension, strBuilderMessage, tableFileAction, progressBarStatus);

                                // Start the worker. Note that control is returned immediately
                                objCryptAction.execute();
                            }
                        });
                    }
                }
            }
            else
            {
                JOptionPane.showMessageDialog(this, "No File(s) has been seleted to start cryptography action", "CryptBox", JOptionPane.INFORMATION_MESSAGE);
            }
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(this, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnStartActionPerformed
    //</editor-fold>
    
    //<editor-fold defaultstate="collapsed" desc="Clear Values - btnClearActionPerformed">
    private void btnClearActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnClearActionPerformed
        try
        {
            /*Set Column Names for tableFileAction*/
            tableFileAction.setModel(new DefaultTableModel(
                new Object [][] { },
                new String [] 
                {
                    "File(s)", "Status", "Sub Status"
                }
            ));
            
            /*Set Column Width for tableFileActionn*/
            tableFileAction.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
            tableFileAction.getColumnModel().getColumn(0).setPreferredWidth(800);
            tableFileAction.getColumnModel().getColumn(1).setPreferredWidth(300);
            tableFileAction.getColumnModel().getColumn(2).setPreferredWidth(300);
            
            //Clear Progress Bar
            progressBarStatus.setValue(0);
            
            /*Clear Status Message*/
            strBuilderMessage.setLength(0);
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(this, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnClearActionPerformed
    //</editor-fold>
    
    public static void main(String args[])
    {
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /*
         * If Nimbus (introduced in Java SE 6) is not available, stay with the
         * default look and feel. For details see
         * http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(frameCryptBox.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(frameCryptBox.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(frameCryptBox.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(frameCryptBox.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        java.awt.EventQueue.invokeLater(new Runnable()
        {

            public void run()
            {
                new frameCryptBox().setVisible(true);
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnClear;
    private javax.swing.JButton btnClose;
    private javax.swing.ButtonGroup btnGroupCryptAction;
    private javax.swing.JButton btnSelect;
    private javax.swing.JButton btnStart;
    private javax.swing.JButton btnStatus;
    private javax.swing.JPanel panelCryptAction;
    private javax.swing.JPanel panelStatus;
    private javax.swing.JProgressBar progressBarStatus;
    private javax.swing.JRadioButton rdoDecrypt;
    private javax.swing.JRadioButton rdoEncrypt;
    private javax.swing.JScrollPane scrollFileAction;
    private javax.swing.JTable tableFileAction;
    // End of variables declaration//GEN-END:variables
}
