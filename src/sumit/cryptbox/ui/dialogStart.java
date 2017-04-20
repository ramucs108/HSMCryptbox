package sumit.cryptbox.ui;

import javax.swing.JOptionPane;

public class dialogStart extends javax.swing.JDialog
{
    public String strMessageDigestAlgorithm;
    public int intPasswordHashIteration;
    public String strPassword;
    public boolean boolCryptAction;
    public boolean boolOriginalFileDelete;
    public boolean boolStart;
    
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
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
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

        lblPassword.setText("Password");

        lblRePassword.setText("Re Password");

        javax.swing.GroupLayout panelCryptographyOptionLayout = new javax.swing.GroupLayout(panelCryptographyOption);
        panelCryptographyOption.setLayout(panelCryptographyOptionLayout);
        panelCryptographyOptionLayout.setHorizontalGroup(
            panelCryptographyOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelCryptographyOptionLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(panelCryptographyOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(lblPassword)
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

        btnGroupOriginalFileOption.add(rdBtnYes);
        rdBtnYes.setSelected(true);
        rdBtnYes.setText("Yes");

        javax.swing.GroupLayout paneloriginalFileOptionLayout = new javax.swing.GroupLayout(paneloriginalFileOption);
        paneloriginalFileOption.setLayout(paneloriginalFileOptionLayout);
        paneloriginalFileOptionLayout.setHorizontalGroup(
            paneloriginalFileOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(paneloriginalFileOptionLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(paneloriginalFileOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(lblOriginalFileOption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(paneloriginalFileOptionLayout.createSequentialGroup()
                        .addComponent(rdBtnYes)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(rdBtnNo)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
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
    }// </editor-fold>//GEN-END:initComponents

    //<editor-fold defaultstate="collapsed" desc="Close dialogStart - btnCancelActionPerformed">
    private void btnCancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCancelActionPerformed
        try
        {
            this.dispose();
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(this, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnCancelActionPerformed
    //</editor-fold>
    
    //<editor-fold defaultstate="collapsed" desc="OK dialogStart - btnOKActionPerformed">
    private void btnOKActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnOKActionPerformed
        try
        {
            if(CheckPassword(new String(passFieldPassword.getPassword()), new String(passFieldRePassword.getPassword())) == 0 && CheckPasswordHashIteration(txtPasswordHashIteration.getText()) == 0)
            {
                strMessageDigestAlgorithm = cmbMessageDigestAlgorithm.getSelectedItem().toString();
                intPasswordHashIteration = Integer.parseInt(txtPasswordHashIteration.getText());
                strPassword = new String(passFieldPassword.getPassword());
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
    }//GEN-LAST:event_btnOKActionPerformed
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
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
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
    // End of variables declaration//GEN-END:variables
}
