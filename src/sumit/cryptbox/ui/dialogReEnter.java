package sumit.cryptbox.ui;

import javax.swing.JOptionPane;

public class dialogReEnter extends javax.swing.JDialog
{
    public String strMessageDigestAlgorithm;
    public int intPasswordHashIteration;
    public String strPassword;
    public boolean boolReEnter;
    
    public dialogReEnter()
    {
        initComponents();
        
        this.setLocationRelativeTo(null);
        getRootPane().setDefaultButton(btnCancel);
        
        /*Set Initial Value*/
        intPasswordHashIteration = 100;
        strPassword = "";
        boolReEnter = false;
        
        /*Assign Values to UI Control*/
        txtPasswordHashIteration.setText(String.valueOf(intPasswordHashIteration));
        passFieldPassword.setText(strPassword);
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        panelCryptographyOption = new javax.swing.JPanel();
        lblMessageDigestAlgorithm = new javax.swing.JLabel();
        cmbMessageDigestAlgorithm = new javax.swing.JComboBox();
        lblPasswordHashIteration = new javax.swing.JLabel();
        txtPasswordHashIteration = new javax.swing.JTextField();
        lblPassword = new javax.swing.JLabel();
        passFieldPassword = new javax.swing.JPasswordField();
        btnOK = new javax.swing.JButton();
        btnCancel = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Re Enter");
        setModal(true);

        panelCryptographyOption.setBorder(javax.swing.BorderFactory.createTitledBorder("Cryptography Option"));

        lblMessageDigestAlgorithm.setText("Message Digest Algorithm");

        cmbMessageDigestAlgorithm.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "PBEWithMD5AndDES" }));

        lblPasswordHashIteration.setText("Password Hash Iteration");

        lblPassword.setText("Password");

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
                            .addComponent(lblMessageDigestAlgorithm))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(panelCryptographyOptionLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(passFieldPassword)
                            .addComponent(txtPasswordHashIteration)
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
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        btnOK.setText("OK");
        btnOK.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnOKActionPerformed(evt);
            }
        });

        btnCancel.setText("Cancel");
        btnCancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCancelActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(panelCryptographyOption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(btnOK)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnCancel)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(panelCryptographyOption, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnCancel)
                    .addComponent(btnOK))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    //<editor-fold defaultstate="collapsed" desc="OK dialogStart - btnOKActionPerformed">
    private void btnOKActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnOKActionPerformed
        try
        {
            if (CheckPasswordHashIteration(txtPasswordHashIteration.getText()) == 0)
            {
                strMessageDigestAlgorithm = cmbMessageDigestAlgorithm.getSelectedItem().toString();
                intPasswordHashIteration = Integer.parseInt(txtPasswordHashIteration.getText());
                strPassword = new String(passFieldPassword.getPassword());

                boolReEnter = true;

                this.dispose();
            }
        }
        catch (Exception ex)
        {
            JOptionPane.showMessageDialog(this, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnOKActionPerformed
    //</editor-fold>
    
    //<editor-fold defaultstate="collapsed" desc="Close dialogStart - btnCancelActionPerformed">
    private void btnCancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCancelActionPerformed
        try
        {
            this.dispose();
        }
        catch (Exception ex)
        {
            JOptionPane.showMessageDialog(this, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnCancelActionPerformed
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
    private javax.swing.JButton btnOK;
    private javax.swing.JComboBox cmbMessageDigestAlgorithm;
    private javax.swing.JLabel lblMessageDigestAlgorithm;
    private javax.swing.JLabel lblPassword;
    private javax.swing.JLabel lblPasswordHashIteration;
    private javax.swing.JPanel panelCryptographyOption;
    private javax.swing.JPasswordField passFieldPassword;
    private javax.swing.JTextField txtPasswordHashIteration;
    // End of variables declaration//GEN-END:variables
}
