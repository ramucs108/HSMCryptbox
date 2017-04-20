package sumit.cryptbox.ui;

import javax.swing.JOptionPane;

public class dialogStatus extends javax.swing.JDialog
{

    public dialogStatus(String strStatus)
    {
        initComponents();
        
        this.setLocationRelativeTo(null);
        getRootPane().setDefaultButton(btnClose);
        
        txtAreaStatus.setText(strStatus);
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        scrollStatus = new javax.swing.JScrollPane();
        txtAreaStatus = new javax.swing.JTextArea();
        btnClose = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Status");
        setModal(true);
        setResizable(false);

        txtAreaStatus.setColumns(20);
        txtAreaStatus.setEditable(false);
        txtAreaStatus.setRows(5);
        scrollStatus.setViewportView(txtAreaStatus);

        btnClose.setText("Close");
        btnClose.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCloseActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(scrollStatus, javax.swing.GroupLayout.DEFAULT_SIZE, 768, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(btnClose)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(scrollStatus, javax.swing.GroupLayout.DEFAULT_SIZE, 249, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnClose)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    //<editor-fold defaultstate="collapsed" desc="Close dialogStatus - btnCloseActionPerformed">
    private void btnCloseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCloseActionPerformed
        try
        {
            this.dispose();
        }
        catch(Exception ex)
        {
            JOptionPane.showMessageDialog(this, ex, "CryptBox Error", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btnCloseActionPerformed
    //</editor-fold>
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnClose;
    private javax.swing.JScrollPane scrollStatus;
    private javax.swing.JTextArea txtAreaStatus;
    // End of variables declaration//GEN-END:variables
}
