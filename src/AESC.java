import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JEditorPane;
import javax.swing.JButton;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.DefaultComboBoxModel;
import java.awt.event.ActionListener;
import java.util.Base64;
import java.awt.event.ActionEvent;
import javax.swing.JTextField;

public class AESC {

	private JFrame frmAesccmTestTool;
	private JTextField txtPassword;
	private JTextField txtAesIV;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					AESC window = new AESC();
					window.frmAesccmTestTool.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public AESC() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frmAesccmTestTool = new JFrame();
		frmAesccmTestTool.setTitle("AES-CBC Test Tool");
		frmAesccmTestTool.setBounds(100, 100, 440, 527);
		frmAesccmTestTool.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		JPanel panel = new JPanel();
		frmAesccmTestTool.getContentPane().add(panel, BorderLayout.CENTER);
		panel.setLayout(null);
		
		JComboBox cbmAesKeylength = new JComboBox();
		cbmAesKeylength.setModel(new DefaultComboBoxModel(new String[] {"AES-128", "AES-192", "AES-256"}));
		cbmAesKeylength.setBounds(119, 10, 101, 23);
		panel.add(cbmAesKeylength);
		
		JLabel lblAesKeylength = new JLabel("AES Key Length");
		lblAesKeylength.setBounds(10, 14, 113, 15);
		panel.add(lblAesKeylength);
		
		JLabel lblAesIV = new JLabel("AES IV:");
		lblAesIV.setBounds(209, 43, 61, 15);
		panel.add(lblAesIV);
		
		JLabel lblMessage = new JLabel("Message");
		lblMessage.setBounds(10, 65, 61, 15);
		panel.add(lblMessage);
		
		JEditorPane txtMessage = new JEditorPane();
		txtMessage.setBounds(10, 90, 404, 95);
		panel.add(txtMessage);
		
		JLabel lblCipher = new JLabel("Cipher");
		lblCipher.setBounds(10, 195, 61, 15);
		panel.add(lblCipher);
		
		JEditorPane txtCipher = new JEditorPane();
		txtCipher.setBounds(10, 220, 404, 95);
		panel.add(txtCipher);
		
		JLabel lblDeCipher = new JLabel("DeCipher");
		lblDeCipher.setBounds(10, 325, 61, 15);
		panel.add(lblDeCipher);
		
		JEditorPane txtDeCipher = new JEditorPane();
		txtDeCipher.setBounds(10, 350, 404, 95);
		panel.add(txtDeCipher);
		
		JButton btnExit = new JButton("Exit");
		btnExit.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.exit(1);
			}
		});
		btnExit.setBounds(330, 455, 87, 23);
		panel.add(btnExit);
		
		JButton btnDecrypt = new JButton("Decrypt");
		btnDecrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (txtCipher.getText().isEmpty()) {
					infoBox("No message to decrypt!", "Decrypt");
				} else if (txtAesIV.getText().isEmpty()) {
					infoBox("No AES IV!", "Decrypt");
				} else if (txtPassword.getText().isEmpty()) {
					infoBox("No Password!", "Decrypt");
				} else {
					int keySize = 0;
					switch (cbmAesKeylength.getSelectedIndex()) {
					case 0:
						keySize = 128;
						break;
					case 1:
						keySize = 192;
						break;
					case 2:
						keySize = 256;
						break;
					}
					int ivSize = keySize / 8;
					int passwordSize = keySize / 8;
					if (txtPassword.getText().length() == passwordSize) {
						if (txtAesIV.getText().length() == ivSize) {
							final SecretKey aesKey = new SecretKeySpec(txtPassword.getText().getBytes() , "AES");
							byte[] iv = txtAesIV.getText().getBytes();
							try {
								String deString = aesDecrypt(aesKey, iv, Base64.getDecoder().decode(txtCipher.getText()));
								txtDeCipher.setText(deString);
							} catch (Exception e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							}
						} else {
							infoBox("IV Length should be " + ivSize + " characters long!", "Encrypt");
						}
					} else {
						infoBox("Password Length should be " + passwordSize + " characters long!", "Encrypt");
					}
				}
			}
		});
		btnDecrypt.setBounds(233, 455, 87, 23);
		panel.add(btnDecrypt);
		
		JButton btnEncrypt = new JButton("Encrypt");
		btnEncrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (txtMessage.getText().isEmpty()) {
					infoBox("No message to encrypt!", "Encrypt");
				} else if (txtAesIV.getText().isEmpty()) {
					infoBox("No AES IV!", "Encrypt");
				} else if (txtPassword.getText().isEmpty()) {
					infoBox("No Password!", "Encrypt");
				} else {
					int keySize = 0;
					switch (cbmAesKeylength.getSelectedIndex()) {
					case 0:
						keySize = 128;
						break;
					case 1:
						keySize = 192;
						break;
					case 2:
						keySize = 256;
						break;
					}
					int ivSize = keySize / 8;
					int passwordSize = keySize / 8;
					if (txtPassword.getText().length() == passwordSize) {
						if (txtAesIV.getText().length() == ivSize) {
							final SecretKey aesKey = new SecretKeySpec(txtPassword.getText().getBytes() , "AES");
							byte[] iv = txtAesIV.getText().getBytes();
							try {
								txtCipher.setText(Base64.getEncoder().encodeToString(aesEncrypt(aesKey, iv, txtMessage.getText())));
							} catch (Exception e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							}
						} else {
							infoBox("IV Length should be " + ivSize + " characters long!", "Encrypt");
						}
					} else {
						infoBox("Password Length should be " + passwordSize + " characters long!", "Encrypt");
					}
					
				}
				
				
			}
		});
		btnEncrypt.setBounds(133, 455, 87, 23);
		panel.add(btnEncrypt);
		
		JLabel lblPassword = new JLabel("Password");
		lblPassword.setBounds(10, 43, 61, 15);
		panel.add(lblPassword);
		
		txtPassword = new JTextField();
		txtPassword.setBounds(98, 39, 101, 21);
		panel.add(txtPassword);
		txtPassword.setColumns(10);
		
		txtAesIV = new JTextField();
		txtAesIV.setBounds(287, 40, 96, 21);
		panel.add(txtAesIV);
		txtAesIV.setColumns(10);
	}
	
	public static byte[] aesEncrypt(SecretKey secretKey, byte[] iv, String msg) throws Exception{
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
		byte[] byteCipherText = cipher.doFinal(msg.getBytes("UTF-8"));
		return byteCipherText;
	}
	
	public static String aesDecrypt(SecretKey secretKey, byte[] iv, byte[] cipherText) throws Exception{
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
		byte[] decryptedText = cipher.doFinal(cipherText);
		String strDecryptedText = new String(decryptedText);
		return strDecryptedText;
	}
	
	public static void infoBox(String infoMessage, String titleBar) {
		JOptionPane.showMessageDialog(null, infoMessage, "InfoBox: " + titleBar, JOptionPane.INFORMATION_MESSAGE);
	}
}
