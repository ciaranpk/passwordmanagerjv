import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * Java Password Manager Application with Encryption, Password Generator, and GUI.
 */
public class PasswordManagerGUI extends JFrame {

    // --- 1. Encryption and Security Constants ---
    // NOTE: In a real application, this key should be securely derived, 
    // stored, and managed (e.g., using a secure KeyStore or derived from user login).
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final byte[] SECRET_KEY = "ThisIsAStrongKey".getBytes(StandardCharsets.UTF_8); // 16 bytes for AES-128
    
    // An Initialization Vector (IV) is needed for CBC mode. 
    // In a real app, a unique IV should be generated per encryption and stored alongside the ciphertext.
    private static final byte[] IV = new byte[16]; // Zero-filled for simplicity, NOT secure practice!

    // --- 2. GUI Components and Data Storage ---
    private JTextArea displayArea;
    private JTextField serviceField, usernameField;
    private JPasswordField passwordField;
    private DefaultListModel<String> serviceListModel;
    private JList<String> serviceJList;

    // Stores encrypted data: Key (Service) -> Encrypted_String
    private java.util.HashMap<String, String> passwordStore = new java.util.HashMap<>();

    // --- 3. Main Constructor and Setup ---

    public PasswordManagerGUI() {
        setTitle("🔑 Secure Password Manager");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(800, 600);
        setLayout(new BorderLayout(10, 10));
        ((JComponent) getContentPane()).setBorder(new EmptyBorder(10, 10, 10, 10));

        // Initialize GUI components
        initComponents();

        // Populate the window
        createMainPanel();

        // Center the window
        setLocationRelativeTo(null);
        setVisible(true);
    }

    private void initComponents() {
        // Input Fields
        serviceField = new JTextField(20);
        usernameField = new JTextField(20);
        passwordField = new JPasswordField(20);

        // Display Area (Right Panel)
        displayArea = new JTextArea();
        displayArea.setEditable(false);
        displayArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        // Service List (Left Panel)
        serviceListModel = new DefaultListModel<>();
        serviceJList = new JList<>(serviceListModel);
        serviceJList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        serviceJList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                retrievePassword();
            }
        });
    }

    // --- 4. Panel Layout ---

    private void createMainPanel() {
        // Left Panel (List of Services)
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.add(new JLabel("Stored Services:"), BorderLayout.NORTH);
        leftPanel.add(new JScrollPane(serviceJList), BorderLayout.CENTER);
        add(leftPanel, BorderLayout.WEST);

        // Center Panel (Input Fields and Buttons)
        JPanel centerPanel = new JPanel(new GridLayout(2, 1, 10, 10));
        centerPanel.add(createInputPanel());
        centerPanel.add(createDisplayPanel());
        add(centerPanel, BorderLayout.CENTER);
    }

    private JPanel createInputPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Password Management"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Labels
        gbc.gridx = 0; gbc.gridy = 0; panel.add(new JLabel("Service (e.g., Google):"), gbc);
        gbc.gridx = 0; gbc.gridy = 1; panel.add(new JLabel("Username/Email:"), gbc);
        gbc.gridx = 0; gbc.gridy = 2; panel.add(new JLabel("Password:"), gbc);

        // Input Fields
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0; panel.add(serviceField, gbc);
        gbc.gridx = 1; gbc.gridy = 1; panel.add(usernameField, gbc);
        gbc.gridx = 1; gbc.gridy = 2; panel.add(passwordField, gbc);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        buttonPanel.add(new JButton("Save Encrypted", e -> savePassword()));
        buttonPanel.add(new JButton("Generate", e -> generatePassword()));
        
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2; panel.add(buttonPanel, gbc);

        return panel;
    }

    private JPanel createDisplayPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Details & Generation Log"));
        panel.add(new JScrollPane(displayArea), BorderLayout.CENTER);
        return panel;
    }

    // --- 5. Core Application Logic (Encryption/Decryption) ---

    private SecretKeySpec generateKey() {
        return new SecretKeySpec(SECRET_KEY, "AES");
    }

    private IvParameterSpec generateIV() {
        return new IvParameterSpec(IV);
    }
    
    /**
     * Encrypts the input string using AES.
     */
    private String encrypt(String strToEncrypt) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, generateKey(), generateIV());
            byte[] cipherText = cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(cipherText);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Encryption Error: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }

    /**
     * Decrypts the Base64 encoded, encrypted string using AES.
     */
    private String decrypt(String strToDecrypt) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, generateKey(), generateIV());
            byte[] decodedBytes = Base64.getDecoder().decode(strToDecrypt);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Decryption Error: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }

    // --- 6. Strong Password Generator ---

    /**
     * Generates a strong password using a mix of characters.
     */
    private void generatePassword() {
        // Define character sets
        final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
        final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        final String DIGITS = "0123456789";
        final String SPECIAL_CHARS = "!@#$%^&*()-_+=<>?";
        final String ALL_CHARS = LOWERCASE + UPPERCASE + DIGITS + SPECIAL_CHARS;

        // Configuration
        final int LENGTH = 16;
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder(LENGTH);

        // Ensure at least one of each type for strength
        password.append(LOWERCASE.charAt(random.nextInt(LOWERCASE.length())));
        password.append(UPPERCASE.charAt(random.nextInt(UPPERCASE.length())));
        password.append(DIGITS.charAt(random.nextInt(DIGITS.length())));
        password.append(SPECIAL_CHARS.charAt(random.nextInt(SPECIAL_CHARS.length())));

        // Fill the rest of the length randomly
        for (int i = 4; i < LENGTH; i++) {
            password.append(ALL_CHARS.charAt(random.nextInt(ALL_CHARS.length())));
        }

        // Shuffle the password to prevent predictable patterns
        String generated = shuffleString(password.toString());
        
        // Update the GUI
        passwordField.setText(generated);
        displayArea.append("Generated Strong Password: " + generated + "\n");
        displayArea.append("Strength: Length " + LENGTH + ", Mixed Case, Digits, Special Chars.\n\n");
    }

    private String shuffleString(String input) {
        java.util.List<Character> characters = new java.util.ArrayList<>();
        for (char c : input.toCharArray()) {
            characters.add(c);
        }
        java.util.Collections.shuffle(characters);
        StringBuilder sb = new StringBuilder();
        for (char c : characters) {
            sb.append(c);
        }
        return sb.toString();
    }

    // --- 7. GUI Action Handlers ---

    private void savePassword() {
        String service = serviceField.getText().trim();
        String username = usernameField.getText().trim();
        String password = new String(passwordField.getPassword()).trim();

        if (service.isEmpty() || username.isEmpty() || password.isEmpty()) {
            JOptionPane.showMessageDialog(this, "All fields must be filled.", "Input Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Combine username and password for encryption
        String credentials = username + "|" + password; 
        
        // Encrypt the data
        String encryptedData = encrypt(credentials);

        if (encryptedData != null) {
            // Store the encrypted data
            passwordStore.put(service, encryptedData);
            
            // Update the service list model
            if (!serviceListModel.contains(service)) {
                serviceListModel.addElement(service);
            }
            
            displayArea.append("🔐 Successfully encrypted and saved credentials for: " + service + "\n");
            displayArea.append("Ciphertext: " + encryptedData + "\n\n");
        }
    }

    private void retrievePassword() {
        String service = serviceJList.getSelectedValue();
        if (service == null || !passwordStore.containsKey(service)) {
            displayArea.setText("Please select a service from the list.\n");
            return;
        }

        String encryptedData = passwordStore.get(service);
        
        // Decrypt the data
        String decryptedCredentials = decrypt(encryptedData);

        if (decryptedCredentials != null) {
            // Split back into username and password
            String[] parts = decryptedCredentials.split("\\|", 2); 
            
            // Display decrypted data (for demonstration purposes)
            displayArea.setText(""); // Clear previous text
            displayArea.append("✅ Decrypted Credentials for: " + service + "\n");
            displayArea.append("   Username: " + parts[0] + "\n");
            displayArea.append("   Password: " + (parts.length > 1 ? parts[1] : "N/A") + "\n\n");
        }
    }

    // --- 8. Main Method ---

    public static void main(String[] args) {
        // Schedule a job for the event dispatch thread: 
        // creating and showing this application's GUI.
        SwingUtilities.invokeLater(() -> new PasswordManagerGUI());
    }
}