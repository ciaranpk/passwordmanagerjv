# passwordmanagerjv
Password Manager Java




📝 Password Management Workflow


1. Saving a New Password

This process securely encrypts your credentials using AES and saves them within the application's memory.
1. Enter Details: Fill in the three input fields:
    * Service: The name of the website or application (e.g., Netflix, Work Email). 
    * Username/Email: Your login ID for that service. 
    * Password: The actual password you use. 
2. Click "Save Encrypted":
    * The application combines your Username and Password, encrypts the combined string, and stores the resulting ciphertext. 
    * The Service name will appear in the list on the left. 
    * A confirmation message and the raw ciphertext will be logged in the Details area. 

2. Retrieving a Stored Password

This process decrypts the stored ciphertext to reveal the original credentials.
1. Select Service: Click on the desired Service name in the Stored Services list on the left. 
2. The application automatically runs the decryption process. 
3. The Details & Generation Log area will immediately update, displaying the decrypted Username and Password for the selected service. 


🛡️ Strong Password Generator

The application includes a built-in generator to create highly secure passwords of 16 characters in length.
1. Click the "Generate" button in the Password Management panel. 
2. A new, strong password is automatically created and filled into the Password field.
    * The generator ensures the password includes a mix of lowercase letters, uppercase letters, digits, and special characters. 
3. The generated password and a brief description of its strength are logged in the Details area. 
4. You can then use this generated password and click "Save Encrypted" to secure it. 


⚠️ Security Notes (Important)

* In-Memory Storage: This version of the application stores all encrypted data in a Java HashMap (in memory). When you close the application, all your saved passwords are lost. 
* Key Security: For simplicity, the AES encryption key (SECRET_KEY) is hardcoded in the source file. In a real, production password manager, the key must never be hardcoded; it should be securely derived from a master password and properly managed to prevent unauthorized decryption. 
* Demo Purpose: This tool is designed to demonstrate encryption (AES), strong password generation, and GUI development in Java, not to be a vault for real-world sensitive data. 
