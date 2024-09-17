# CipherMimic: A Cutting-Edge, Stealthy Encryption Engine

Welcome to **CipherMimic**, an encryption engine designed for stealth, security, and performance. Whether you're securing sensitive data, testing security tools, or creating highly stealthy applications, CipherMimic is built with future-proof cryptographic techniques and state-of-the-art operational security (OpSec) features to handle today's and tomorrow's challenges.

## **Table of Contents**

- [Introduction](#introduction)
- [Key Features](#key-features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Command Line Options](#command-line-options)
- [Best Practices for Testing](#best-practices-for-testing)
- [Security and Compliance](#security-and-compliance)
- [Contribution Guidelines](#contribution-guidelines)
- [License](#license)

---

## **Introduction**

CipherMimic is a highly advanced and stealthy file encryption tool that is designed to not only encrypt sensitive data but also operate in a way that minimizes forensic traces, avoids detection by security software, and adheres to modern zero-trust principles. Built with **Golang 1.23.0**, this encryption engine is engineered to offer top-tier security and performance, ensuring your data remains safe and out of reach from unauthorized actors.

CipherMimic is especially suitable for use cases where **high performance**, **scalability**, and **stealth** are paramount, including:

- Secure file encryption for personal and enterprise applications
- Security and penetration testing
- Data protection in high-risk environments
- Developing ransomware-like functionality for ethical research

---

## **Key Features**

### **🛡️ Stealth Encryption**

- **Argon2 Key Derivation:** CipherMimic employs the Argon2 password hashing algorithm, one of the most secure and memory-hard key derivation functions available, ensuring protection against brute-force attacks.
- **AES-GCM Encryption:** Supports the industry-standard AES-GCM encryption algorithm, ensuring maximum security and data integrity.
- **Obfuscated File Names:** Encrypts file names using Base64 encoding to hide their original purpose, further adding stealth.

### **🔒 Advanced Security**

- **In-Memory Execution:** Minimizes the writing of sensitive data to disk, reducing the chances of leaving forensic traces.
- **Machine-Specific Encryption:** CipherMimic derives encryption keys based on the specific machine it runs on, ensuring that even if the binary is stolen, it can't be executed on a different device.
- **HMAC for Data Integrity:** Uses HMAC (Hash-based Message Authentication Code) to detect tampering, ensuring that encrypted files remain intact.

### **💥 Operational Security (OpSec)**

- **Self-Destruct Mechanism:** Automatically wipes itself and logs if too many failed attempts are detected, preventing attackers from reverse engineering or analyzing the tool.
- **Shredding Files:** Performs multi-pass overwriting of original files to prevent data recovery.
- **Encrypted Logging:** Optional encrypted logging that ensures no sensitive information is exposed in logs.

### **⚡ High Performance & Scalability**

- **Concurrency with Worker Pool:** Supports multi-threaded file encryption with a controlled worker pool for optimal performance on systems with multiple CPU cores.
- **Large File Support:** Handles both small and large files efficiently by chunking and parallelizing encryption operations.

### **🔑 KMS Integration**

- **AWS KMS Support:** Integrates with **AWS KMS** for secure key management, allowing you to store and retrieve encryption keys in the cloud.

### **🤖 Fully Customizable**

- **Golang Codebase:** Written in Go 1.23.0, making it easy to extend, modify, and integrate with other tools.
- **Command-Line Interface:** Full control over the encryption process via command-line options, giving you the ability to fine-tune performance and security based on your needs.

---

## **How It Works**

CipherMimic is designed around key cryptographic principles and modern stealth practices. Here's an overview of the encryption flow:

1. **Key Generation:** The user provides a password, and Argon2 generates a 256-bit key derived from the password, salt, and machine-specific identifiers (e.g., CPU serial).
2. **AWS KMS Integration:** For enterprise deployments, the tool supports AWS KMS for securely managing encryption keys.
3. **File Encryption:** CipherMimic walks through a directory, encrypting all files using AES-GCM. It also generates a unique nonce for each file.
4. **HMAC Integrity Check:** Each encrypted file is appended with an HMAC to ensure the encrypted data hasn’t been tampered with.
5. **Obfuscation and Deletion:** Files are renamed with obfuscated names, and the original files are shredded using multi-pass overwriting techniques.
6. **Self-Destruct:** If tampering or too many failed attempts are detected, CipherMimic will self-destruct, wiping traces from the system.

---

## **Installation**

### **Prerequisites**

- Go 1.23.0 or later is required to build CipherMimic from source. Ensure that Go is properly installed on your system.
- AWS credentials are needed if using AWS KMS integration for key management.

### **Build from Source**

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/CipherMimic.git
   cd CipherMimic
   ```

2. Build the executable:

   ```bash
   go build -o ciphermimic
   ```

3. Run the tool:

   ```bash
   ./ciphermimic
   ```

### **Binary Releases**

Precompiled binaries for major operating systems (Linux, Windows, macOS) are available under the [Releases](https://github.com/yourusername/CipherMimic/releases) section.

---

## **Usage**

### **Basic Command**

To encrypt all files in the user's home directory:

```bash
./ciphermimic --password "super_secret_key"
```

### **Command Line Options**

- `--password <password>`: The password used for key generation.
- `--dir <directory>`: The directory to walk and encrypt (defaults to the user's home directory).
- `--shred`: Shreds files after encryption with multi-pass overwriting (default is enabled).
- `--algorithm <aes>`: Choose the encryption algorithm (default: AES-GCM).
- `--workers <N>`: Set the number of concurrent workers for encryption (default: Number of CPU cores).
- `--self-destruct`: Enable the self-destruct mechanism after a certain number of failures.

### **Examples**

Encrypt all files in a custom directory using AES-GCM:

```bash
./ciphermimic --password "super_secret_key" --dir "/path/to/directory" --algorithm aes
```

Encrypt files with 4 concurrent workers:

```bash
./ciphermimic --password "super_secret_key" --workers 4
```

---

## **Best Practices for Testing**

1. **Test in a VM or Sandbox:** Always run CipherMimic in a controlled environment such as a virtual machine or isolated container.
2. **Use Dummy Files:** Before encrypting sensitive data, test with dummy files to ensure the encryption and shredding process works as intended.
3. **Monitor System Activity:** Use system monitoring tools like Sysmon or auditd to ensure CipherMimic operates stealthily.
4. **Review Logs:** If you enable logging for testing purposes, ensure it’s disabled in production to maintain operational security.

---

## **Security and Compliance**

CipherMimic follows modern encryption best practices, ensuring compliance with:

- **GDPR** for encryption of personal data
- **NIST SP 800-131A** for cryptographic algorithms and key management
- **FIPS 140-2** for AES-GCM and HMAC operations (when applicable)
- **Zero Trust Model:** Adhering to zero-trust security concepts

> **Disclaimer:** This tool is intended for **ethical research** and **legitimate security purposes**. Misuse of this tool for illegal activities, such as ransomware, is strictly prohibited.

---

## **Contribution Guidelines**

I welcome contributions to improve CipherMimic! Whether it’s adding new features, fixing bugs, or enhancing performance, feel free to submit pull requests or open issues.

### Steps for Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-xyz`).
3. Make your changes and commit them (`git commit -m 'Add feature xyz'`).
4. Push to your fork (`git push origin feature-xyz`).
5. Create a pull request.

---

## **License**

CipherMimic is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for more information.
