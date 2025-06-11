# -Cross-Platform-Encryption-Streams-in-C-
Building secure, real-time systems? One of the most powerful tools in your arsenal is a streaming crypto interface.

I recently worked on a cross-platform C++ encryption/decryption stream layer that handles:
✅ On-the-fly data encryption
✅ Seamless support for OpenSSL and BCrypt (Xbox)
✅ Buffered, block-aware design for performance & portability

💡 Key learnings:

Designed EncryptionStream / DecryptionStream for plug-and-play crypto in pipelines

Used abstraction to cleanly switch between OpenSSL & BCrypt without changing client code

Handled block-padding challenges (AES) with custom BlockEncryptionStream logic

📦 Applications:

Encrypted logs or save files

Secure file/network I/O

Game engines and high-performance apps

It’s been a deep dive into crypto, system design, and cross-platform development—and a reminder that clean design can coexist with performance-critical code.
