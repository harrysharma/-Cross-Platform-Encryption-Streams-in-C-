#pragma once

#include "Stream.h"
#include "Stream/Buffer.h"

#if defined(_XBOX_ONE)
#define USE_BCRYPT
#endif

#if defined(USE_BCRYPT)
#include "XBCrypto.h"
#else
#include "SSLCrypto.h"
#include <openssl/evp.h>
#endif


namespace TWN
{
  class Crypto
  {
  public:
    static void InitializeLibrary();
  };

  class EncryptionStream : public WriteStream
  {
  public:
    EncryptionStream(WriteStream* dest);

    bool Init(int algorithm, const void* key, size_t keySize, const void* iv, size_t ivSize);

    bool NextWrite(Buffer& buffer) override;
    bool AdvanceWrite(int bytes) override;
  protected:
    Buffer m_lastBuffer;
    WriteStream* m_dest;
#if defined(USE_BCRYPT)
    XBCrypto m_crypto;
#else
    SSLCrypto m_crypto;
#endif
  };

  class DecryptionStream : public ReadStream
  {
  public:
    DecryptionStream(ReadStream* source);

    bool Init(int algorithm, const void* key, size_t keySize, const void* iv, size_t ivSize);

    bool NextRead(Buffer& buffer) override;
    bool AdvanceRead(int bytes) override;

    void SetSource(ReadStream* source) { m_source = source; }
  protected:
    bool Decrypt();
    int GetAvailableRead() const { return m_readEnd - m_readPos; }

    ReadStream* m_source;
#if defined(USE_BCRYPT)
    XBCrypto m_crypto;
#else
    SSLCrypto m_crypto;
#endif

    uint8_t m_buffer[4096];
    uint8_t* m_readPos;
    uint8_t* m_readEnd;
  };

  // Encrypts data in block-sized chunks, and pads data so its size is a multiple of the block size
  // Less efficient than a normal EncryptionStream because it has to copy data to an intermediate buffer, but necessary for BCrypt <-> OpenSSL interop
  class BlockEncryptionStream : public WriteStream
  {
  public:
    BlockEncryptionStream(WriteStream* dest);

    bool Init(int algorithm, const void* key, size_t keySize, const void* iv, size_t ivSize);

    bool NextWrite(Buffer& buffer) override;
    bool AdvanceWrite(int bytes) override;

    void Flush();

  protected:
    int Pad(uint8_t* buffer, int bufferLen, int dataLen);
    int GetAvailableRead() const { return m_writePos - m_buffer; }

    Buffer m_lastBuffer;
    WriteStream* m_dest;
#if defined(USE_BCRYPT)
    XBCrypto m_crypto;
#else
    SSLCrypto m_crypto;
#endif

    int m_blockSize;

    uint8_t m_buffer[4096];
    uint8_t m_encrypedBuffer[4096];
    uint8_t* m_writePos;
  };

  // Decrypts data that was encrypted by a BlockEncryptionStream
  // Less efficient than a normal DecryptionStream because it has to copy data to an intermediate buffer, but necessary for BCrypt <-> OpenSSL interop
  class BlockDecryptionStream : public ReadStream
  {
  public:
    BlockDecryptionStream(ReadStream* source);

    bool Init(int algorithm, const void* key, size_t keySize, const void* iv, size_t ivSize);

    bool NextRead(Buffer& buffer) override;
    bool AdvanceRead(int bytes) override;

    void Flush();

    void SetSource(ReadStream* source) { m_source = source; }
  protected:
    bool Decrypt();
    int GetAvailableRead() const { return m_readEnd - m_readPos; }
    int GetUsedWrite() const { return m_writePos - m_encrypedBuffer; }
    int GetAvailableWrite() const { return TWN_ARRAY_SIZE(m_encrypedBuffer) - GetUsedWrite(); }

    ReadStream* m_source;
#if defined(USE_BCRYPT)
    XBCrypto m_crypto;
#else
    SSLCrypto m_crypto;
#endif

    int m_blockSize;

    uint8_t m_buffer[4096];
    uint8_t m_encrypedBuffer[4096];
    uint8_t* m_readPos;
    uint8_t* m_readEnd;
    uint8_t* m_writePos;
  };
}
