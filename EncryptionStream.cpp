#include "EncryptionStream.h"
#include "Buffer.h"

#include "Common/Assert.h"
#include "FixedStream.h"

namespace TWN
{
  //////////////////////////////////////////////////////////////////////////
  // EncryptionStream
  //////////////////////////////////////////////////////////////////////////

  EncryptionStream::EncryptionStream(WriteStream* dest)
    : m_dest(dest)
  {

  }

  bool EncryptionStream::Init(int algorithm, const void* key, size_t keySize, const void* iv, size_t ivSize)
  {
    return m_crypto.Init(algorithm, key, keySize, iv, ivSize, true, true);
  }

  bool EncryptionStream::NextWrite(Buffer& buffer)
  {
    bool result = m_dest->NextWrite(m_lastBuffer);
    buffer.SetData(m_lastBuffer.GetData(), m_lastBuffer.GetDataLen());
    return result;
  }

  bool EncryptionStream::AdvanceWrite(int bytes)
  {
    PROF_EX(EncryptionStream, AdvanceWrite);
    size_t written = m_crypto.Cipher(m_lastBuffer.GetData(), bytes);
    return m_dest->AdvanceWrite(static_cast<int>(written));
  }


  //////////////////////////////////////////////////////////////////////////
  // DecryptionStream
  //////////////////////////////////////////////////////////////////////////

  DecryptionStream::DecryptionStream(ReadStream* source)
    : m_source(source)
    , m_readPos(m_buffer)
    , m_readEnd(m_buffer)
  {

  }

  bool DecryptionStream::Init(int algorithm, const void* key, size_t keySize, const void* iv, size_t ivSize)
  {
    return m_crypto.Init(algorithm, key, keySize, iv, ivSize, false, true);
  }

  bool DecryptionStream::NextRead(Buffer& buffer)
  {
    bool ok = true;

    if(GetAvailableRead() == 0)
    {
      ok = Decrypt();
    }

    if(ok)
    {
      buffer.SetData(m_readPos, m_readEnd - m_readPos);
      return true;
    }
    else
    {
      return false;
    }
  }

  bool DecryptionStream::AdvanceRead(int bytes)
  {
    TWN_REQUIRE(bytes <= GetAvailableRead());

    if(bytes <= GetAvailableRead())
    {
      m_readPos += bytes;
      return true;
    }

    return false;
  }

  bool DecryptionStream::Decrypt()
  {
    m_readPos = m_readEnd = m_buffer;

    Buffer buffer;
    if(m_source->NextRead(buffer))
    {
      int len = twn::min<int>(TWN_ARRAY_SIZE(m_buffer), static_cast<int>(buffer.GetDataLen()));
      memcpy(m_buffer, buffer.GetData(), len);
      m_source->AdvanceRead(len);

      size_t written = m_crypto.Cipher(m_buffer, len);
      m_readEnd = m_buffer + written;

      return true;
    }

    return false;
  } 

  /*static*/ void Crypto::InitializeLibrary()
  {
#if defined(USE_BCRYPT)
    XBCrypto::InitializeLibrary();
#else
    SSLCrypto::InitializeLibrary();
#endif
  }


  //////////////////////////////////////////////////////////////////////////
  // BlockEncryptionStream
  //////////////////////////////////////////////////////////////////////////

  BlockEncryptionStream::BlockEncryptionStream(WriteStream* dest)
    : m_dest(dest)
    , m_blockSize(0)
    , m_writePos(m_buffer)
  {

  }

  bool BlockEncryptionStream::Init(int algorithm, const void* key, size_t keySize, const void* iv, size_t ivSize)
  {
    m_blockSize = static_cast<int>(keySize);

    return m_crypto.Init(algorithm, key, keySize, iv, ivSize, true, false);
  }

  bool BlockEncryptionStream::NextWrite(Buffer& buffer)
  {
    size_t bufferRemaining = TWN_ARRAY_SIZE(m_buffer) - GetAvailableRead();
    buffer.SetData(m_writePos, bufferRemaining);
    return true;
  }

  bool BlockEncryptionStream::AdvanceWrite(int bytes)
  {
    PROF_EX(BlockEncryptionStream, AdvanceWrite);

    int totalBytes = bytes + GetAvailableRead();

    if(totalBytes >= m_blockSize)
    {
      // Only encrypt bytes in block-sized chunks
      int bytesToWrite = totalBytes - (totalBytes % m_blockSize);
      int remainingBytes = totalBytes - bytesToWrite;
      size_t written = m_crypto.Cipher(m_buffer, m_encrypedBuffer, bytesToWrite);

      // Copy remaining bytes to start of buffer so they can be encrypted later (possibly after padding)
      memcpy(m_buffer, m_buffer + bytesToWrite, remainingBytes);

      m_writePos = m_buffer + remainingBytes;

      return Stream::Copy(m_encrypedBuffer, *m_dest, written);
    }
    else
    {
      m_writePos += bytes;
    }

    return true;
  }

  void BlockEncryptionStream::Flush()
  {
    int padBytes = Pad(m_buffer, TWN_ARRAY_SIZE(m_buffer), GetAvailableRead());

    TWN_REQUIRE((GetAvailableRead() + padBytes) % m_blockSize == 0);

    AdvanceWrite(padBytes);
  }

  int BlockEncryptionStream::Pad(uint8_t* buffer, int bufferLen, int dataLen)
  {
    int paddingLen = m_blockSize - (dataLen % m_blockSize);

    if(dataLen + paddingLen < bufferLen)
    {
      // Pad to block size by filling with 0s, except the last byte which is number of padded bytes
      buffer += dataLen;

      for(int i = 0; i < paddingLen - 1; ++i)
      {
        *buffer = 0;
        ++buffer;
      }

      *buffer = static_cast<uint8_t>(paddingLen);

      return paddingLen;
    }
    else
    {
      TWN_BUG("BlockEncryptionStream: Padding failed due to insufficient buffer space");
    }

    return 0;
  }


  //////////////////////////////////////////////////////////////////////////
  // BlockDecryptionStream
  //////////////////////////////////////////////////////////////////////////

  BlockDecryptionStream::BlockDecryptionStream(ReadStream* source)
    : m_source(source)
    , m_readPos(m_buffer)
    , m_readEnd(m_buffer)
    , m_writePos(m_encrypedBuffer)
    , m_blockSize(0)
  {

  }

  bool BlockDecryptionStream::Init(int algorithm, const void* key, size_t keySize, const void* iv, size_t ivSize)
  {
    m_blockSize = static_cast<int>(keySize);

    return m_crypto.Init(algorithm, key, keySize, iv, ivSize, false, false);
  }

  bool BlockDecryptionStream::NextRead(Buffer& buffer)
  {
    bool ok = true;

    if(GetAvailableRead() == 0)
    {
      ok = Decrypt();
    }

    if(ok)
    {
      buffer.SetData(m_readPos, m_readEnd - m_readPos);
      return true;
    }
    else
    {
      return false;
    }
  }

  bool BlockDecryptionStream::AdvanceRead(int bytes)
  {
    TWN_REQUIRE(bytes <= GetAvailableRead());

    if(bytes <= GetAvailableRead())
    {
      m_readPos += bytes;
      return true;
    }

    return false;
  }

  void BlockDecryptionStream::Flush()
  {
    int bytesToRead = GetUsedWrite();

    TWN_REQUIRE(bytesToRead % m_blockSize == 0);
    TWN_REQUIRE(bytesToRead <= static_cast<int>(TWN_ARRAY_SIZE(m_buffer)) - (m_buffer - m_readEnd));

    size_t written = m_crypto.Cipher(m_encrypedBuffer, m_readEnd, bytesToRead);

    if(written > 0)
    {
      m_readEnd += written;
      uint8_t numPaddedBytes = *(m_readEnd - 1);

      if(numPaddedBytes <= m_blockSize)
      {
        m_readEnd -= numPaddedBytes;
      }
      else
      {
        TWN_BUG("BlockDecryptionStream: Invalid number of padded bytes {0}; maximum is {1}", numPaddedBytes, m_blockSize);
      }
    }

    m_writePos = m_encrypedBuffer;
  }

  bool BlockDecryptionStream::Decrypt()
  {
    m_readPos = m_readEnd = m_buffer;

    int bytesRead = 0;

    Buffer buffer;
    while(GetAvailableWrite() > 0 && GetAvailableRead() < m_blockSize && m_source->NextRead(buffer))
    {
      int len = static_cast<int>(twn::min<size_t>(GetAvailableWrite(), buffer.GetDataLen()));
      
      memcpy(m_writePos, buffer.GetData(), len);
      m_writePos += len;
      m_source->AdvanceRead(len);

      // All data is padded to be a multiple of the block size, which means the final bytes are always padded bytes.
      // The padded bytes are decrypted in Flush(). So, don't decrypt the last bytes out of the buffer here just in case they are the final padded bytes.

      int availableBytes = GetUsedWrite();
      int bytesToRead = availableBytes - (availableBytes % m_blockSize) - m_blockSize;
      int remainingBytes = availableBytes - bytesToRead;

      if(bytesToRead > 0)
      {
        size_t written = m_crypto.Cipher(m_encrypedBuffer, m_buffer, bytesToRead); 
        m_readEnd = m_buffer + written;

        // Copy remaining bytes to start of buffer so they can be decrypted later
        memmove(m_encrypedBuffer, m_encrypedBuffer + bytesToRead, remainingBytes);
        m_writePos = m_encrypedBuffer + remainingBytes;
      }

      bytesRead += len;
    }

    return bytesRead > 0;
  }
}
