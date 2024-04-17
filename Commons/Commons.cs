using System.ComponentModel;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace QuatschAndSuch
{
    class Commons
    {
        
    }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct,AllowMultiple = false, Inherited = false)]
    public class ByteSerializable : Attribute
    {
        public readonly string[] SerializedFields;

        public ByteSerializable(params string[] serializedFields)
        {
            SerializedFields = serializedFields;
        }
    }

    public static class ByteSerializer
    {
        public class MissingSerializableAtttributeException : Exception { }

        public static byte[] Serialize<T>(T source)
        {
            if (typeof(T).IsClass)
            {
                if (Attribute.GetCustomAttribute(typeof(T), typeof(ByteSerializable)) is not ByteSerializable b) throw new MissingSerializableAtttributeException();

                List<byte> data = new();
                foreach (string fieldName in b.SerializedFields)
                {
                    data.AddRange(Serialize(typeof(T).GetField(fieldName).GetValue(source)));
                }

                return data.ToArray();
            } else
            {
                switch (source)
                {
                    case int i:
                        {
                            return BitConverter.GetBytes(i);
                        }
                    case long l:
                        {
                            return BitConverter.GetBytes(l);
                        }
                    case string s:
                        {
                            byte[] bytes = Encoding.Unicode.GetBytes(s);
                            return BitConverter.GetBytes(bytes.Length).Concat(bytes).ToArray();
                        }
                    case byte[] bytes:
                        {
                            return BitConverter.GetBytes(bytes.Length).Concat(bytes).ToArray();
                        }
                    case var obj:
                        {
                            byte[] bytes = Serialize(obj);
                            return BitConverter.GetBytes(bytes.Length).Concat(bytes).ToArray();
                        }
                }
            }
        }

        public static T Deserialize<T>(byte[] bytes, int offset, out int bytesRead)
        {
            bytesRead = 0;
            if (typeof(T).IsClass)
            {
                if (Attribute.GetCustomAttribute(typeof(T), typeof(ByteSerializable)) is not ByteSerializable b) throw new MissingSerializableAtttributeException();
                T obj = default;

                List<byte> data = new(bytes);
                MethodInfo method = typeof(ByteSerializer).GetMethod(nameof(Deserialize));

                foreach (string fieldName in b.SerializedFields)
                {
                    FieldInfo f = typeof(T).GetField(fieldName);
                    object[] parameters = new object[] { data.ToArray(), 0, null };
                    f.SetValue(obj, method.MakeGenericMethod(f.FieldType).Invoke(null, parameters));
                    bytesRead += (int)parameters[2];
                }

                return obj;
            } else
            {
                switch (typeof(T))
                {
                    case Type t when t == typeof(int):
                        {
                            bytesRead = 4;
                            return (T)(object)BitConverter.ToInt32(bytes);
                        }
                    case Type t when t == typeof(long):
                        {
                            bytesRead = 8;
                            return (T)(object)BitConverter.ToInt64(bytes);
                        }
                    case Type t when t == typeof(string):
                        {
                            int len = BitConverter.ToInt32(bytes);
                            bytesRead = 4 + len;
                            return (T)(object)Encoding.Unicode.GetString(bytes.Skip(4).Take(len).ToArray());
                        }
                    case Type t when t == typeof(byte[]):
                        {
                            int len = BitConverter.ToInt32(bytes);
                            bytesRead = 4 + len;
                            return (T)(object)bytes.Skip(4).Take(len).ToArray();
                        }
                    case Type t:
                        {
                            int len = BitConverter.ToInt32(bytes);
                            T r = Deserialize<T>(bytes.Skip(4).Take(len).ToArray(), 0, out bytesRead);
                            bytesRead += 4;
                            return r;
                        }
                    default: return default;
                        
                }
            }
        }
    }
    

    /// <summary>
    /// Gives information for connecting to servers. These servers are simply there as the link for the parties to communicate over. The messages stay encrypted the whole time
    /// </summary>
    [Serializable]
    public class ServerInfo
    {
        public readonly string Name;
        public readonly string Description;
        public readonly string Url;
    }

    /// <summary>
    /// Gives information on the client, to keep track of them.
    /// </summary>
    [Serializable, ByteSerializable(nameof(Name), nameof(Handle), nameof(key))]
    public class ClientInfo
    {
        public readonly string Name;
        public readonly string Handle;
        public readonly byte[] key;
    }

    public abstract class Packet
    {
        public static readonly Dictionary<byte, Func<byte[], Packet>> creators = new()
        {
            { 0, b => new BasicPacket(b.First(), Encoding.Unicode.GetString(b, 5, BitConverter.ToInt32(b, 1))) },
            { 1, b => new GreetPacket(ByteSerializer.Deserialize<ClientInfo>(b, 0, out var _)) },
            { 2, b => new ChannelRequestPacket(ByteSerializer.Deserialize<ClientInfo>(b, 0, out var i), Encoding.Unicode.GetString(b, i + 4, BitConverter.ToInt32(b, i))) }
        };

        public abstract byte Id { get; }

        protected virtual byte[] Serialize(params byte[] data)
        {
            return new byte[] { Id }.Concat(data).ToArray();
        }

        public abstract byte[] Serialize();

        public static Packet Deserialize(byte[] data)
        {
            return creators[data.First()](data.Skip(1).ToArray());
        }
    }

    public class BasicPacket : Packet
    {
        public override byte Id => 0;
        public readonly BasicValue value;
        public readonly string reason;

        public enum BasicValue
        {
            Acknowledge, // General acknowledgement / positive answer
            NonAcknowledge, // General non-acknowledgement / negative answer
            Repeat, // Repeat the last packet
            Close // Close the connection
        }

        public BasicPacket(byte value, string reason)
        {
            this.value = (BasicValue)value;
            this.reason = reason;
        }

        public BasicPacket(BasicValue value, string reason)
        {
            this.value = value;
            this.reason = reason;
        }

        public override byte[] Serialize()
        {
            byte[] bytes = Encoding.Unicode.GetBytes(reason);
            return base.Serialize( new byte[] { (byte)value }.Concat(BitConverter.GetBytes(bytes.Length)).Concat(bytes).ToArray());
        }
    }

    public class GreetPacket : Packet
    {
        public override byte Id => 1;
        public readonly ClientInfo clientInfo;

        public GreetPacket(ClientInfo clientInfo)
        {
            this.clientInfo = clientInfo;
        }

        public override byte[] Serialize()
        {
            return base.Serialize(ByteSerializer.Serialize(clientInfo));
        }
    }

    /// <summary>
    /// Static class to provide cryptographic functionality
    /// </summary>
    public static class Crypto
    {
        // Settings
        const int saltSize = 32;
        const int secureHashSize = 256;
        const bool fOAEL = false;
        static readonly HashAlgorithm hashAlgorithm = SHA256.Create();
        static readonly PbeParameters keySavingParams = new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000);

        public class DecryptionHashMismatchException : Exception
        {
            public DecryptionHashMismatchException()
            {
            }

            public DecryptionHashMismatchException(string message) : base(message)
            {
            }

            public DecryptionHashMismatchException(string message, Exception innerException) : base(message, innerException)
            {
            }

            protected DecryptionHashMismatchException(SerializationInfo info, StreamingContext context) : base(info, context)
            {
            }
        }
        public class PasswordHashMismatchException : Exception
        {
            public PasswordHashMismatchException()
            {
            }

            public PasswordHashMismatchException(string message) : base(message)
            {
            }

            public PasswordHashMismatchException(string message, Exception innerException) : base(message, innerException)
            {
            }

            protected PasswordHashMismatchException(SerializationInfo info, StreamingContext context) : base(info, context)
            {
            }
        }

        /// <summary>
        /// Generates new private and public keys using RSA
        /// </summary>
        /// <returns>A tuple containing the CSP blobs for the private and public key in that order</returns>
        public static (byte[], byte[]) GenerateKeys()
        {
            using RSACryptoServiceProvider rsa = new();
            return (rsa.ExportCspBlob(true), rsa.ExportCspBlob(false));
        }

        /// <summary>
        /// Securly generates a hash for the inputted data using PBKDF2
        /// </summary>
        /// <returns><see cref="secureHashSize"><c>SecureHashSize</c></see> bytes from the hash</returns>
        public static byte[] SecuredHash(byte[] data, byte[] salt)
        {
            if (salt.Length != saltSize) throw new ArgumentException("The salt needs to be the specified length", nameof(salt));
            using Rfc2898DeriveBytes rfc = new(data, salt, keySavingParams.IterationCount, keySavingParams.HashAlgorithm);
            return rfc.GetBytes(secureHashSize);
        }

        /// <summary>
        /// Securly generates a hash for the inputted data using PBKDF2, using a random value for the salt
        /// </summary>
        /// <returns>The salt and <see cref="secureHashSize"><c>secureHashSize</c></see> bytes from the hash</returns>
        public static (byte[], byte[]) SecuredHash(byte[] data)
        {
            byte[] salt = new byte[saltSize];
            RandomNumberGenerator.Fill(salt);
            using Rfc2898DeriveBytes rfc = new(data, salt, keySavingParams.IterationCount, keySavingParams.HashAlgorithm);
            return (salt, rfc.GetBytes(secureHashSize));
        }

        /// <summary>
        /// Locally saves the key, along with the verification information for the password
        /// </summary>
        /// <param name="path">The path to saves this information to</param>
        /// <param name="key">The CSP blob for the private key to save</param>
        /// <param name="password">The password to use for PKCS#8. Make sure to handle this securely!</param>
        public static void SaveKey(string path, byte[] key, byte[] password)
        {
            using RSACryptoServiceProvider rsa = new();
            rsa.ImportCspBlob(key);
            byte[] keyData = rsa.ExportEncryptedPkcs8PrivateKey(password, keySavingParams);
            int keyLen = keyData.Length;
            (byte[] salt, byte[] hash) = SecuredHash(password);
            File.WriteAllBytes(path, BitConverter.GetBytes(keyLen).Concat(keyData).Concat(salt).Concat(hash).ToArray());
        }

        /// <summary>
        /// Retrieve the locally stored key information, and verifies the password
        /// </summary>
        /// <param name="path">The path to get the information from</param>
        /// <param name="password">The password to use for PKCS#8. Make sure to handle this securely!</param>
        /// <returns>CSP blob for the decoded private key</returns>
        /// <exception cref="PasswordHashMismatchException"Thrown if the password does not fit the stored password information</exception>
        public static byte[] RetrieveKey(string path, byte[] password)
        {
            byte[] data = File.ReadAllBytes(path);
            byte[] keyData = new byte[BitConverter.ToInt32(data)];
            Array.Copy(data, 4, keyData, 0, keyData.Length);
            byte[] salt = new byte[saltSize];
            Array.Copy(data, keyData.Length + 4, salt, 0, salt.Length);
            byte[] hashData = new byte[secureHashSize];
            Array.Copy(data, keyData.Length + salt.Length + 4, hashData, 0, hashData.Length);

            byte[] hash = SecuredHash(password, salt);
            if (!hashData.Equals(hash)) throw new PasswordHashMismatchException();
            using RSACryptoServiceProvider rsa = new();
            rsa.ImportEncryptedPkcs8PrivateKey(password, keyData, out var _);
            return rsa.ExportCspBlob(true);
        }

        /// <summary>
        /// Retrieve the locally stored key information, and verifies the password
        /// </summary>
        /// <param name="path">The path to get the information from</param>
        /// <param name="offset">The offset index from whihc to start reading the key information</param>
        /// <param name="password">The password to use for PKCS#8. Make sure to handle this securely!</param>
        /// <param name="bytesRead">How many bytes wereread for the key information</param>
        /// <returns>CSP blob for the decoded private key</returns>
        /// <exception cref="PasswordHashMismatchException"Thrown if the password does not fit the stored password information</exception>
        public static byte[] RetrieveKey(string path, int offset, byte[] password, out int bytesRead)
        {
            byte[] data = File.ReadAllBytes(path);
            byte[] keyData = new byte[BitConverter.ToInt32(data, offset)];
            Array.Copy(data, 4 + offset, keyData, 0, keyData.Length);
            byte[] salt = new byte[saltSize];
            Array.Copy(data, keyData.Length + 4 + offset, salt, 0, salt.Length);
            byte[] hashData = new byte[secureHashSize];
            Array.Copy(data, keyData.Length + salt.Length + 4 + offset, hashData, 0, hashData.Length);

            byte[] hash = SecuredHash(password, salt);
            if (!hashData.Equals(hash)) throw new PasswordHashMismatchException();
            bytesRead = keyData.Length + salt.Length + hashData.Length + 4;
            using RSACryptoServiceProvider rsa = new();
            rsa.ImportEncryptedPkcs8PrivateKey(password, keyData, out var _);
            return rsa.ExportCspBlob(true);
        }

        /// <summary>
        /// Decrypts an encryption packet, and checks its hash to make sure it arrived correctly. Throws a <see cref="DecryptionHashMismatchException"><c>DecryptionHashMismatchException</c></see> when the sent hash and hash of the decrypted string are not the same
        /// </summary>
        /// <param name="packet">The encryption packet. It contains the length of the following encrypted messgae string, followed by the 32 byte hash of the original string</param>
        /// <param name="key">The private key of the recipient</param>
        /// <returns>The decrypted and verified message string</returns>
        /// <exception cref="DecryptionHashMismatchException"></exception>
        public static string Decrypt(byte[] packet, byte[] key)
        {
            int msgLength = BitConverter.ToInt32(packet);
            byte[] msg = packet.Skip(4).Take(msgLength).ToArray();
            byte[] sentHash = packet.Skip(msgLength + 4).Take(hashAlgorithm.HashSize / 8).ToArray();
            using RSACryptoServiceProvider rsa = new();
            rsa.ImportCspBlob(key);
            byte[] msgString = rsa.Decrypt(msg, fOAEL);
            byte[] hash = hashAlgorithm.ComputeHash(msgString);
            if (!hash.Equals(sentHash))
            {
                throw new DecryptionHashMismatchException($"Hash mismatch for decrypted message:\nSent:   {BitConverter.ToString(sentHash)}\nHashed: {BitConverter.ToString(hash)}");
            }
            return Encoding.Unicode.GetString(msg);
        }

        /// <summary>
        /// Decrypts an encryption packet, and checks its hash to make sure it arrived correctly. Throws a <see cref="DecryptionHashMismatchException"><c>DecryptionHashMismatchException</c></see> when the sent hash and hash of the decrypted string are not the same
        /// </summary>
        /// <param name="buffer">The buffer containing the encryption packet. See <c cref="Decrypt(byte[], byte[])">Decrypt</c> for more info</param>
        /// <param name="offset">The index in the buffer to begin and try to read the packet from</param>
        /// <param name="key">The private key of the recipient</param>
        /// <param name="packetLength">The length of the extracted packet in bytes</param>
        /// <returns>The decrypted and verified message string</returns>
        /// <exception cref="DecryptionHashMismatchException"></exception>
        public static string Decrypt(byte[] buffer, int offset, byte[] key, out int packetLength)
        {
            int len = BitConverter.ToInt32(buffer, offset);
            packetLength = 4 + len + hashAlgorithm.HashSize / 8;
            return Decrypt(buffer.Skip(offset).ToArray(), key);
        }

        /// <summary>
        /// Enrypts a string using the provided public key of the recipient
        /// </summary>
        /// <param name="message">The string to be encrypted. Supports Unicode (UTF-16)</param>
        /// <param name="key">The CSP blob of the recipients public key</param>
        /// <returns>The encryption packet for the message. See <see cref="Decrypt(byte[], byte[])"><c>Decrypt</c></see> for more info on this</returns>
        public static byte[] Encrypt(string message, byte[] key)
        {
            using RSACryptoServiceProvider rsa = new();
            rsa.ImportCspBlob(key);
            byte[] msg = rsa.Encrypt(Encoding.Unicode.GetBytes(message), fOAEL);
            byte[] hash = hashAlgorithm.ComputeHash(Encoding.Unicode.GetBytes(message));
            return BitConverter.GetBytes(msg.Length).Concat(msg).Concat(hash).ToArray();
        }

        
    }
}