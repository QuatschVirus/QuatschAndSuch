using System.ComponentModel;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace QuatschAndSuch
{
    class Commons
    {
        
    }

    [AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
    public class PacketAttribute : Attribute
    {
        public byte id;

        public PacketAttribute(byte id)
        {
            this.id = id;
        }
    }

    public class MissingAtttributeException : Exception { }
    

    /// <summary>
    /// Gives information for connecting to servers. These servers are simply there as the link for the parties to communicate over. The messages stay encrypted the whole time
    /// </summary>
    [Serializable]
    public class ServerInfo
    {
        public readonly string Name;
        public readonly string Description;
        public readonly string Url;
        public readonly ClientInfo Identity;

        public override string ToString()
        {
            return $"{Name} @ {Url}";
        }
    }

    /// <summary>
    /// Gives information on the client, to keep track of them.
    /// </summary>
    [Serializable]
    public class ClientInfo
    {
        public readonly string Name;
        public readonly string Handle;
        public readonly byte[] key;

        public ClientInfo(string name, string handle, byte[] key)
        {
            Name = name;
            Handle = handle;
            this.key = key;
        }
    }

    public class Packet
    {
        public static readonly Dictionary<byte, Type> typeResolve = new();
        public static readonly Dictionary<Type, byte> idResolve = new();

        public static Packet Deserialize(string data)
        {
            (byte id, string content) = JsonSerializer.Deserialize<(byte, string)>(data);
            return (Packet)JsonSerializer.Deserialize(content, typeResolve[id]);
        }

        public static string Serialize(Packet packet)
        {
            return JsonSerializer.Serialize((idResolve[packet.GetType()], JsonSerializer.Serialize(packet, packet.GetType())));
        }

        static Packet()
        {
            var packets =
                from a in AppDomain.CurrentDomain.GetAssemblies().AsParallel()
                from t in a.GetTypes()
                where t.IsSubclassOf(typeof(Packet))
                let attribute = Attribute.GetCustomAttribute(t, typeof(PacketAttribute)) as PacketAttribute
                where attribute != null
                select (t, attribute.id);

            packets.ForAll(a =>
            {
                idResolve.Add(a.t, a.id);
                typeResolve.Add(a.id, a.t);
            });
        }
    }

    [Serializable, Packet(0)]
    public class BasicPacket : Packet
    {
        public readonly BasicValue value;
        public readonly string reason;

        public enum BasicValue
        {
            /// <summary>
            /// General acknowledgement / positive answer
            /// </summary>
            Acknowledge,
            /// <summary>
            /// General non-acknowledgement / negative answer
            /// </summary>
            NonAcknowledge,
            /// <summary>
            /// Repeat the last packet
            /// </summary>
            Repeat,
            /// <summary>
            /// Close the connection
            /// </summary>
            Close
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
    }

    [Serializable, Packet(1)]
    public class GreetPacket : Packet
    {
        public readonly ClientInfo clientInfo;

        public GreetPacket(ClientInfo clientInfo)
        {
            this.clientInfo = clientInfo;
        }
    }

    [Serializable, Packet(2)]
    public class QueryPacket : Packet
    {
        public readonly string query;

        public QueryPacket(string query)
        {
            this.query = query;
        }
    }

    [Serializable, Packet(3)]
    public class QueryDataPacket : Packet
    {
        public readonly object data;

        public QueryDataPacket(object data)
        {
            this.data = data;
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
        const int iVSize = 64;
        const int SyncBlockSize = 256;
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
        public static (byte[], byte[]) GenerateKeyPair()
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
        /// Gets the public key out of the private key
        /// </summary>
        /// <param name="key">The private key</param>
        /// <returns>The correspondng public key</returns>
        public static byte[] Extract(byte[] key)
        {
            using RSACryptoServiceProvider rsa = new();
            rsa.ImportCspBlob(key);
            return rsa.ExportCspBlob(false);
        }

        /// <summary>
        /// Locally saves the key, along with the verification information for the password
        /// </summary>
        /// <param name="path">The path to saves this information to</param>
        /// <param name="key">The CSP blob for the private key to save</param>
        /// <param name="password">The password to use for PKCS#8. Make sure to handle this securely!</param>
        public static void SaveKey(string path, byte[] key, string password)
        {
            using RSACryptoServiceProvider rsa = new();
            rsa.ImportCspBlob(key);
            byte[] keyData = rsa.ExportEncryptedPkcs8PrivateKey(password, keySavingParams);
            int keyLen = keyData.Length;
            (byte[] salt, byte[] hash) = SecuredHash(Encoding.Unicode.GetBytes(password));
            File.WriteAllBytes(path, BitConverter.GetBytes(keyLen).Concat(keyData).Concat(salt).Concat(hash).ToArray());
        }

        /// <summary>
        /// Retrieve the locally stored key information, and verifies the password
        /// </summary>
        /// <param name="path">The path to get the information from</param>
        /// <param name="password">The password to use for PKCS#8. Make sure to handle this securely!</param>
        /// <returns>CSP blob for the decoded private key</returns>
        /// <exception cref="PasswordHashMismatchException"Thrown if the password does not fit the stored password information</exception>
        public static byte[] RetrieveKey(string path, string password)
        {
            return RetrieveKey(path, 0, password, out var _);
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
        public static byte[] RetrieveKey(string path, int offset, string password, out int bytesRead)
        {
            byte[] data = File.ReadAllBytes(path);
            byte[] keyData = new byte[BitConverter.ToInt32(data, offset)];
            Array.Copy(data, 4 + offset, keyData, 0, keyData.Length);
            byte[] salt = new byte[saltSize];
            Array.Copy(data, keyData.Length + 4 + offset, salt, 0, salt.Length);
            byte[] hashData = new byte[secureHashSize];
            Array.Copy(data, keyData.Length + salt.Length + 4 + offset, hashData, 0, hashData.Length);

            byte[] hash = SecuredHash(Encoding.Unicode.GetBytes(password), salt);
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

        /// <summary>
        /// Locally save a file, encrypted with symmetric encryption. Make sure to not lose the key!
        /// </summary>
        /// <param name="path">The path to save the encrypted file at</param>
        /// <param name="content">To content to encrypt and save</param>
        /// <param name="key">The key to encrypt everything with. Make sure to pick a secure, hard to guess key</param>
        public static void SaveEncrypted(string path, string content, string key)
        {
            (byte[] password, byte[] salt) = SecuredHash(Encoding.Unicode.GetBytes(key));
            byte[] iv = new byte[iVSize];
            RandomNumberGenerator.Fill(iv);
            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.BlockSize = SyncBlockSize;
            using FileStream f = File.Create(path);
            f.Write(salt);
            f.Write(iv);
            using var encryptor = aes.CreateEncryptor(password, iv);
            using CryptoStream c = new(f, encryptor, CryptoStreamMode.Write);
            c.Write(Encoding.Unicode.GetBytes(content));
            c.FlushFinalBlock();
            f.Flush();
        }

        /// <summary>
        /// Retrieve and decrypt the contents of a locally saved, symmetrically enrypted file.
        /// </summary>
        /// <param name="path">The path to the encrypted file</param>
        /// <param name="key">The key that was used to encrypt the data</param>
        /// <returns></returns>
        public static string RetrieveEncrypted(string path, string key)
        {
            using FileStream f = File.OpenRead(path);
            byte[] salt = new byte[saltSize];
            byte[] iv = new byte[iVSize];
            f.Read(salt);
            f.Read(iv);
            byte[] password = SecuredHash(Encoding.Unicode.GetBytes(key), salt);
            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.BlockSize = SyncBlockSize;
            using var decryptor = aes.CreateDecryptor(password, iv);
            using CryptoStream c = new(f, decryptor, CryptoStreamMode.Read);
            using StreamReader r = new(c);
            return r.ReadToEnd();
        }
    }
}