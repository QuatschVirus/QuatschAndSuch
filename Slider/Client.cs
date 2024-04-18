using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace QuatschAndSuch.Slider.Client
{

    public class Client
    {

        const string infoFilePath = "./info.dat";
        const string keyFilePath = "./key.dat";
        const string fallbackLogBasePath = "./";
        const string conversationsPath = "./Convos";

        protected Logging logger;
        protected byte[] Key { get; private set; }
        protected byte[] PublicKey { get; private set; }

        protected List<ServerInfo> servers = null;
        protected Dictionary<string, ClientInfo> clients = null;

        protected List<Message> conversation = null;
        protected ClientInfo conversationPartner = null;

        public Client(string[] args, Logging frontEndLogger)
        {
            logger = frontEndLogger ?? new(Path.Combine(fallbackLogBasePath, Logging.LogFileName));
        }

        public void LoadKeys(string password)
        {
            if (File.Exists(keyFilePath))
            {
                Key = Crypto.RetrieveKey(keyFilePath, password);
                PublicKey = Crypto.Extract(Key);
            } else
            {
                GenerateNewKeys(password);
            }
        }

        public void SaveKeys(string password)
        {
            Crypto.SaveKey(keyFilePath, Key, password);
        }

        public void GenerateNewKeys(string password)
        {
            (Key, PublicKey) = Crypto.GenerateKeyPair();
            SaveKeys(password);
        }

        public State GetState()
        {
            State s = State.None;
            if (Key != null && PublicKey != null) s |= State.KeysLoaded;
            if (servers != null && clients != null) s |= State.InfoLoaded;
            if (conversation != null && conversationPartner != null) s |= State.ConversationLoaded;

            return s;
        }

        public bool HasState(State s)
        {
            return (s & GetState()) == s;
        }

        public void LoadInfo(string password)
        {
            if (File.Exists(infoFilePath))
            {
                (servers, clients) = JsonSerializer.Deserialize<(List<ServerInfo>, Dictionary<string, ClientInfo>)>(Crypto.RetrieveEncrypted(infoFilePath, password));
            } else
            {
                logger.Warn("InfoFileNotFound", $"The info file at {Path.GetFullPath(infoFilePath)} could not be loaded. Creating a new empty file");
                SaveInfo(password);
            }
        }

        public void SaveInfo(string password)
        {
            Crypto.SaveEncrypted(infoFilePath, JsonSerializer.Serialize((servers, clients)), password);
        }

        public void LoadConversation(ClientInfo partner)
        {
            RequireState(State.KeysLoaded);
            string identifier = BitConverter.ToString(Encoding.Unicode.GetBytes(partner.Handle)).Replace("-", string.Empty);
            string path = Path.Combine(conversationsPath, identifier + ".dat");
            string data = Crypto.Decrypt(File.ReadAllBytes(path), Key);
            conversation = JsonSerializer.Deserialize<List<Message>>(data);
            conversationPartner = partner;
        }

        public void SaveConversation()
        {
            RequireState(State.KeysLoaded);
            string identifier = BitConverter.ToString(Encoding.Unicode.GetBytes(conversationPartner.Handle)).Replace("-", string.Empty);
            string path = Path.Combine(conversationsPath, identifier + ".dat");
            string data = JsonSerializer.Serialize(conversation);
            File.WriteAllBytes(path, Crypto.Encrypt(data, PublicKey));
        }

        public void RequireState(params State[] state)
        {
            State s = State.None;
            foreach (State s2 in state)
            {
                s |= s2;
            }

            if (!HasState(s)) throw new MissingStateException("The required states to run this are missing");
        }
        
    }

    [Flags]
    public enum State
    {
        None = 0,
        KeysLoaded = 1,
        InfoLoaded = 2,
        ConversationLoaded = 4,
    }

    [Serializable]
    public class Message
    {
        public readonly ClientInfo sender;
        public readonly string message;
        public readonly DateTime sent;

        public Message(ClientInfo sender, string message)
        {
            this.sender = sender;
            this.message = message;
            sent = DateTime.Now;
        }

        public Message(ClientInfo sender, string message, DateTime sent) : this(sender, message)
        {
            this.sent = sent;
        }
    }

    /// <summary>
    /// Something has been called in the wrong state
    /// </summary>
    public class MissingStateException : Exception
    {
        public MissingStateException()
        {
        }

        public MissingStateException(string message) : base(message)
        {
        }

        public MissingStateException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected MissingStateException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
