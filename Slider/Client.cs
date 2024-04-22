using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WebSocketSharp;

namespace QuatschAndSuch.Slider.Client
{

    public class Client
    {
        public event Action StateUpdated;
        public event Action<PromptType, string> PromptInitiated;

        readonly string infoFilePath = "./info.dat";
        readonly string keyFilePath = "./key.dat";
        readonly string fallbackLogBasePath = "./";
        readonly string conversationsPath = "./Convos";

        protected Logging logger;
        protected byte[] Key { get; private set; }
        protected byte[] PublicKey { get; private set; }

        protected List<ServerInfo> servers = null;
        protected Dictionary<string, ClientInfo> clients = null;

        protected List<Message> conversation = null;
        protected ClientInfo conversationPartner = null;

        protected WebSocket socket = null;
        protected ServerInfo activeConnection = null;

        #region ---StateFlags---
        protected bool identityAcknowledged = false;
        #endregion

        public Client(string[] args, Logging frontEndLogger)
        {
            logger = frontEndLogger ?? new(Path.Combine(fallbackLogBasePath, Logging.LogFileName));
            StateUpdated.Invoke();
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
            StateUpdated.Invoke();
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
            if (socket != null && socket.IsAlive) s |= State.ConnectedToServer; 
            if (identityAcknowledged) s |= State.IdentityAckowledged;

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
            StateUpdated.Invoke();
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
            StateUpdated.Invoke();
        }

        public void SaveConversation()
        {
            RequireState(State.KeysLoaded);
            string identifier = BitConverter.ToString(Encoding.Unicode.GetBytes(conversationPartner.Handle)).Replace("-", string.Empty);
            string path = Path.Combine(conversationsPath, identifier + ".dat");
            string data = JsonSerializer.Serialize(conversation);
            File.WriteAllBytes(path, Crypto.Encrypt(data, PublicKey));
        }

        public bool HasOpenConversation(ClientInfo partner)
        {
            string identifier = BitConverter.ToString(Encoding.Unicode.GetBytes(partner.Handle)).Replace("-", string.Empty);
            return File.Exists(Path.Combine(conversationsPath, identifier + ".dat"));
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
        
        public bool Connect(ServerInfo s)
        {
            socket = new(s.Url);
            socket.Connect();
            if (socket.ReadyState == WebSocketState.Open)
            {
                activeConnection = s;
                socket.OnMessage += OnMessage;
                StateUpdated.Invoke();
                return true;
            } else
            {
                logger.Error("ConnectionError", $"Could not connect to server {s}");
                return false;
            }
        }

        public void Greet(ClientInfo c)
        {
            socket.Send(Packet.Serialize(new GreetPacket(c)));
        }

        protected virtual void OnMessage(object sender, MessageEventArgs e)
        {
            Packet packet;
            if (e.IsBinary)
            {
                packet = Packet.Deserialize(Crypto.Decrypt(e.RawData, Key));
            } else if (e.IsText)
            {
                packet = Packet.Deserialize(e.Data);
            } else if (e.IsPing)
            {
                packet = new BasicPacket(BasicPacket.BasicValue.Ping, "");
            } else
            {
                return;
            }

            switch (packet)
            {
                case BasicPacket p:
                    {
                        if (!identityAcknowledged)
                        {
                            if (p.value == BasicPacket.BasicValue.Acknowledge)
                            {
                                identityAcknowledged = true;
                            } else if (p.value == BasicPacket.BasicValue.NonAcknowledge)
                            {
                                PromptInitiated.Invoke(PromptType.NewHandle, "");
                            }
                            return;
                        }
                        break;
                    }
            }
        }
    }

    [Flags]
    public enum State
    {
        None = 0,
        KeysLoaded = 1,
        InfoLoaded = 2,
        ConversationLoaded = 4,
        ConnectedToServer = 8,
        IdentityAckowledged = 16,
    }

    public enum PromptType
    {
        NewHandle
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
