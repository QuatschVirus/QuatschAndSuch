using System.IO;
using System.Net;
using System.Text;
using System.Security.Cryptography;
using System.Buffers.Text;
using System.Text.Json;
using Commons.Database;
using Microsoft.EntityFrameworkCore;
using QuatschAndSuch.Authentication;
using SQLitePCL;
using System.Net.Sockets;

namespace QuatschAndSuch.Authentication.Server
{
    public class AuthServerDatabase : Database
    {
        public DbSet<AuthServerClient> Clients { get; set; }
        public DbSet<ProviderInfo> Providers { get; set; }

        public AuthServerDatabase(string key) : base("./database.db", key)
        {

        }
    }

    public class AuthServer
    {
        const string url = "http://*:5000";
        const string providerFilePath = "./providers.dat";

        public static readonly TimeSpan validationLife = TimeSpan.FromMinutes(60);

        readonly HttpListener http = new();

        byte[] key;
        byte[] publicKey;

        readonly AuthServerDatabase db;
        readonly PacketHandler packetHandler = new()
        {
            FallbackHandler = (p, t) => (new BasicPacket(BasicPacket.BasicValue.Invalid, ""), null),
        };

        readonly Dictionary<Guid, ProviderInfo> providers = new();


        public static void Main(string[] args)
        {
            
        }

        public AuthServer(string key)
        {
            db = new(key);
            http.Prefixes.Add(url);
            RenewKeys();

            packetHandler.RegisterHandler<GreetPacket>((p, t) =>
            {
                GreetPacket packet = p as GreetPacket;
                AuthServerClient c = db.Clients.Find(packet.clientInfo.Handle);
                if (c == null)
                {
                    db.Clients.Add(new(packet.clientInfo));
                }
                else
                {
                    c.key = packet.clientInfo.key;
                }
                db.SaveChanges();
                return (new KeyPacket(publicKey), null);
            });

            packetHandler.RegisterHandler<ProviderPacket>((pc, t) =>
            {
                ProviderPacket packet = pc as ProviderPacket;
                ProviderInfo p = db.Providers.Find(packet.info.uid);
                if (p == null)
                {
                    return (new BasicPacket(BasicPacket.BasicValue.NonAcknowledge, "Unkown provider"), null);
                }
                if (packet.seekingValidation)
                {
                    if (p.service == packet.info.service && p.secret == packet.info.secret)
                    {
                        p.runout = DateTime.UtcNow + validationLife;
                        db.SaveChanges();
                        return (new BasicPacket(BasicPacket.BasicValue.Acknowledge, "Revalidated"), null);
                    }
                    else
                    {
                        return (new BasicPacket(BasicPacket.BasicValue.NonAcknowledge, "Revalidation failed"), null);
                    }
                }
                else
                {
                    p.key = packet.info.key;
                    db.SaveChanges();
                    return (new KeyPacket(publicKey), null);
                }
            });
        }

        void Recieve()
        {
            var ctx = http.GetContext();
            var req = ctx.Request;
            using var resp = ctx.Response;
            resp.ContentEncoding = Encoding.Unicode;
            HttpStatusCode code = HttpStatusCode.OK;

            Packet response = new BasicPacket(BasicPacket.BasicValue.Invalid, "");
            byte[] recieverKey = null;
            if (req.HasEntityBody)
            {
                byte[] buffer = new byte[req.ContentLength64];
                _ = req.InputStream.Read(buffer);
                Packet pc = Authentication.BodyToPacket(buffer, key);
                (response, recieverKey) = packetHandler.Handle(pc);
            }
            byte[] body = Authentication.PacketToBody(response, recieverKey, out long outLength);
            resp.OutputStream.Write(body);
            resp.StatusCode = (int)code;
            resp.ContentLength64 = outLength;
        }

        void RenewKeys()
        {
            (key, publicKey) = Crypto.GenerateKeyPair();
        }

        
    }
}