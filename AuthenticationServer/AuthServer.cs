using System.IO;
using System.Net;
using System.Text;
using System.Security.Cryptography;
using System.Buffers.Text;
using System.Text.Json;

namespace QuatschAndSuch.Authentication.Server
{
    public class AuthServer
    {
        const string url = "http://*:5000";
        const string providerFilePath = "./providers.dat";

        public static readonly TimeSpan validationLife = TimeSpan.FromMinutes(60);

        readonly HttpListener http = new();

        byte[] key;
        byte[] publicKey;

        readonly Dictionary<string, AuthClientInfo> clients = new();
        readonly Dictionary<string, AuthenticationSignature> signatures = new();

        readonly Dictionary<Guid, ProviderInfo> providers = new();
        readonly Dictionary<Guid, byte[]> recognisedProviders = new();



        public static void Main(string[] args)
        {
            
        }

        public AuthServer(string key)
        {
            http.Prefixes.Add(url);
            recognisedProviders = JsonSerializer.Deserialize<Dictionary<Guid, byte[]>>(Crypto.RetrieveEncrypted(providerFilePath, key));
            RenewKeys();
        }

        void Recieve()
        {
            var ctx = http.GetContext();
            var req = ctx.Request;
            using var resp = ctx.Response;
            using StreamReader input = new(req.InputStream, req.ContentEncoding);
            using StreamWriter output = new(resp.OutputStream, Encoding.Unicode);
            resp.ContentEncoding = Encoding.Unicode;
            long outLength = resp.ContentLength64;
            HttpStatusCode code = HttpStatusCode.OK;

            if (req.HasEntityBody)
            {
                switch (req.Url.LocalPath)
                {
                    case "/preauth":
                        {
                            string handle = input.ReadToEnd();

                            output.WriteLine(Convert.ToBase64String(publicKey));
                            break;
                        }
                    case "/provider-init":
                        {
                            ProviderInfo info = JsonSerializer.Deserialize<ProviderInfo>(input.ReadToEnd());
                            if (recognisedProviders.ContainsKey(info.uid) && !providers.ContainsKey(info.uid)) providers.Add(info.uid, info);
                            output.Write(Convert.ToBase64String(publicKey));
                            break;
                        }
                    default:
                        {
                            code = HttpStatusCode.NotFound;
                            break;
                        }
                }
                
            }

            resp.StatusCode = (int)code;
            resp.ContentLength64 = outLength;
        }

        void RenewKeys()
        {
            (key, publicKey) = Crypto.GenerateKeyPair();
        }
    }
}