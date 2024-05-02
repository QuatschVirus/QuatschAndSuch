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
        readonly Dictionary<Guid, (Service, string)> recognisedProviders = new();



        public static void Main(string[] args)
        {
            
        }

        public AuthServer(string key)
        {
            http.Prefixes.Add(url);
            recognisedProviders = JsonSerializer.Deserialize<Dictionary<Guid, (Service, string)>>(Crypto.RetrieveEncrypted(providerFilePath, key));
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
                            string handle = input.ReadLine();
                            byte[] key = Convert.FromBase64String(input.ReadToEnd());



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
                    case "/provider":
                        {
                            byte[] data = Convert.FromBase64String(input.ReadToEnd());
                            Guid uid = new(data.Take(16).ToArray());
                            string[] content = Crypto.Decrypt(data.Skip(16).ToArray(), key).Split('\n');
                            if (!providers.ContainsKey(uid))
                            {
                                output.WriteLine("UNKOWN");
                                output.WriteLine($"Unkown AuthenticationProvider {uid}");
                            }

                            switch (content[0])
                            {
                                case "VALIDATE":
                                    {
                                        if (!recognisedProviders.ContainsKey(uid))
                                        {
                                            output.WriteLine("VALIDATION_FAILED");
                                            output.WriteLine($"AuthenticationProvider {uid} is not recognised. Contact the developers for recognition");
                                            break;
                                        }
                                        var pData = recognisedProviders[uid];
                                        Service s = Enum.Parse<Service>(content[1]);
                                        if (pData == (s, content[2]))
                                        {
                                            providers[uid].runout = DateTime.UtcNow + validationLife;
                                            output.WriteLine("VALIDATED");
                                            output.WriteLine($"AuthenticationProvider {uid} revalidated until {providers[uid].runout:o}");
                                        } else
                                        {
                                            output.WriteLine("VALIDATION_FAILED");
                                            output.WriteLine($"AuthenticationProvider {uid} revalidation failed. Secret or Services did not match with the record (Services: {content[1]} vs {recognisedProviders[uid].Item1})");
                                        }
                                        break;
                                    }
                                case "AUTH":
                                    {
                                        break;
                                    }
                                case "RENEW":
                                    {
                                        break;
                                    }
                                default:
                                    {
                                        providers[uid].runout = DateTime.UtcNow;
                                        output.WriteLine("REVALIDATE");
                                        output.WriteLine($"Sent invalid header ({content[0]}), revalidate for security");
                                        break;
                                    }
                            }
                            break;
                        }
                    case "/auth":
                        {
                            (string handle, string password) = JsonSerializer.Deserialize<(string, string)>(Crypto.Decrypt(Convert.FromBase64String(input.ReadToEnd()), key));

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