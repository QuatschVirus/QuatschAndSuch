using System.IO;
using System.Net;
using System.Text;
using System.Security.Cryptography;
using System.Buffers.Text;

namespace QuatschAndSuch.Authentication.Server
{
    public class AuthServer
    {
        const string url = "http://*:5000";

        readonly HttpListener http = new();

        byte[] key;
        byte[] publicKey;

        Dictionary<string, AuthClientInfo> clients = new();

        public static void Main(string[] args)
        {
            
        }

        public AuthServer()
        {
            http.Prefixes.Add(url);
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
                    case "/provider":
                        {
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