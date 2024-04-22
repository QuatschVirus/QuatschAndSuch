using System.ComponentModel;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;

namespace QuatschAndSuch.Authentication
{
    public class AuthenticationProvider
    {
        readonly Dictionary<string, AuthenticationCertificate> certificates = new();
        readonly Service service;
        readonly TimeSpan authenticationLife;
        readonly TimeSpan certificateTimeout;
        readonly TimeSpan timeout;
        readonly Uri serverURL;

        readonly HttpClient http;
        readonly byte[] serverKey;

        readonly byte[] key;
        readonly byte[] publicKey;

        public AuthenticationProvider(string serverURL, Service service, TimeSpan authenticationLife, TimeSpan certificateTimeout, TimeSpan timeout)
        {
            this.service = service;
            this.authenticationLife = authenticationLife;
            this.certificateTimeout = certificateTimeout;
            this.serverURL = new(serverURL);
            this.timeout = timeout;

            (key, publicKey) = Crypto.GenerateKeyPair();

            http = new()
            {
                Timeout = timeout
            };
            var response = http.Send(GetInitializationMessage());
            response.EnsureSuccessStatusCode();
            serverKey = Convert.FromBase64String(response.Content.ReadAsStringAsync().Result);
        }

        HttpRequestMessage GetInitializationMessage()
        {
            return new(HttpMethod.Post, new Uri(serverURL, "/provider"))
            {
                Content = JsonContent.Create((service, publicKey))
            };
        }

        HttpRequestMessage GetRenewalMessage(AuthenticationCertificate certificate)
        {
            return GetEncryptedMessage("RENEW", certificate.Hash);
        }

        HttpRequestMessage GetEncryptedMessage(params string[] content)
        {
            return new(HttpMethod.Post, new Uri(serverURL, "/provider"))
            {
                Content = new ByteArrayContent(Crypto.Encrypt(string.Join('\n', content), serverKey))
            };
        }

        string[] GetDecryptedResponse(HttpResponseMessage response)
        {
            response.EnsureSuccessStatusCode();
            byte[] raw = response.Content.ReadAsByteArrayAsync().Result;
            string content = Crypto.Decrypt(raw, key);
            return content.Split('\n');
        }

        public bool Renew(AuthenticationCertificate certificate)
        {
            var response = http.Send(GetRenewalMessage(certificate));
            string[] res = GetDecryptedResponse(response);
            if (res[0] == "RENEWED")
            {
                certificate.LastRenewed = DateTime.Parse(res[1]);
                return true;
            }
            return false;
        }

        public bool CheckAuthentication(string handle, bool autoRenew = true)
        {
            if (!certificates.ContainsKey(handle)) return false;
            var certificate = certificates[handle];
            if (certificate.LastChecked + certificateTimeout < DateTime.UtcNow)
            {
                certificates.Remove(handle);
                return false;
            }
            if (certificate.LastRenewed + authenticationLife < DateTime.UtcNow)
            {
                if (autoRenew) // Needs to be this way, because otherwise it would be renewed either way
                {
                    return Renew(certificate);
                } else
                {
                    return false;
                }
            }
            return true;
        }

        public bool Authenticate(string handle, string token)
        {
            var response = http.Send(GetEncryptedMessage("AUTH", handle, token));
            string[] res = GetDecryptedResponse(response);
            if (res[0] == "AUTHED")
            {
                certificates.Add(handle, AuthenticationCertificate.GenerateCertificate(res[1]));
                return CheckAuthentication(handle);
            }
            return false;
        }
    }

    public class AuthenticationCertificate
    {
        public const char PropertySeperator = '\0';

        public readonly string Handle;
        public readonly string Token;
        public DateTime LastChecked;
        public DateTime LastRenewed;
        public readonly DateTime FirstIssued;
        public readonly Service Service;

        public AuthenticationCertificate(string handle, string token, DateTime firstIssued, Service service)
        {
            Handle = handle;
            Token = token;
            LastChecked = firstIssued;
            LastRenewed = firstIssued;
            FirstIssued = firstIssued;
            Service = service;
        }

        public static AuthenticationCertificate GenerateCertificate(string data)
        {
            string[] properties = data.Split(PropertySeperator);
            if (properties.Length != 4) throw new ArgumentException("The CertificateData needs exactly four line-break (\\n) seperated properties", nameof(data));
            Service service = (Service)Enum.Parse(typeof(Service), properties[0]);
            DateTime firstIssued = DateTime.Parse(properties[3]);
            return new(properties[1], properties[2], firstIssued, service);
        }

        public string Hash => GetHash();

        public string GetHash()
        {
            string data = $"({Service}) {Handle}: {Token} [{FirstIssued:yyyy-MM-dd HH-mm-ss}]";
            return Convert.ToBase64String(SHA256.HashData(Encoding.Unicode.GetBytes(data)));
        }
    }

    public struct AuthenticationSignature
    {
        public readonly string Handle;
        public readonly string Token;
        public readonly DateTime FirstIssued;
        public readonly Service Service;
        public DateTime LastRenewed;

        public AuthenticationSignature(string handle, string token, Service service)
        {
            Handle = handle;
            Token = token;
            FirstIssued = DateTime.UtcNow;
            LastRenewed = DateTime.UtcNow;
            Service = service;
        }

        public readonly bool Check(string hash)
        {
            return GetHash().Equals(hash);
        }

        public readonly string GetCertificateData()
        {
            return string.Join(AuthenticationCertificate.PropertySeperator, Service, Handle, Token, FirstIssued.ToString("o"));
        }

        public readonly string GetHash()
        {
            string data = $"({Service}) {Handle}: {Token} [{FirstIssued:yyyy-MM-dd HH-mm-ss}]";
            return Convert.ToBase64String(SHA256.HashData(Encoding.Unicode.GetBytes(data)));
        }
    }
}