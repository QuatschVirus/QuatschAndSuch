using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using QuatschAndSuch.Logging;

namespace QuatschAndSuch.Authentication
{
    public class Authentication
    {
        public const uint AuthPacketPrefix = 0xFF_00_00_00;

        public static Packet BodyToPacket(byte[] body, byte[] key)
        {
            int length = BitConverter.ToInt32(body);
            string raw;
            if (length < 0)
            {
                raw = Crypto.Decrypt(body.Skip(8).Take(length).ToArray(), key);
            }
            else
            {
                raw = Encoding.Unicode.GetString(body.Skip(8).Take(length).ToArray());
            }
            return Packet.Deserialize(raw);
        }

        public static byte[] PacketToBody(Packet packet, byte[] publicKey, out long bodyLength)
        {
            string raw = Packet.Serialize(packet);
            byte[] encoded;
            if (publicKey != null)
            {
                encoded = Crypto.Encrypt(raw, publicKey);
            } else
            {
                encoded = Encoding.Unicode.GetBytes(raw);
            }
            int length = encoded.Length;
            if (publicKey != null) length *= -1;
            bodyLength = Math.Abs(length);
            return BitConverter.GetBytes(length).Concat(encoded).ToArray();
        }
    }

    public class AuthenticationProvider
    {
        public readonly Guid uid;

        readonly Dictionary<string, AuthenticationCertificate> certificates = new();
        public readonly Service service;
        readonly TimeSpan authenticationLife;
        readonly TimeSpan certificateTimeout;
        readonly TimeSpan timeout;
        readonly Uri serverURL;

        readonly HttpClient http;
        readonly byte[] serverKey;

        readonly byte[] key;
        public readonly byte[] publicKey;

        readonly Logger logger;

        public bool Validated { get; private set; } = false;

        public AuthenticationProvider(Guid guid, string serverURL, Service service, TimeSpan authenticationLife, TimeSpan certificateTimeout, TimeSpan timeout, Logger logger)
        {
            this.uid = guid;
            this.logger = logger;
            this.logger.Info("Beginning initalization of AuthenticationProvider", $"AuthenticationProvider [{uid}]");
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

        public bool Revalidate(string secret)
        {
            var response = http.Send(GetEncryptedMessage("VALIDATE", service.ToString(), Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(secret)))));
            string[] resp = GetDecryptedResponse(response);
            if (ProcessResponse(resp, out var header, out var body, "VALIDATED", "VALIDATION_FAILED"))
            {
                if (header == "VALIDATED")
                {
                    logger.Info("AuthenticationProvider has been revalidated" + ((body.Length > 0) ? ("\n" + string.Join('\n', body)) : ""), $"AuthenticationProvider [{uid}]");
                    return true;
                } else
                {
                    logger.Error("ValidationFailed", "AuthenticationProvider could not be reauthenticated. Reason: " + ((body.Length > 0) ? ("\n" + string.Join('\n', body)) : ""), $"AuthenticationProvider [{uid}]");
                }
            } else
            {
                logger.Error("ValidationFailed", $"AuthenticationProvider could not be reauthenticated becasue the response was invalid. You may need to contact the developers. Recieved:\n{header}\n{string.Join('\n', body)}", $"AuthenticationProvider [{uid}]");
            }
            return false;
        }

        HttpRequestMessage GetInitializationMessage()
        {
            return new(HttpMethod.Post, new Uri(serverURL, "/provider-init"))
            {
                Content = JsonContent.Create(new ProviderInfo(this))
            };
        }

        HttpRequestMessage GetRenewalMessage(AuthenticationCertificate certificate)
        {
            return GetEncryptedMessage("RENEW", certificate.Hash);
        }

        HttpRequestMessage GetEncryptedMessage(params string[] content)
        {
            byte[] data = uid.ToByteArray().Concat(Crypto.Encrypt(string.Join('\n', content), serverKey)).ToArray();
            return new(HttpMethod.Post, new Uri(serverURL, "/provider"))
            {
                Content = new StringContent(Convert.ToBase64String(data))
            };
        }

        string[] GetDecryptedResponse(HttpResponseMessage response)
        {
            response.EnsureSuccessStatusCode();
            byte[] raw = response.Content.ReadAsByteArrayAsync().Result;
            string content = Crypto.Decrypt(raw, key);
            return content.Split('\n');
        }

        bool ProcessResponse(string[] response, out string header, out string[] body, params string[] validHeaders)
        {
            if (response.Length < 1) throw new ArgumentException("The response needs to contain atleast a header", nameof(response));
            header = response[0];
            if (header == "INVALID")
            {
                logger.Warn("InvalidAuthenticationProvider", "VAlidation for the AuthenticationProvider has expired", $"AuthenticationProvider [{uid}]");
                Validated = false;
                header = null;
                body = null;
                return false;
            }
            body = response.Skip(1).ToArray();
            return validHeaders.Contains(header);
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

        public void Revoke(string handle)
        {
            certificates.Remove(handle);
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

    [Serializable]
    public class AuthServerClient : ClientInfo
    {
        public Service authorizedServices;
        public string password;

        public string token;
        public DateTime validUntil = DateTime.UnixEpoch;
        public DateTime tokenIssued = DateTime.UnixEpoch;

        public AuthServerClient(string name, string handle, byte[] key, Service authorizedServices, string password) : base(name, handle, key)
        {
            this.authorizedServices = authorizedServices;
            this.password = password;
        }

        public AuthServerClient(ClientInfo basis) : base(basis.Name, basis.Handle, basis.key)
        {
            this.authorizedServices = Service.None;
            this.password = null;
        }

        public byte[] GetTokenHash()
        {
            if (token != "")
            {
                return SHA256.HashData(Encoding.Unicode.GetBytes($"{Handle}: {token} [{tokenIssued:yyyy-MM-dd HH-mm-ss}]"));
            }
            return null;
        }

        public byte[] TokenHash => GetTokenHash();

        public bool Registered => password != null;
    }

    [Serializable, Table("Providers")]
    public class ProviderInfo
    {
        [Key] public readonly Guid uid;
        public readonly Service service;
        public byte[] key;
        public DateTime runout = DateTime.UtcNow;
        public readonly string secret = null;

        public ProviderInfo(Guid uid, Service service, byte[] key)
        {
            this.uid = uid;
            this.service = service;
            this.key = key;
        }

        public ProviderInfo(AuthenticationProvider source) : this(source.uid, source.service, source.publicKey) {}

        public bool Valid => runout > DateTime.UtcNow;
        public bool Official => secret != null;
    }

    [Serializable, Packet(Authentication.AuthPacketPrefix | 0)]
    public class ProviderPacket : Packet
    {
        public readonly ProviderInfo info;
        public readonly bool seekingValidation;

        public ProviderPacket(ProviderInfo info, bool seekingValidation)
        {
            this.info = info;
            this.seekingValidation = seekingValidation;
        }
    }

}