using System.Net;

namespace QuatschAndSuch.AuthServer
{
    class AuthServer
    {
        const string url = "http://*:5000";

        readonly HttpListener http = new();

        public static void Main(string[] args)
        {
            
        }

        public AuthServer()
        {
            http.Prefixes.Add(url);
        }

        void Recieve()
        {
            var ctx = http.GetContext();
            var req = ctx.Request;
            var resp = ctx.Response;

            if (req.HasEntityBody)
            {
                switch (req.Url.LocalPath)
                {
                    case "/preauth":
                        {
                            
                        }
                }
            }
        }

        bool CheckAuthentication()
        {

        }
    }

    [Serializable]
    class AuthClientInfo : ClientInfo
    {
        public readonly Service authorizedServices;
        public readonly byte[] salt;

        public AuthClientInfo(string name, string handle, byte[] key, Service authorizedServices, byte[] salt) : base(name, handle, key)
        {
            this.authorizedServices = authorizedServices;
            this.salt = salt;
        }
    }

    [Flags]
    public enum Service
    {
        Slider = 1
    }
}