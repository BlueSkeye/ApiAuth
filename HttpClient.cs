using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace ApiAuth
{
    public class HttpClient : IDisposable
    {
        private const string AuthorizationContentHeaderName =
            "X-Authorization-Content-SHA256";
        private const int NoGcRegionSize = 16 * 1024 * 1024;
        private static readonly object _noGcLock = new object();
        private SecureString _apiKeyId;
        private SecureString _apiSecretKey;
        private string _authorizationPrefix;

        private HttpClient()
        {
        }

        public void Dispose()
        {
            Dispose(true);
        }

        protected void Dispose(bool disposing)
        {
            if (disposing) {
                GC.SuppressFinalize(this);
            }
        }

        public string ApiKeyId
        {
            set
            {
                _apiKeyId = new SecureString();
                foreach(char scannedCharacter in value
                    ?? throw new ArgumentNullException("ApiKeyId")) {
                    _apiKeyId.AppendChar(scannedCharacter);
                }
                _apiKeyId.MakeReadOnly();
            }
        }

        public SecureString ApiSecretKey
        {
            set { _apiSecretKey = value.Copy(); }
        }

        public string AuthorizationPrefix
        {
            set { _authorizationPrefix = value; }
        }

        public static HttpClient Create()
        {
            return new HttpClient();
        }

        private static string CreateCanonicalString(HttpWebRequest request)
        {
            WebHeaderCollection headers =
                (request ?? throw new ArgumentNullException(nameof(request))).Headers;
            StringBuilder canonicalBuilder = new StringBuilder();
            canonicalBuilder.Append(request.Method
                ?? throw new InvalidOperationException("Method not defined"));
            canonicalBuilder.Append(',');
            canonicalBuilder.Append(request.ContentType ?? string.Empty);
            canonicalBuilder.Append(',');
            canonicalBuilder.Append(headers.Get(AuthorizationContentHeaderName));
            canonicalBuilder.Append(',');
            canonicalBuilder.Append((request.RequestUri
                ?? throw new InvalidOperationException("Request path undefined"))
                    .AbsolutePath
                        ?? throw new InvalidOperationException("Path undefined"));
            canonicalBuilder.Append(',');
            canonicalBuilder.Append(DateTime.UtcNow.ToString("R"));
            return canonicalBuilder.ToString();
        }

        public HttpWebResponse Send(HttpWebRequest request)
        {
            string canonicalString = CreateCanonicalString(request);
            string base64Signature = GetAuthorizationString(canonicalString);
            request.Headers.Add("Authorization", base64Signature);
            return (HttpWebResponse)request.GetResponse();
        }

        private string GetAuthorizationString(string canonicalString)
        {
            byte[] rawCanonicalString = UnicodeEncoding.Unicode.GetBytes(canonicalString
                ?? throw new ArgumentNullException(nameof(canonicalString)));
            byte[] signature;
            using (HMACSHA256 signatureAlgorithm = (HMACSHA256)HMACSHA256.Create()) {
                IntPtr rawSecretKey = IntPtr.Zero;
                byte[] transientSecretKey = null;
                lock (_noGcLock) {
                    // Remark : Secret key may be leaked in memory if a GC occurs between
                    // marshaling conversion and finally block completion.
                    GC.TryStartNoGCRegion(1024);
                    try {
                        try {
                            rawSecretKey = Marshal.SecureStringToCoTaskMemUnicode(_apiSecretKey);
                            transientSecretKey = Marshal.PtrToStructure<byte[]>(rawSecretKey);
                        }
                        finally {
                            if (IntPtr.Zero != rawSecretKey) {
                                Marshal.ZeroFreeCoTaskMemUnicode(rawSecretKey);
                            }
                        }
                        try {
                            // TODO : Check accessor source code. Should the key be copied
                            // in an objet local array, some additional security measure
                            // should be enforced.
                            signatureAlgorithm.Key = transientSecretKey;
                            signature = signatureAlgorithm.ComputeHash(rawCanonicalString);
                        }
                        finally {
                            int transientSecretKeylength = transientSecretKey.Length;
                            for(int index = 0; index < transientSecretKeylength; index++) {
                                transientSecretKey[index] = 0;
                            }
                        }
                    }
                    finally {
                        GC.EndNoGCRegion();
                    }
                }
            }
            return Convert.ToBase64String(signature);
        }
    }
}
