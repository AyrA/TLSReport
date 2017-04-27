using System;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace TLSReport
{
    public class TLS
    {
        public Exception Error { get; private set; }
        public X509Certificate[] ServerChain { get; private set; }
        public X509Certificate ServerCertificate { get; set; }
        public IPEndPoint RemoteLocation { get; private set; }
        public SslPolicyErrors SslErrors { get; private set; }
        public CipherAlgorithmType SslAlgorithm { get; private set; }
        public HashAlgorithmType HashAlgorithm { get; private set; }
        public ExchangeAlgorithmType KeyExchangeAlgorithm { get; private set; }
        public SslProtocols SslProtocol { get; private set; }
        public TransportContext TransportContext { get; private set; }
        public int SslStrength { get; private set; }
        public int HashStrength { get; private set; }
        public int KeyExchangeStrength { get; private set; }
        public bool IsAuthenticated { get; private set; }
        public bool IsMutuallyAuthenticated { get; private set; }
        public bool IsEncrypted { get; private set; }
        public bool IsSigned { get; private set; }

        public TLS()
        {
        }

        private X509Certificate[] CloneChain(X509Chain C)
        {
            X509Certificate[] Ret = new X509Certificate[C.ChainElements.Count];
            for (var i = 0; i < C.ChainElements.Count; i++)
            {
                Ret[i] = C.ChainElements[i].Certificate.Clone();
            }
            return Ret;
        }

        public bool Connect(IPEndPoint Destination, string Hostname = "localhost", int ConnectTimeout = 4000, int AuthTimeout = 4000)
        {
            if (Error != null)
            {
                return false;
            }
            Socket S = new Socket(SocketType.Stream, ProtocolType.Tcp);
            Thread T = new Thread(() =>
            {
                try
                {
                    S.Connect(Destination);
                }
                catch (Exception ex)
                {
                    Error = ex;
                }
            });
            T.IsBackground = true;
            T.Start();
            if (!T.Join(ConnectTimeout) || Error != null)
            {
                T.Abort(false);
                Error = new TimeoutException($"Connecting: The operation timed out after {ConnectTimeout} ms");
                return false;
            }

            SslStream TLS = new SslStream(
                new NetworkStream(S, true),
                false,
                (a, b, c, d) => {
                    //We need to clone these as the stream will dispose them
                    ServerCertificate = new X509Certificate(b.Export(X509ContentType.Cert));
                    ServerChain = CloneChain(c);
                    SslErrors = d;
                    return true;
                },
                (a, b, c, d, e) => { return null; },
                EncryptionPolicy.AllowNoEncryption);

            T = new Thread(() =>
            {
                try
                {
                    TLS.AuthenticateAsClient(Hostname, null, SslProtocols.Default | SslProtocols.Tls11 | SslProtocols.Tls12, true);
                }
                catch (Exception ex)
                {
                    TLS.Dispose();
                    Error = ex;
                }
            });
            T.IsBackground = true;
            T.Start();
            if (!T.Join(AuthTimeout) || Error != null)
            {
                T.Abort(false);
                TLS.Dispose();
                Error = new TimeoutException($"Authenticating: The operation timed out after {AuthTimeout} ms");
                return false;
            }

            SslAlgorithm = TLS.CipherAlgorithm;
            SslStrength = TLS.CipherStrength;
            HashAlgorithm = TLS.HashAlgorithm;
            HashStrength = TLS.HashStrength;
            IsAuthenticated = TLS.IsAuthenticated;
            IsEncrypted = TLS.IsEncrypted;
            IsMutuallyAuthenticated = TLS.IsMutuallyAuthenticated;
            IsSigned = TLS.IsSigned;
            KeyExchangeAlgorithm = TLS.KeyExchangeAlgorithm;
            KeyExchangeStrength = TLS.KeyExchangeStrength;
            SslProtocol = TLS.SslProtocol;
            TransportContext = TLS.TransportContext;

            TLS.Close();
            TLS.Dispose();

            return true;
        }
    }
}
