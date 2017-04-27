using System;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace TLSReport
{
    public static class Extensions
    {
        public static X509Certificate Clone(this X509Certificate Cert)
        {
            return new X509Certificate(Cert.Export(X509ContentType.Cert));
        }

        public static IPEndPoint ToEndpoint(this string Source)
        {
            if (!Source.Contains(':'))
            {
                return null;
            }
            int Port = 0;
            string IP = Source.Substring(0, Source.LastIndexOf(':'));
            if (int.TryParse(Source.Split(':').Last(), out Port) && Port > ushort.MinValue && Port < ushort.MaxValue)
            {
                IPAddress Temp = IPAddress.Any;
                if (IPAddress.TryParse(IP, out Temp) && Temp!=IPAddress.Any && Temp!=IPAddress.IPv6Any)
                {
                    return new IPEndPoint(Temp, Port);
                }
            }
            return null;
        }

        public static void Abort(this Thread T, bool RaiseException)
        {
            try
            {
                if (T.IsAlive)
                {
                    T.Abort();
                }
            }
            catch (Exception ex)
            {
                if (RaiseException)
                {
                    throw;
                }
            }
        }
    }
}
