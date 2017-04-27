using System;
using System.Linq;

namespace TLSReport
{
    class Program
    {
        static void Main(string[] args)
        {
#if DEBUG
            args = new string[] { "127.0.0.1:443" };
#endif
            TLS T = new TLS();
            var EP = args.First().ToEndpoint();
            if (EP != null)
            {
                if (T.Connect(EP, "localhost", 5000, 10000))
                {
                }
                else
                {
                    Console.Error.WriteLine(T.Error);
                }
            }
            else
            {
                Console.Error.WriteLine("Invalid command line argument");
            }
        }
    }
}
