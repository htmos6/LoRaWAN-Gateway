using LoRaWAN;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LoRaWAN_Gateway
{
    public class Program
    {
        static void Main(string[] args)
        {
            string sslCertificate = "C:\\Users\\Legion\\projects\\LoRaWAN-Server\\LoRaWAN.pfx";
            string sslPassword = "sTrongPassW1";

            ClientGateway clientGateway = new ClientGateway(sslCertificate, sslPassword);
            ServerGateway serverGateway = new ServerGateway();

            while (true)
            {
                string message = serverGateway.Run("127.0.0.1", 123);

                if (message != null)
                {
                    clientGateway.SendFramesToServer("127.0.0.1", 8082, message);
                }
            }
        }
    }
}
