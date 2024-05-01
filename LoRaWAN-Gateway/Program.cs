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

            //ClientGateway clientGateway = new ClientGateway(sslCertificate, sslPassword);
            //clientGateway.SendFramesToServer("127.0.0.1", 8082, "Hello, LoRaWAN Community!<EOF>");

            ServerGateway serverGateway = new ServerGateway();
            serverGateway.Run("127.0.0.1", 123);
        }
    }
}
