using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace LoRaWAN
{
    public class ClientGateway
    {
        private TcpClient client;
        private SslStream sslStream;

        readonly string sslCertificate;
        readonly string sslPassword;


        /// <summary>
        /// Initializes a new instance of the Gateway class with SSL certificate and password.
        /// </summary>
        /// <param name="sslCertificate">The path to the SSL certificate file.</param>
        /// <param name="sslPassword">The password for the SSL certificate.</param>
        public ClientGateway(string sslCertificate, string sslPassword)
        {
            // Assign the provided SSL certificate path and password to the corresponding properties
            this.sslCertificate = sslCertificate;
            this.sslPassword = sslPassword;
        }


        /// <summary>
        /// Callback method to handle certificate validation for SSL/TLS connections.
        /// </summary>
        /// <param name="sender">The object that raised the event.</param>
        /// <param name="certificate">The certificate associated with the remote party.</param>
        /// <param name="chain">The chain of certificate authorities associated with the remote certificate.</param>
        /// <param name="sslPolicyErrors">The errors encountered when validating the remote certificate.</param>
        /// <returns>True to indicate that the all certificates are accepted without validation.</returns>
        static bool CertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // Accept all certificates without validation
            return true;
        }


        /// <summary>
        /// Connects to the server.
        /// </summary>
        /// <param name="ipAddress">The IP address of the server.</param>
        /// <param name="port">The port number to connect to on the server.</param>
        /// <returns>True if connection succeeds, otherwise false.</returns>
        private bool ConnectToServer(string ipAddress, int port)
        {
            try
            {
                // Create a new TcpClient instance to establish a connection
                client = new TcpClient();

                // Connect to the server using the specified IP address and port number
                client.Connect(ipAddress, port);

                // Get the network stream associated with the TcpClient for communication through Stream instance
                NetworkStream stream = client.GetStream();

                // Print a message indicating successful connection along with the server's endpoint
                Console.WriteLine("Connected to server " + client.Client.RemoteEndPoint);

                // Wrap the stream with SSL/TLS encryption
                sslStream = new SslStream(stream, false, new RemoteCertificateValidationCallback(CertificateValidationCallback));

                // Authenticate as client using SSL/TLS with the provided certificate and password
                sslStream.AuthenticateAsClient(ipAddress, new X509Certificate2Collection(new X509Certificate2(sslCertificate, sslPassword)), SslProtocols.Tls, true);

                // Print message indicating successful SSL/TLS handshake
                Console.WriteLine("SSL/TLS handshake completed.");

                // Return true to indicate successful connection
                return true;
            }
            catch (Exception ex)
            {
                // Print an error message if connection attempt fails and return false
                Console.WriteLine("Error connecting to server: " + ex.Message);
                Console.ReadKey();
                return false;
            }
        }


        /// <summary>
        /// Sends a message to the server.
        /// </summary>
        /// <param name="message">The message to send.</param>
        /// <returns>True if message sent successfully, otherwise false.</returns>
        private bool SendMessage(string message)
        {
            try
            {
                // Convert the message string into a byte array using ASCII encoding
                byte[] buffer = Encoding.UTF8.GetBytes(message);

                // Write the byte array (message) to the network stream
                sslStream.Write(buffer);

                // Sent the byte array (message) to server
                sslStream.Flush();

                // Print a message indicating successful sending of the message
                Console.WriteLine("Sent message: " + message);

                // Return true to indicate successful message transmission
                return true;
            }
            catch (Exception ex)
            {
                // Print an error message if sending the message fails and return false
                Console.WriteLine("Error sending message: " + ex.Message);

                return false;
            }
        }


        /// <summary>
        /// Receives a response from the server.
        /// </summary>
        /// <returns>The received response as a string.</returns>
        private string ReceiveResponse()
        {
            try
            {
                // Create a byte array to store received data
                byte[] buffer = new byte[2048];

                // Initialize a StringBuilder to construct the received message
                StringBuilder messageData = new StringBuilder();

                int bytesRead = -1;

                do
                {
                    // Read data from the network stream and store the number of bytes read
                    bytesRead = sslStream.Read(buffer, 0, buffer.Length);

                    // Create a UTF-8 decoder
                    Decoder decoder = Encoding.UTF8.GetDecoder();

                    // Decode bytes to characters
                    char[] chars = new char[decoder.GetCharCount(buffer, 0, bytesRead)];
                    decoder.GetChars(buffer, 0, bytesRead, chars, 0);

                    // Append decoded characters to the messageData StringBuilder
                    messageData.Append(chars);

                    // Check for end-of-file indicator
                    if (messageData.ToString().IndexOf("<EOF>") != -1)
                    {
                        // Exit loop if end-of-file indicator is found
                        break;
                    }
                } while (bytesRead != 0); // Continue looping until no more data is read

                // Print received response
                Console.WriteLine("Received response: " + messageData.ToString());

                // Return received response
                return messageData.ToString();
            }
            catch (Exception ex)
            {
                // Print an error message if receiving the response fails and return null
                Console.WriteLine("Error receiving response: " + ex.Message);

                return null;
            }
        }


        /// <summary>
        /// Disconnects from the server.
        /// </summary>
        private void DisconnectFromServer()
        {
            try
            {
                // Close the network stream
                sslStream.Close();

                // Close the TcpClient
                client.Close();

                // Print a message indicating successful disconnection
                Console.WriteLine("Disconnected from server.");
            }
            catch (Exception ex)
            {
                // Print an error message if disconnection fails
                Console.WriteLine("Error disconnecting from server: " + ex.Message);
            }
        }


        /// <summary>
        /// Connects to the server, sends a message, receives a response, and then disconnects.
        /// </summary>
        /// <param name="ipAddress">The IP address of the server.</param>
        /// <param name="port">The port number to connect to on the server.</param>
        /// <param name="message">The message to send to the server.</param>
        /// <returns>True if message sent successfully.</returns>
        public bool SendFramesToServer(string ipAddress, int port, string message)
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();

            while (stopwatch.ElapsedMilliseconds < 5000)
            {
                // Connect to the server
                if (this.ConnectToServer(ipAddress, port))
                {
                    // Send the message to the server
                    if (this.SendMessage(message))
                    {
                        // Receive the response from the server
                        _ = this.ReceiveResponse();
                    }

                    // Disconnect from the server
                    DisconnectFromServer();

                    return true;
                }
            }

            stopwatch.Stop();

            Console.WriteLine("\t- Gateway could not Established a Connection with Server!\nConnection Timeout!");
            return false;
        }
    }
}
