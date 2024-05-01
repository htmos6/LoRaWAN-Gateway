using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace LoRaWAN_Gateway
{
    public class ServerGateway : IDisposable
    {
        void IDisposable.Dispose()
        {

        }

        private TcpListener server;
        private TcpClient client;
        private SslStream sslStream;

        private IPAddress ip;
        private X509Certificate2 sslCertificate = null;

        private AesCryptographyService aes256 = new AesCryptographyService();

        bool serverStarted = false;

        byte[] key = new byte[16] { 0x69, 0x93, 0xAB, 0x4F, 0x2A, 0xC1, 0x0F, 0x2D, 0x3A, 0x5B, 0x21, 0x8C, 0x4E, 0x97, 0xE9, 0x6C };
        byte[] iv = new byte[16] { 0x8A, 0x57, 0x6F, 0x0C, 0x45, 0x83, 0x28, 0xE0, 0x9E, 0x41, 0x23, 0x14, 0x36, 0xD7, 0xB7, 0x55 };


        /// <summary>
        /// Starts the server on the specified IP address and port.
        /// </summary>
        /// <param name="ipAddress">The IP address to listen on.</param>
        /// <param name="port">The port number to listen on.</param>
        /// <returns>True if the server started successfully, otherwise false.</returns>
        private bool Start(string ipAddress, int port)
        {
            try
            {
                // Print session information
                Console.WriteLine("\n\n\n************ Gateway (Server) Session ************\n\n");

                // Parse the IP address
                ip = IPAddress.Parse(ipAddress);

                // Create a new TcpListener instance bound to the specified IP address and port
                server = new TcpListener(ip, port);

                // Start listening for incoming connections
                server.Start();

                // Output server's local endpoint
                Console.WriteLine("Server started on " + server.LocalEndpoint);

                // Return true indicating successful server start
                return true;
            }
            catch (SocketException ex)
            {
                // Output specific error message for socket exception
                Console.WriteLine($"Error starting server: {ex.SocketErrorCode}");

                // Return false indicating failure to start the server
                return false;
            }
            catch (Exception ex)
            {
                // Output general error message for other exceptions
                Console.WriteLine("Error starting server: " + ex.Message);

                // Return false indicating failure to start the server
                return false;
            }
        }


        /// <summary>
        /// Listens for incoming client connections. If connection found, establish a connection.
        /// </summary>
        /// <returns>A TcpClient representing the accepted client connection, or null if an error occurs.</returns>
        private bool ListenThenConnectToClient()
        {
            try
            {
                // Output a message indicating waiting for a connection
                Console.WriteLine("Waiting for a connection...");

                // Accept a pending connection request
                client = server.AcceptTcpClient();

                // Return the TcpClient representing the connected client
                return true;
            }
            catch (Exception ex)
            {
                // Output an error message if an exception occurs during accepting the connection
                Console.WriteLine("Error accepting client connection: " + ex.Message);

                // Return null to indicate an error occurred while accepting the connection
                return false;
            }
        }


        /// <summary>
        /// Receives a message from the connected client.
        /// </summary>
        /// <returns>The received message as a string, or null if an error occurs.</returns>
        private string ReceiveMessage()
        {
            try
            {
                // Indicate a EndPoint of the connected client.
                Console.WriteLine("Connected to client " + ((IPEndPoint)client.Client.RemoteEndPoint).ToString());

                // Get the network stream to generate ssl stream to read messages from client
                NetworkStream stream = client.GetStream();

                //Wrap client in SSLstream
                sslStream = new SslStream(stream, false);

                //Read self-signed certificate
                sslCertificate = new X509Certificate2(@"C:\Users\Legion\projects\LoRaWAN-Server\LoRaWAN.pfx", "sTrongPassW1");

                //Authenticate server with self-signed certificate, false (for not requiring client authentication), SSL protocol type, ...
                sslStream.AuthenticateAsServer(sslCertificate, false, System.Security.Authentication.SslProtocols.Default, false);

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

                Console.WriteLine("\n\nReceived encrypted message: " + messageData.ToString());

                string encryptedMessage = messageData.ToString().Replace("<EOF>", "");
                byte[] bytes = Hex2Str(encryptedMessage);
                
                var message = Encoding.ASCII.GetString(aes256.Decrypt(bytes, key, iv));

                Console.WriteLine($"Received encrypted message : {Encoding.ASCII.GetString(bytes)}");
                Console.WriteLine("Received decrypted message: " + message + "\n");

                // Return received response
                return messageData.ToString();
            }
            catch (Exception ex)
            {
                // Output an error message if an exception occurs during message receiving
                Console.WriteLine("Error receiving message: " + ex.Message);

                // Return null to indicate an error occurred while receiving the message
                return null;
            }
        }


        /// <summary>
        /// Sends a response message to the connected client.
        /// </summary>
        /// <param name="message">The message to send as a response.</param>
        /// <returns>True if the response was successfully sent, otherwise false.</returns>
        private bool SendResponse(string message)
        {
            try
            {
                // Create the response message to send to the client
                string response = message;

                // Convert the response message to a byte array
                byte[] responseBuffer = Encoding.UTF8.GetBytes(response);

                // Write the response message to the ssl stream
                sslStream.Write(responseBuffer);

                // Output a message indicating that the response was sent
                Console.WriteLine("\nResponse sent : " + response);

                // Return true to indicate that the response was successfully sent
                return true;
            }
            catch (Exception ex)
            {
                // Output an error message if an exception occurs during response sending
                Console.WriteLine("Error sending response: " + ex.Message);

                // Return false to indicate that an error occurred while sending the response
                return false;
            }
        }


        /// <summary>
        /// Stops the server.
        /// </summary>
        private bool DisconnectFromClient()
        {
            try
            {
                string clientIpEndPoint = ((IPEndPoint)client.Client.RemoteEndPoint).ToString();

                // Close the client connection after sending the response
                client.Close();

                // Close the ssl stream
                sslStream.Close();

                // Output a message indicating that the server has stopped
                Console.WriteLine("\nDisconnected from client " + clientIpEndPoint);
                Console.WriteLine("\n\n************ Gateway (Server) Session Ends ************\n\n\n");

                // Return true indicating successful server stop
                return true;
            }
            catch (Exception ex)
            {
                // Output an error message if an exception occurs during server stop
                Console.WriteLine("Error stopping server: " + ex.Message);

                // Return false if an exception occurs during server stop
                return false;
            }

        }


        /// <summary>
        /// Starts the server and responds back to connected clients.
        /// </summary>
        /// <param name="ipAddress">The IP address to listen on.</param>
        /// <param name="port">The port number to listen on.</param>
        /// <returns>The received message from the connected client.</returns>
        public string Run(string ipAddress, int port)
        {
            // Start the server if not already started
            if (serverStarted == false)
            {
                if (this.Start(ipAddress, port) == false)
                {
                    // Stop the server if failed to start
                    server.Stop();
                }  
                else
                {
                    serverStarted = true;
                }
            }
            
            if (serverStarted == true)
            {
                // If the server is started, continuously listen for and respond to client connections
                while (serverStarted)
                {
                    // Listen for a client connection and connect to it
                    if (this.ListenThenConnectToClient())
                    {
                        // Receive a message from the connected client
                        string message = this.ReceiveMessage();

                        // If a message is received successfully, send a response back to the client
                        if (message != null)
                        {
                            this.SendResponse(message);
                        }

                        // Disconnect from the client
                        this.DisconnectFromClient();

                        return message;
                    }
                }
            }

            return null;
        }


        /// <summary>
        /// Converts a hexadecimal string to a byte array.
        /// </summary>
        /// <param name="hexString">The hexadecimal string to convert.</param>
        /// <returns>The byte array representing the hexadecimal string.</returns>
        private byte[] Hex2Str(string hexString)
        {
            // Split the hexadecimal string by '-' delimiter
            string[] hexValuesSplit = hexString.Split('-');

            // Create a byte array to store the parsed hexadecimal values
            byte[] bytes = new byte[hexValuesSplit.Length];

            // Parse each hexadecimal string and store it in the byte array
            for (int i = 0; i < hexValuesSplit.Length; i++)
            {
                bytes[i] = byte.Parse(hexValuesSplit[i], System.Globalization.NumberStyles.HexNumber);
            }

            return bytes;
        }
    }
}
