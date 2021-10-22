using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SampleServerClient
{
    class Client
    {
        static void Main(string[] args)
        {
            bool done = false;
            int listenPort = 55600;
            using (UdpClient listener = new UdpClient(listenPort))
            {
                IPEndPoint listenEndPoint = new IPEndPoint(IPAddress.Any, listenPort);
                while (!done)
                {
                    byte[] receivedData = listener.Receive(ref listenEndPoint);
                    string decodedData = Encoding.ASCII.GetString(receivedData);

                    Console.WriteLine("Received broadcast message from client {0}", listenEndPoint.ToString());

                    Console.WriteLine("Decoded data is:");
                    Console.WriteLine(decodedData);

                    if (decodedData.ToLower().Contains("done"))
                    {
                        done = true;
                        receivedData = Encoding.ASCII.GetBytes("Closing socket: received payload containing done");
                    }

                    //now we reply

                    listener.Send(receivedData, receivedData.Length, listenEndPoint);
                    Console.Write("Sent response to: {0}", listenEndPoint.ToString());
                }
            }
        }
    }
}
