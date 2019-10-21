using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Timers;

namespace AdminShareClient
{
    class Client
    {
        static int encryptCounter = 0;
        static int decryptCounter = 0;

        static void Main(string[] args)
        {
            int num;
            string serverIP;
            int serverPort;
            int bytesRcvd = 0;
            byte[] byteArray = new byte[1024];
            byte[] byteArrayReceive = new byte[1024];
            byte[] exitBuffer = Encoding.ASCII.GetBytes("exit");
            byte[] exitLength = new byte[64];
            byte[] encryptedExit;
            Array.Copy(exitBuffer, byteArray, exitBuffer.Length);
            string sendString;
            Timer sessionTimer = new Timer();
            bool ipFlag;
            IPAddress IP;

            try
            {
                Console.Write("Enter Server IP Address:");
                serverIP = Console.ReadLine();
                ipFlag = IPAddress.TryParse(serverIP, out IP);
                if (!ipFlag)
                {
                    Console.WriteLine("Invalid IP address provided.");
                    return;
                }
                Console.Write("Enter Server Port:");
                try
                {
                    serverPort = Convert.ToInt32(Console.ReadLine());
                }
                catch (OverflowException)
                {
                    Console.WriteLine("Input is outside the range of a valid port number.");
                    return;
                }
                catch (FormatException)
                {
                    Console.WriteLine("Input is not a valid numerical port.");
                    return;
                }

                TcpClient client = new TcpClient(serverIP, serverPort);
                Console.WriteLine("Successful TCP Connection!");
                NetworkStream netStream = client.GetStream();
                //Handle Server Password
                initiateServerProtocol(netStream);
                //Setup Timeouts
                initTimer(sessionTimer, netStream, client);
                if ((bytesRcvd = netStream.Read(byteArrayReceive, 0, 64)) == 0)
                {
                    Console.WriteLine("Connection died early");
                    return;
                }
                num = decryptStatus(byteArrayReceive, decryptCounter++);
                ListFiles(num, netStream);
                while (true)
                {
                    //Main Command Loop
                    Console.Write("Command:");
                    Array.Clear(byteArray, 0, byteArray.Length);
                    sendString = Console.ReadLine();
                    sessionTimer.Stop();
                    if (sendString.Equals("exit", StringComparison.OrdinalIgnoreCase))
                    {
                        Array.Copy(exitBuffer, byteArray, exitBuffer.Length);
                        break;
                    }
                    else
                    {
                        if (!sendString.Contains(" ")){
                            Console.WriteLine("Invalid command provided.");
                        }
                        else if (System.Text.ASCIIEncoding.ASCII.GetByteCount(sendString) > 1024)
                        {
                            Console.WriteLine("Error: Oversized path");
                        }
                        else if (sendString.Substring(0, sendString.IndexOf(" ")).Equals("get", StringComparison.OrdinalIgnoreCase))
                        {
                            if (initRequest(sendString, netStream, false))
                            {
                                GetFile(sendString, netStream);
                                Console.WriteLine("Get Request Complete!");
                            }
                            else
                            {
                                Console.WriteLine("Failed Request");
                            }

                        }
                        else if (sendString.Substring(0, sendString.IndexOf(" ")).Equals("send", StringComparison.OrdinalIgnoreCase))
                        {
                            if (initRequest(sendString, netStream, false))
                            {
                                SendFile(sendString, netStream);
                                Console.WriteLine("Send Request Complete!");
                            }
                            else
                            {
                                Console.WriteLine("Failed Request");
                            }

                        }
                        else if (sendString.Substring(0, sendString.IndexOf(" ")).Equals("use", StringComparison.OrdinalIgnoreCase))
                        {
                            if (initRequest(sendString, netStream, false))
                            {
                                useDirectory(sendString, netStream);
                                Console.WriteLine("Use Request Completed!");
                            }
                            else
                            {
                                Console.WriteLine("Failed Request");
                            }
                        }
                        else if (sendString.Substring(0, sendString.IndexOf(" ")).Equals("del", StringComparison.OrdinalIgnoreCase))
                        {
                            if (initRequest(sendString, netStream, false))
                            {
                                deleteFile(sendString, netStream);
                                Console.WriteLine("Delete Reqeust Completed!");
                            }
                            else
                            {
                                Console.WriteLine("Failed Request");
                            }
                        }
                        else
                        {
                            Console.WriteLine("Invalid Command");
                        }
                        sessionTimer.Start();
                    }
                }
                Console.WriteLine("Exiting...");
                exitLength = encryptSize(sendString.Length, encryptCounter++);
                netStream.Write(exitLength, 0, 64);
                encryptedExit = encryptData(Encoding.ASCII.GetBytes(sendString), encryptCounter++);
                netStream.Write(encryptedExit, 0, 1024);
                netStream.Close();
                client.Close();
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine("ArgumentNullException: {0}", e);
            }
            catch (SocketException e)
            {
                Console.WriteLine("SocketException: {0}", e);
            }
        }

        /*
         * Handle the initial server authentication 
         */
        static void initiateServerProtocol(NetworkStream netStream)
        {
            int bytesRcvd = 0;
            byte[] byteArrayReceive = new byte[1024];
            int maxAttempts = 0;
            byte[] sendBytes = new byte[1024];
            int code;
            string pass = "";
            byte[] byteArray;
            byte[] tempByteArray;

            if ((bytesRcvd = netStream.Read(byteArrayReceive, 0, 64)) == 0)
            {
                Console.WriteLine("Connection died early");
            }
            maxAttempts = decryptStatus(byteArrayReceive, decryptCounter++);

            while (true)
            {
                if(maxAttempts == -2)
                {
                    Console.WriteLine("Blocked from the server for failing authentication too many times.");
                    Environment.Exit(0);
                }
                if(maxAttempts == -3)
                {
                    Console.WriteLine("Blocked by the server.");
                    Environment.Exit(0);
                }
                if (maxAttempts > 0)
                {
                    Console.WriteLine("Max Attempts:{0}", maxAttempts);
                    Console.Write("Enter Server Password({0} Attempts remaining):", maxAttempts);
                    maxAttempts--;
                }
                else
                {
                    //Handle if server specified infinite tries
                    Console.WriteLine("Enter Server Password:");
                }
                pass = Console.ReadLine();
                netStream.Write(encryptSize(pass.Length, encryptCounter++), 0, 64);
                Array.Clear(sendBytes, 0, sendBytes.Length);
                tempByteArray = Encoding.UTF8.GetBytes(pass);
                byteArray = encryptData(tempByteArray, encryptCounter++);
                Array.Copy(byteArray, sendBytes, byteArray.Length);
                netStream.Write(sendBytes, 0, sendBytes.Length);

                Array.Clear(byteArrayReceive, 0, byteArrayReceive.Length);

                if ((bytesRcvd = netStream.Read(byteArrayReceive, 0, 64)) == 0)
                {
                    Console.WriteLine("Connection died early");
                }
                code = decryptStatus(byteArrayReceive, decryptCounter++);
                if (code == 1)
                {
                    Console.WriteLine("Password Accepted");
                    break;
                }
                Console.WriteLine("Password Incorrect");
                if (maxAttempts == 0)
                {
                    Console.WriteLine("Out of attempts. Disconnecting...");
                    netStream.Close();
                    Environment.Exit(0);
                }
            }
        }

        /*Receives and displays the total number of files and their names as well as the file type
         [D] - Directory
         [F] - File
        */
        static void ListFiles(int num, NetworkStream netStream)
        {
            int totalRcvd = 0;
            int bytesRcvd = 0;
            int length;
            string line;
            byte[] overflow = new byte[1024];
            byte[] ciphertext = new byte[1024];
            byte[] byteArrayReceive = new byte[1024];
            for (int i = 0; i < num; i++)
            {
                totalRcvd = 0;
                Array.Clear(byteArrayReceive, 0, byteArrayReceive.Length);
                Array.Clear(ciphertext, 0, ciphertext.Length);
                length = getStringLength(netStream, decryptCounter);
                decryptCounter++;
                //SLEEP ON SERVER SIDE BECAUSE IT IS TOO FAST
                while ((bytesRcvd = netStream.Read(byteArrayReceive, 0, 1024)) > 0)
                {
                    
                    if ((bytesRcvd + totalRcvd) > 1024)
                    {
                        Array.Copy(byteArrayReceive, 0, ciphertext, totalRcvd, (1024 - totalRcvd));
                        Array.Copy(byteArrayReceive, (1024 - totalRcvd), overflow, 0, (bytesRcvd - (1024 - totalRcvd)));
                    }
                    else
                    {
                        Array.Copy(byteArrayReceive, 0, ciphertext, totalRcvd, bytesRcvd);
                    }

                    totalRcvd += bytesRcvd;
                    if (totalRcvd >= 1024)
                    {
                        line = Encoding.UTF8.GetString(decryptData(ciphertext, decryptCounter++));
                        if (line[0] == 'd')
                        {
                            line = line.Substring(1, length - 1);
                            Console.WriteLine("{1}----[D] {0}", line, i);
                        }
                        else
                        {
                            line = line.Substring(1, length - 1);
                            Console.WriteLine("{1}----[F] {0}", line, i);
                        }
                        break;
                    }

                }
            }
        }

        /*
         * GET file request
         * Attempts to receive a specified file from the server
         */
        static void GetFile(string sendString, NetworkStream stream)
        {
            byte[] byteArray = new byte[1024];
            int bytesRcvd = 0;
            byte[] byteArrayReceive = new byte[1024];
            byte[] sendBytes = Encoding.ASCII.GetBytes(sendString);
            string fileName = "";
            int bytes_to_read = 1024;
            int statusCode = -1;
            long total_bytes = 5;

            fileName = sendString.Split('/').Last();
            if (fileName.Equals(sendString))
            {
                fileName = sendString.Split(' ').Last();
            }

            while ((bytesRcvd = stream.Read(byteArrayReceive, 0, 64)) > 0)
            {
                statusCode = decryptStatus(byteArrayReceive, decryptCounter++);
                if (statusCode == 1)
                {
                    break;
                }
                else if (statusCode == 2)
                {
                    Console.WriteLine("ERROR:File unaccessible on server side.");
                    return;
                }
            }
            Array.Clear(byteArrayReceive, 0, byteArrayReceive.Length);
            if ((bytesRcvd = stream.Read(byteArrayReceive, 0, 64)) == 0)
            {
                Console.WriteLine("Connection Died early");
            }
            total_bytes = decryptStatus(byteArrayReceive, decryptCounter++);
            Console.WriteLine("Bytes to Receive: {0}", total_bytes);
            if (total_bytes < 1024)
            {
                bytes_to_read = (int)total_bytes;
            }
            Array.Clear(byteArrayReceive, 0, byteArrayReceive.Length);
            try
            {
                using (var fs = new FileStream(fileName, FileMode.Create, FileAccess.Write))
                {
                    while ((bytesRcvd = stream.Read(byteArrayReceive, 0, 1024)) > 0)
                    {
                        fs.Write(decryptData(byteArrayReceive, decryptCounter++), 0, bytes_to_read);
                        Array.Clear(byteArrayReceive, 0, byteArrayReceive.Length);
                        total_bytes -= bytes_to_read;
                        Console.WriteLine("Bytes to read: {1} Total Bytes left: {0}", total_bytes, bytes_to_read);
                        if (total_bytes <= 1024)
                        {
                            bytes_to_read = (int)total_bytes;
                        }
                        if (total_bytes == 0)
                        {
                            break;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception caught writing to file: {0}", e);
                return;
            }
        }

        /*
         * SEND file request
         * Send a file to the server
         * Requires that the user is using a directory before sending
         */
        static void SendFile(string sendString, NetworkStream stream)
        {
            byte[] byteArray = new byte[1024];
            byte[] encryptedSize = new byte[64];
            byte[] encryptedData = new byte[1024];
            byte[] byteArrayReceive = new byte[1024];
            byte[] byteArraySend = new byte[1024];
            byte[] sendBytes = Encoding.ASCII.GetBytes(sendString);
            string filepath = "";
            int bytesRead = 0;
            int elements = 0;
            FileAttributes attr;

            filepath = sendString.Split(' ').Last();

            string fullPath = Directory.GetCurrentDirectory() + "\\" + filepath;
            attr = File.GetAttributes(fullPath);
            if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
            {
                Console.WriteLine("ERROR: Attempting to SEND a directory instead of file.");
                stream.Write(encryptSize(-1, encryptCounter++), 0, 64);
                return;
            }

            //See if file exists first
            if (!File.Exists(filepath))
            {
                Console.WriteLine("File specified does not exist or invalid permissions to file");
                stream.Write(encryptSize(-1, encryptCounter++), 0, 64);
                return;
            }
            

            long length = new System.IO.FileInfo(filepath).Length;

            encryptedSize = encryptSize((int)length, encryptCounter++);

            stream.Write(encryptedSize, 0, 64);
            Array.Clear(byteArray, 0, byteArray.Length);


            using (var fs = File.OpenRead(filepath))
            {
                byte[] overflowBuffer = new byte[1024];
                /*reads RANDOM NUMBER of bytes for whatever reason up to a max of 1024*/
                while ((bytesRead = fs.Read(byteArray, 0, byteArray.Length)) > 0)
                {
                    length -= bytesRead;

                    if (length == 0)
                    {
                        encryptedData = encryptData(byteArray, encryptCounter++);
                        Console.WriteLine("Sending Last Data: {0}", Encoding.Default.GetString(byteArraySend));
                        stream.Write(encryptedData, 0, 1024);
                    }
                    else if ((bytesRead + elements) > 1024)
                    {
                        Array.Copy(byteArray, 0, byteArraySend, elements, (1024 - elements));
                        encryptedData = encryptData(byteArraySend, encryptCounter++);
                        stream.Write(encryptedData, 0, 1024);
                        Array.Clear(byteArraySend, 0, byteArraySend.Length);
                        Array.Clear(encryptedData, 0, encryptedData.Length);
                        Array.Copy(byteArray, (elements + bytesRead - 1024), byteArraySend, 0, (bytesRead + 1024 - elements));
                        elements = 0;
                    }
                    else if ((bytesRead + elements) == 1024)
                    {
                        byteArray.CopyTo(byteArraySend, elements);
                        encryptedData = encryptData(byteArraySend, encryptCounter++);
                        stream.Write(encryptedData, 0, 1024);
                        elements = 0;
                        Array.Clear(byteArray, 0, byteArray.Length);
                        Array.Clear(byteArraySend, 0, byteArraySend.Length);
                        Array.Clear(encryptedData, 0, encryptedData.Length);
                    }
                    else
                    {
                        byteArray.CopyTo(byteArraySend, elements);
                        elements += bytesRead;
                        Array.Clear(byteArray, 0, byteArray.Length);
                    }
                }

            }
        }

        /*
         * DELETE file request
         * Attempts to delete a file off of the server
         */
        static void deleteFile(string sendString, NetworkStream stream)
        {
            byte[] byteArray = new byte[1024];
            int bytesRcvd = 0;
            byte[] byteArrayReceive = new byte[1024];
            byte[] byteArraySend = new byte[1024];
            byte[] sendBytes = Encoding.ASCII.GetBytes(sendString);
            int statusCode = -1;


            //Get Server Response
            while ((bytesRcvd = stream.Read(byteArrayReceive, 0, 64)) > 0)
            {
                statusCode = decryptStatus(byteArrayReceive, decryptCounter++);
                if (statusCode == 1) // OK
                {
                    break;
                }
                else if (statusCode == 2)
                {
                    Console.WriteLine("Error deleting file.");
                    return;
                }else if(statusCode == 3)
                {
                    Console.WriteLine("You do not have sufficient privliges to delete this file.");
                    return;
                }
            }

            Console.WriteLine("File successfully deleted.");

        }

        /*
         * USE directory request
         * Attempts to read the contents of a directory listed by the server
         * Any future actions (GET/SEND/DELETE) will be processed in accordance to files in the directory that is being USE'd
         * To go back directories, USE the ".." directory
         */
        static void useDirectory(string sendString, NetworkStream stream)
        {
            byte[] byteArray = new byte[1024];
            int bytesRcvd = 0;
            byte[] byteArrayReceive = new byte[1024];
            byte[] sendBytes = Encoding.ASCII.GetBytes(sendString);
            int statusCode = -1;
            string directoryName;
            int totalFiles = 0;

            directoryName = sendString.Split(' ').Last();
            
            while ((bytesRcvd = stream.Read(byteArrayReceive, 0, 64)) > 0)
            {
                statusCode = decryptStatus(byteArrayReceive, decryptCounter++);
                if (statusCode == 1) // OK
                {
                    break;
                }
                else if (statusCode == 2) // Error
                {
                    Console.WriteLine("Error sent from server");
                    return;
                }
            }



            Array.Clear(byteArrayReceive, 0, byteArrayReceive.Length);
            while ((bytesRcvd = stream.Read(byteArrayReceive, 0, 64)) > 0)
            {
                totalFiles = decryptStatus(byteArrayReceive, decryptCounter++);
                if (totalFiles > 0)
                {
                    Console.WriteLine("Total Files: {0}", totalFiles);
                    break;
                }
            }

            Console.WriteLine("Listings for {0}:", directoryName);
            ListFiles(totalFiles, stream);
        }

        /* Initiates any requests sent from our client to the server
         * Handles any password protected files/directories
         * Status Codes:
         *  1 - OK
         *  2 - Password Required
         *  3 - Password OK
         *  -2 - Invalid priveleges
         *  -1 - ERROR
         */
        static bool initRequest(string sendString, NetworkStream stream, bool recursive)
        {
            int bytesRcvd = 0;
            byte[] byteArrayReceive = new byte[64];
            byte[] byteArray;
            byte[] encryptedBytes;
            byte[] sendArray = new byte[1024];
            byte[] sendBytes = Encoding.ASCII.GetBytes(sendString);
            int statusCode = 0;
            byte[] encryptedLength;
            byte[] lengthSender = new byte[64];


            if (!recursive)
            {
                //Send str length first
                encryptedLength = encryptSize(sendString.Length, encryptCounter++);
                Array.Copy(encryptedLength, lengthSender, encryptedLength.Length);
                stream.Write(lengthSender, 0, lengthSender.Length);
                Array.Clear(lengthSender, 0, lengthSender.Length);

                encryptedBytes = encryptData(sendBytes, encryptCounter++);
                Array.Copy(encryptedBytes, sendArray, encryptedBytes.Length);
                stream.Write(sendArray, 0, sendArray.Length);
                Array.Clear(sendBytes, 0, sendBytes.Length);
            }
            //Get Server Response to see if we are OK to send
            if ((bytesRcvd = stream.Read(byteArrayReceive, 0, 64)) == 0)
            {
                Console.WriteLine("Connection Died early");
            }
            statusCode = decryptStatus(byteArrayReceive, decryptCounter++);
            if (statusCode == 1) // OK
            {
                return true;
            }
            else if (statusCode == 2) // Error
            {
                Console.Write("Password:");
                Array.Clear(sendArray, 0, sendArray.Length);
                sendString = Console.ReadLine();
                encryptedLength = encryptSize(sendString.Length, encryptCounter++);
                Array.Copy(encryptedLength, lengthSender, encryptedLength.Length);
                stream.Write(lengthSender, 0, lengthSender.Length);
                Array.Clear(lengthSender, 0, lengthSender.Length);

                byteArray = encryptData(Encoding.UTF8.GetBytes(sendString), encryptCounter++);
                Array.Copy(byteArray, sendArray, byteArray.Length);
                stream.Write(sendArray, 0, sendArray.Length);
                return initRequest(sendString, stream, true);
            }
            else if (statusCode == 3)
            {
                Console.WriteLine("Password Accepted");
                return true;
            }
            else if (statusCode == -1)
            {
                Console.WriteLine("Error, access denied");
                return false;
            }
            else if(statusCode == -2)
            {
                Console.WriteLine("Invalid privliges");
                return false;
            }
            return false;
        }

        /*
         * Initiates a client-sided timeout for requests
         * If no requests are attempted in the server-specified timeout period, the client will exit
         */
        static void initTimer(Timer t, NetworkStream stream, TcpClient client)
        {
            byte[] byteArrayReceive = new byte[1024];
            int bytesRcvd = 0;
            string timeout;
            int res;

            while ((bytesRcvd = stream.Read(byteArrayReceive, 0, 1024)) > 0)
            {
                timeout = Encoding.ASCII.GetString(decryptData(byteArrayReceive, decryptCounter++)).Substring(0, 8);
                if (timeout != "-1" && !(Int32.TryParse(timeout, out res)))
                {
                    try
                    {
                        Console.WriteLine("Timeout: {0}", timeout);
                        TimeSpan span = TimeSpan.ParseExact(timeout, "g", CultureInfo.CurrentCulture, TimeSpanStyles.AssumeNegative);
                        t.Interval = span.TotalMilliseconds;
                        t.Elapsed += (source, e) => onTimedEvent(source, e, stream, client);
                        t.AutoReset = false;
                        t.Start();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Error in server provided timeout variable.");
                        return;
                    }

                }
                else
                {
                    Console.WriteLine("No timeouts set by server.");
                }
                return;
            }
        }

        /*
         * Function called by our timer when a timeout occurs
         * Closes connection with the server and exits
         */
        private static void onTimedEvent(object source, ElapsedEventArgs e, NetworkStream stream, TcpClient client)
        {
            byte[] exitBuffer = Encoding.ASCII.GetBytes("exit");
            byte[] byteArray = new byte[1024];
            byte[] encryptedArray = new byte[1024];
            byte[] encryptedLength = new byte[64];

            Console.WriteLine("Session Timeout. Exiting...");
            encryptedLength = encryptSize(4, encryptCounter++);
            stream.Write(encryptedLength, 0, 64);
            Array.Copy(exitBuffer, byteArray, exitBuffer.Length);
            encryptedArray = encryptData(byteArray, encryptCounter++);
            stream.Write(encryptedArray, 0, encryptedArray.Length);
            stream.Close();
            client.Close();
            Environment.Exit(0);
        }

        //Decrypts lengths of a string and returns it
        private static int getStringLength(NetworkStream netStream, int counter)
        {
            int bytesRcvd = 0;
            byte[] byteArrayReceive = new byte[64];
            byte[] data = new byte[64];

            if ((bytesRcvd = netStream.Read(byteArrayReceive, 0, 64)) == 0)
            {
                Console.WriteLine("Connection died early");
            }
            return decryptStatus(byteArrayReceive, counter);
        }

        //ENCRYPTION FOR CTR MODE
        private static byte[] encryptData(byte[] data, int counter)
        {
            byte[] encrypted = new byte[1024];
            byte[] tempdata = new byte[64];
            byte[] plaintext = new byte[1024];
            byte[] tempPlain = new byte[64];
            int i = 0;
            byte[] encryptKey = Encoding.UTF8.GetBytes("----KEY_HERE----");
            byte[] encryptIV = Encoding.UTF8.GetBytes("-----IV_HERE----");
            //Do we need to pad the data?
            if (data.Length != 1024)
            {
                Array.Copy(data, plaintext, data.Length);
                for (i = data.Length; i < (plaintext.Length - data.Length); i++)
                {
                    plaintext[i] = 0x00;
                }
            }
            else
            {
                plaintext = data.ToArray();
            }

            encryptIV[(counter % 16)]++;

            Aes128CounterMode am;
            ICryptoTransform ict;
            am = new Aes128CounterMode(encryptIV);
            ict = am.CreateEncryptor(encryptKey, null);
            ict.TransformBlock(plaintext, 0, 1024, encrypted, 0);
            return encrypted;
        }

        private static byte[] encryptSize(int size, int counter)
        {
            int i;
            byte[] encrypted = new byte[64];
            byte[] tempData = new byte[64];
            byte[] plaintext = new byte[64];
            byte[] encryptKey = Encoding.UTF8.GetBytes("----KEY_HERE----");
            byte[] encryptIV = Encoding.UTF8.GetBytes("-----IV_HERE----");

            tempData = Encoding.UTF8.GetBytes(size.ToString());
            //Do we need to pad the data?
            if (tempData.Length != 64)
            {
                Array.Copy(tempData, plaintext, tempData.Length);
                for (i = tempData.Length; i < (plaintext.Length - tempData.Length); i++)
                {
                    plaintext[i] = 0x00;
                }
            }
            else
            {
                plaintext = tempData.ToArray();
            }
            encryptIV[(counter % 16)]++;

            Aes128CounterMode am;
            ICryptoTransform ict;
            am = new Aes128CounterMode(encryptIV);
            ict = am.CreateEncryptor(encryptKey, null);
            ict.TransformBlock(plaintext, 0, 64, encrypted, 0);
            return encrypted;
        }


        private static int decryptStatus(byte[] status, int counter)
        {
            int ret = -1;
            string s;
            byte[] tempData = new byte[64];
            byte[] decryptKey = Encoding.UTF8.GetBytes("----KEY_HERE----");
            byte[] decryptIV = Encoding.UTF8.GetBytes("-----IV_HERE----");
            int neg = -1;

            decryptIV[(counter % 16)]++;

            Aes128CounterMode amD;
            ICryptoTransform ictD;
            amD = new Aes128CounterMode(decryptIV);
            ictD = amD.CreateDecryptor(decryptKey, null);


            ictD.TransformBlock(status, 0, 64, tempData, 0);
            s = System.Text.Encoding.UTF8.GetString(tempData);
            neg = s.IndexOf("-");
            if (neg != -1)
            {
                Int32.TryParse(s.Substring(neg), out ret);
            }
            else
            {
                Int32.TryParse(s, out ret);
            }
            return ret;

        }

        private static byte[] decryptData(byte[] data, int counter)
        {
            string s;
            byte[] decrypted = new byte[1024];
            byte[] decryptKey = Encoding.UTF8.GetBytes("----KEY_HERE----");
            byte[] decryptIV = Encoding.UTF8.GetBytes("-----IV_HERE----");

            decryptIV[(counter % 16)]++;

            Aes128CounterMode amD;
            ICryptoTransform ict;
            amD = new Aes128CounterMode(decryptIV);
            ict = amD.CreateDecryptor(decryptKey, null);
            ict.TransformBlock(data, 0, 1024, decrypted, 0);
            s = System.Text.Encoding.UTF8.GetString(decrypted);
            return decrypted;
        }

        //END OF ENCRYPTION FOR CTR MODE
    }
}