using System;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using static System.Net.Mime.MediaTypeNames;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace LösenRenskriv
{
    public class Program
    {
        public static void Main(string[] args)
        {
            

            if(args.Length == 0)
                return;
            
                switch (args[0].ToLower())
                {
                    case "init":
                    try
                    {
                        string clientPath = args[1];
                        string serverPath = args[2];
                        Init(clientPath, serverPath);
                    }
                    catch
                    {
                        Console.WriteLine("IN Wrong input, try again.");
                        return;
                    }
                    break;


                    case "create":
                    try
                    {
                        string clientPath = args[1];
                        string serverPath = args[2];
                        Create(clientPath, serverPath);
                    }
                    catch
                    {
                        Console.WriteLine("CRE Wrong input, try again.");
                        return;
                    }
                    break;


                    case "get":
                    try
                    {
                        if (args[3].Length != 0)
                        {
                            string clientPath = args[1];
                            string serverPath = args[2];
                            string prop = args[3];
                            Get(clientPath, serverPath, prop);
                        }
                        else if (args[3].Length == 0)
                        {
                            string clientPath = args[1];
                            string serverPath = args[2];
                            string noProp = "noProp";
                            Get(clientPath, serverPath, noProp);
                        }
                    }
                    catch
                    {
                        Console.WriteLine("GET Wrong input, try again.");
                        return;
                    } 
                    break;


                    case "set":     //osäker 
                    try
                    {
                        string clientPath = args[1];
                        string serverPath = args[2];
                        string prop = args[3];

                        if (args[4].ToLower() == "--generate" || args[4].ToLower() == "--g")
                        {
                            bool generate = true;
                            Set(clientPath, serverPath, prop, generate);
                        }
                        else if (args[4].Length == 0)
                        {
                            bool generate = false;
                            Set(clientPath, serverPath, prop, generate);
                        }
                        else Console.WriteLine("Wrong input, try again.");
                    }
                    catch
                    {
                        Console.WriteLine("SET Wrong input, try again.");
                        return;
                    }
                    break;


                    case "delete":  //osäker. kollar try att args 1 och 2 ej är null?
                    try
                    {
                        string clientPath = args[1];
                        string serverPath = args[2];
                        if (args[3].Length != 0)
                        {
                            string prop = args[3];
                            Delete(clientPath, serverPath, prop);

                        }
                        else Console.WriteLine("Wrong input, try again.");
                    }
                    catch
                    {
                        Console.WriteLine("DEL Wrong input, try again.");
                        return;
                    }
                    break;


                    case "secret":
                    try
                    {
                        string clientPath = args[1];
                        Secret(clientPath);
                    }
                    catch
                    {
                        Console.WriteLine("SEC Wrong input, try again.");
                        return;
                    }
                    break;

                    default:
                        Console.WriteLine("Something went wrong.");
                    break;
                }

                

            static void Secret(string clientP)
            {
                string readJsonClient = File.ReadAllText(clientP);
                Dictionary<string, string> clientJsonText = JsonSerializer.Deserialize<Dictionary<string, string>>(readJsonClient);

                string sameSecretKey = clientJsonText["SecretKey"];

                Console.WriteLine($"The secret key is: {sameSecretKey}");
            }

            static void Delete(string clientP, string serverP, string prop)
            {
                Console.WriteLine("Enter your password:");
                string masterPassword = Console.ReadLine();

                if (masterPassword == null)
                {
                    Console.WriteLine("mp är  null");

                    Environment.Exit(0);
                }

                string result = CheckMasterPassword(clientP, serverP, masterPassword);

                if (result != null)
                {
                    Dictionary<string, string> decryptedVault = JsonSerializer.Deserialize<Dictionary<string, string>>(result);
                    
                    if (decryptedVault.ContainsKey(prop))
                    {
                        decryptedVault.Remove(prop);
                        Console.WriteLine($"You have now deleted the property {prop} from the vault.");
                    }
                    else Console.WriteLine("The propetry you entered does not exist.");

                }
                else Console.WriteLine("Your entered the wrong password, try again.");
                Environment.Exit(0);
            }

            static void Set(string clientP, string serverP, string prop, bool generate)
            {
                Console.WriteLine("Enter your password:");
                string masterPassword = Console.ReadLine();

                if (masterPassword == null)
                {
                    Console.WriteLine("mp är  null");

                    Environment.Exit(0);
                }

                string result = CheckMasterPassword(masterPassword, clientP, serverP);

                if (result != null)
                {
                    Dictionary<string, string> decryptedVault = JsonSerializer.Deserialize<Dictionary<string, string>>(result);

                    if (generate == true)
                    {
                        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                        var stringChars = new char[20];
                        var random = new Random();

                        for (int i = 0; i < stringChars.Length; i++)
                        {
                            stringChars[i] = chars[random.Next(chars.Length)];
                        }

                        string generatedPassword = stringChars.ToString();

                        Console.WriteLine($"Your generated password for {prop} is: {generatedPassword}");
                    }
                    else if (generate == false)
                    {
                        Console.WriteLine($"Enter your new password for {prop}:");
                        string newPassword = Console.ReadLine();

                        if (newPassword.Length != 0)
                        {
                            decryptedVault["prop"] = newPassword;
                            Console.WriteLine($"Your new password for {prop} is: {newPassword}");
                        }
                        else Console.WriteLine("Try again.");
                    }
                }
                else Console.WriteLine("Your entered the wrong password, try again.");
                Environment.Exit(0);
            }

            static void Get(string clientP, string serverP, string prop)
            {
                //ta in lösen och secret key för att göra vault key för att försöka dekrypera aka kolla om rätt lösen
                Console.WriteLine("Enter your password:");
                string masterPassword = Console.ReadLine();

                if (masterPassword == null)
                {
                    Console.WriteLine("mp är  null");

                    Environment.Exit(0);
                }

                string result = CheckMasterPassword(masterPassword, clientP, serverP);

                if (result != null)
                {
                    //Console.WriteLine("Enter the property whose password you wish to get. Otherwise press enter to see all current properties.");
                    //string prop = Console.ReadLine();

                    Dictionary<string, string> decryptedVault = JsonSerializer.Deserialize<Dictionary<string, string>>(result);

                    if (prop == "noProp")
                    {
                        Console.WriteLine("These are all of the properties: ");
                        foreach (string key in decryptedVault.Keys)
                        {
                            Console.WriteLine(key);
                        }
                        //printa hela decrypted vault, alla props aka keys
                    }
                    else if (decryptedVault.ContainsKey(prop))
                    {
                        Console.WriteLine($"This is the password for {prop}:");
                        Console.WriteLine(decryptedVault[prop]);
                        //printa lösenordet till den tillhörande propen
                    }
                    else Console.WriteLine("Vault contains no such property.");
                }
                else Console.WriteLine("Your entered the wrong password, try again.");
                Environment.Exit(0);
            }

            static void Create(string clientP, string serverP)
            {
                //användaren skriver in både masterpassword och secret key
                Console.WriteLine("Enter your password:");
                string masterPassword = Console.ReadLine();

                if (masterPassword == null)
                {
                    Console.WriteLine("mp är  null");

                    Environment.Exit(0);
                }

                Console.WriteLine("Enter your secret key:");
                string secretKey = Console.ReadLine();           

                //konvertera secret key för att generera ny vault key - rätt metod

                byte[] byteSecretKey = new byte[16];

                byteSecretKey = Convert.FromBase64String(secretKey);
                              

                int iterera = 1000;
                Rfc2898DeriveBytes newVaultKey = new Rfc2898DeriveBytes(masterPassword, byteSecretKey, iterera);
                byte[] byteNewVaultKey = newVaultKey.GetBytes(16);

                string readJsonServer;

                //hämta krypterat valv och IV, deserialisera i en dictionary för att kunna hämta värdena
                
                readJsonServer = File.ReadAllText(serverP);
               

                Dictionary<string, string> serverJsonText = JsonSerializer.Deserialize<Dictionary<string, string>>(readJsonServer);

                string encryptedVault = serverJsonText["EncryptedVault"];
                string IV = serverJsonText["IV"];


                byte[] encryptedVaultbyte = Convert.FromBase64String(encryptedVault);
                byte[] IVbyte = Convert.FromBase64String(IV);

                //Försöka dekryptera valvet
                string roundtrip = DecryptStringFromBytes_Aes(encryptedVaultbyte, byteNewVaultKey, IVbyte);

                if (roundtrip != null)
                {
                    string readJsonClient;
                    try
                    {
                        readJsonClient = File.ReadAllText(clientP);
                    }
                    catch
                    {
                        Console.WriteLine("Couldn't find path.");
                        return;
                    }

                    Dictionary<string, string> clientJsonText = JsonSerializer.Deserialize<Dictionary<string, string>>(readJsonClient);

                    string sameSecretKey = clientJsonText["SecretKey"];
                    byte[] sameSecretKeyByte = Convert.FromBase64String(sameSecretKey);


                    Client newClient = new Client()
                    {
                        SecretKey = sameSecretKeyByte,
                        Path = clientP
                    };

                    string secretKeyText = Convert.ToBase64String(newClient.SecretKey);

                    Dictionary<string, string> clientDictionary = new Dictionary<string, string>
                    {
                        { "SecretKey", secretKeyText }
                    };

                    //serialisera och spara dictionaryn som json-fil, sparar över gammal
                    string jsonClient = JsonSerializer.Serialize(clientDictionary);

                    File.WriteAllText(newClient.Path, jsonClient);
                }

                else Console.WriteLine("Your entered the wrong password, try again.");                
            }

            static void Init(string clientP, string serverP)
            {
                //användaren skriver in lösenord
                Console.WriteLine("Enter your password:");
                string masterPassword = Console.ReadLine();

                if (masterPassword == null)
                {
                    Console.WriteLine("mp är  null");
                    Environment.Exit(0);
                }

                //skapa random iv och secret key
                RandomNumberGenerator rng = RandomNumberGenerator.Create();

                byte[] IV = GenerateRandom(rng);
                byte[] secretKey = GenerateRandom(rng);

                //skapa CLient och set dess secret key, skriv ut så användaren kan spara ?
                Client client = new Client()
                {
                    SecretKey = secretKey,
                    Path = clientP 
                };


                //gör om till string för att kunna lagra i en dictionary

                string secretKeyText = Convert.ToBase64String(client.SecretKey);


                //secret key printed in plain text - siffror???
                Console.WriteLine($"Remember your secret key, it is: {secretKeyText}");
               

                Dictionary<string, string> clientDictionary = new Dictionary<string, string>
                {
                    { "SecretKey", secretKeyText }
                };

                //serialisera och spara dictionaryn som json-fil
                string jsonClient = JsonSerializer.Serialize(clientDictionary);

                File.WriteAllText(client.Path, jsonClient);

                //skapa tomt lösenordsvalv och serialisera
                Dictionary<string, string> Vault = new Dictionary<string, string>();

                string jsonVault = JsonSerializer.Serialize(Vault);

                //generera vault key, gör om till byte[]
                int iterera = 1000;
                Rfc2898DeriveBytes vaultKey = new Rfc2898DeriveBytes(masterPassword, client.SecretKey, iterera);
                byte[] byteVaultKey = vaultKey.GetBytes(16);

                //kryptera valv med vault key och IV
                using (Aes AES = Aes.Create())
                {
                    byte[] encryptedVault = EncryptStringToBytes_Aes(jsonVault, byteVaultKey, IV);

                    //skapa server, tilldela krypterat valv och IV
                    Server server = new Server()
                    {
                        IV = IV,
                        EncryptedVault = encryptedVault,
                        Path = serverP
                    };

                    //gör om till string för att kunna lagra i en dictionary
                    string IVtext = Convert.ToBase64String(server.IV);
                    string encryptedVaultText = Convert.ToBase64String(server.EncryptedVault);

                    Dictionary<string, string> serverDictionary = new Dictionary<string, string>
                    {
                        { "IV", IVtext },
                        { "EncryptedVault", encryptedVaultText }
                    };

                    //serialisera och spara servern som json-fil
                    string jsonServer = JsonSerializer.Serialize(serverDictionary);

                    File.WriteAllText(server.Path, jsonServer);
                }
            }



            static byte[] GenerateRandom(RandomNumberGenerator rng)
            {
                byte[] random = new byte[16];

                rng.GetBytes(random);

                return random;
            }

            static byte[] EncryptStringToBytes_Aes(string input, byte[] vaultkey, byte[] IV)
            {
                // Felhantera innan det här
                if (input == null || input.Length <= 0)
                    throw new ArgumentNullException("fel med plainText");
                if (vaultkey == null || vaultkey.Length <= 0)
                    throw new ArgumentNullException("fel med Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("fel med IV");
                

                byte[] encryptedVault;

                using (Aes aes = Aes.Create())
                {
                    ICryptoTransform encryptor = aes.CreateEncryptor(vaultkey, IV);

                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                //Write all data to the stream.
                                swEncrypt.Write(input);
                            }
                            encryptedVault = msEncrypt.ToArray();
                        }
                    }
                }
                return encryptedVault;
            }

            static string DecryptStringFromBytes_Aes(byte[] input, byte[] newVaultKey, byte[] IV)
            {
                // Check arguments - gör innan
                if (input == null || input.Length <= 0)
                    throw new ArgumentNullException("cipherText");
                if (newVaultKey == null || newVaultKey.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("IV");

                // Declare the string used to hold
                // the decrypted text.
                string plaintext = null;

                // Create an Aes object
                // with the specified key and IV.
                using (Aes aesAlg = Aes.Create())
                {

                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(newVaultKey, IV);

                    // Create the streams used for decryption.
                    using (MemoryStream msDecrypt = new MemoryStream(input))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                plaintext = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }

                return plaintext;
            }

            static string CheckMasterPassword(string input, string clientP, string serverP)
            {
                string readJsonClient = File.ReadAllText(clientP);
                Dictionary<string, string> clientJsonText = JsonSerializer.Deserialize<Dictionary<string, string>>(readJsonClient);

                string sameSecretKey = clientJsonText["SecretKey"];
                byte[] sameSecretKeyByte = Convert.FromBase64String(sameSecretKey);

                int iterera = 1000;
                Rfc2898DeriveBytes newVaultKey = new Rfc2898DeriveBytes(input, sameSecretKeyByte, iterera);
                byte[] byteNewVaultKey = newVaultKey.GetBytes(16);


                string readJsonServer = File.ReadAllText(serverP);
                Dictionary<string, string> serverJsonText = JsonSerializer.Deserialize<Dictionary<string, string>>(readJsonServer);

                string encryptedVault = serverJsonText["EncryptedVault"];
                string IV = serverJsonText["IV"];

                byte[] encryptedVaultbyte = Convert.FromBase64String(encryptedVault);                //ändrad metod ascii
                byte[] IVbyte = Convert.FromBase64String(IV);


                string roundtrip = DecryptStringFromBytes_Aes(encryptedVaultbyte, byteNewVaultKey, IVbyte);

                return roundtrip;
            }


        }
    }
}
