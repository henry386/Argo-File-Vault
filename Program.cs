using System.Security.Cryptography;
using System.Text;

interfacing.start_menu_volume();


while(true)
{
    interfacing.get_input();
}
public class interfacing
{
    public static string volume = "";

    public static Aes myAes = Aes.Create();
    public static Dictionary<string, string> encrypted_files = new Dictionary<string, string>();
    private string key = "";

    static string aes_key = "";
    public static void clear()
    {
        Console.Clear();
    }
    public static void start_menu_volume()
    {

        Console.BackgroundColor = ConsoleColor.Red;
        Console.ForegroundColor = ConsoleColor.Black;
        print("Argo File Vault");
        print("");
        Console.BackgroundColor = ConsoleColor.Black;
        Console.ForegroundColor = ConsoleColor.Green;

        print("Select Function:");
        print("1. Edit Existing Volume");
        print("2. Create New Volume");
        print("3. Exit");
        Console.Write("> ");
        string selection = Console.ReadLine();
        clear();
        if(selection == "1")
        {
            print("Enter Volume Location: ");
            Console.Write("> ");
            volume = Console.ReadLine();
            set_directory(volume);
        }
        else if(selection == "2")
        {
            create_volume();
        }
        else if(selection == "3")
        {
            Environment.Exit(0);
        }
        else
        {
            clear();
            print("Invalid Input");
            print("");
            start_menu_volume();
        }
    }
    private static string current_directory = "";

    public static void create_volume()
    {
        print("Enter New Volume Name: ");
        volume = "";
        while (volume == "" || volume == ".encv")
        {
            Console.Write("> ");
            volume = Console.ReadLine() + ".encv";
        }
        if (volume != "")
        {
            if (File.Exists(volume) == false)
            {
                using (File.Create(volume)) ;
                set_directory(volume);

            }
            else
            {
                print("");
                print("Volume " + volume + " already Exists");
                print("");
                create_volume();
            }
        }
        
    }

    public static void get_encrypted_data(string volume)
    {
        string data = encryption.decrypt_file(volume);
        if (data != "")
        {
            string[] lines = data.Split(Environment.NewLine);
            int i = 0;
            while (i < lines.Length - 1)
            {
                encrypted_files.Add(lines[i].Split(',')[0], lines[i].Split(',')[1]);
                i++;
            }
        }
    }
    public static void set_directory(string dir)
    {
        if(File.Exists(dir) == true)
        {
            print("Enter Key: ");
            Console.Write("> ");

            encryption.set_key(encryption.sha256(Console.ReadLine()));
            print("Volume Set: " + dir);
            current_directory = dir;
            get_encrypted_data(current_directory);
        }
        else
        {
            print("Volume Doesnt Exist");
            start_menu_volume();
        }
    }
    public static void get_input()
    {
        Console.Write(current_directory + "> ");
        string command = Console.ReadLine();
        process_input(command);
    }

    public static void process_input(string command)
    {
        if(command == "upload")
        {
            upload();
        }
        else if (command.StartsWith("upload"))
        {
            upload(command.Substring(7, command.Length - 7));
        }
        else if (command == "dir")
        {
            dir();
        }

        else if(command == "export")
        {
            export();
        }
        else if (command.StartsWith("export"))
        {
            string temp = (command.Substring(7, command.Length - 7));
            string main_file = temp.Split(' ')[0];
            string second_file = temp.Split(' ')[1];
            export(main_file, second_file);
        }
        else if(command == "help")
        {
            help();
        }
        else if (command == "peak")
        {
            peak();
        }
        else if (command.StartsWith("peak"))
        {
            peak(command.Substring(5, command.Length - 5));
        }

        else if (command == "rm")
        {
            remove_file();
        }
        else if (command.StartsWith("rm"))
        {
            remove_file(command.Substring(3, command.Length - 3));
        }
        else if (command.StartsWith("quit") || command.StartsWith("exit") || command.StartsWith("close"))
        {
            Environment.Exit(0);
        }
        else
        {
            print("ERROR: Command Not Found");
        }
    }

    public static void remove_file(string file = "null")
    {
        if (file == "null")
        {
            print("Enter File to Remove:");
            Console.Write("> ");
            file = Console.ReadLine();
        }

        if (encrypted_files.ContainsKey(file))
        {
            encrypted_files.Remove(file);

            string write_var = "";
            int i = 0;
            while (i < encrypted_files.Count)
            {
                write_var = write_var + encrypted_files.ElementAt(i).Key + "," + encrypted_files.ElementAt(i).Value + Environment.NewLine;
                i++;
            }

            encryption.encrypt_file(volume, write_var);

            print("File: " + file + " Removed");
        }
        else
        {
            print("File: " + file + " Not Found");
        }
    }
    public static void peak(string file = "null")
    {
        if (file == "null")
        {
            print("Enter File to Veiw: ");
            file = Console.ReadLine();
            print(Encoding.UTF8.GetString(Base64Decode(encrypted_files[file])));
        }
        else
        {
            print(Encoding.UTF8.GetString(Base64Decode(encrypted_files[file])));
        }
    }
    public static void help()
    {
        clear();
        print("");
        print("Help Menu");
        print("");
        print("Commands:");
        print("     dir : List All files within the Volume");
        print("     upload : Upload file from Source File System (upload filename)");
        print("     export : Export a file from the volume to the Source File System (export filenameonvolume locationonlocaldisk)");
        print("     exit : Quit the application");
        print("     peak : Print the Contents of a File to the Terminal Screen (peak filenameonvolume)");
        print("     rm : Removes the File from the Volume (rm filenameonvolume)");
        print("");

    }

    public static void export(string file_main = "null", string file_second = "null")
    {
        if (file_main == "null" | file_second == "null")
        {
            print("Enter File Name to Export: ");
            string file = Console.ReadLine();
            print("Enter Export Location");
            string export_location = Console.ReadLine();
            print("Exporting File...");

            File.WriteAllBytes(export_location + '\\' + file, Base64Decode(encrypted_files[file]));
        }
        else
        {
            print("Exporting File...");
            File.WriteAllBytes(file_second + '\\' + file_main, Base64Decode(encrypted_files[file_main]));
        }
        print("File Exported");
    }

    public static void upload(string file = "null")
    {
        string file_name = "";
        if(file == "null")
        {
            print("Enter File Location: ");
            file_name = Console.ReadLine();
            
            
        }
        else
        {
            file_name = file;
        }

        if (File.Exists(file_name) == true)
        {
            if (encrypted_files.ContainsKey(Path.GetFileName(file_name)))
            {
                print("Removing Existing File...");
                remove_file(file_name);
            }
            else
            {
                byte[] file_contents = File.ReadAllBytes(file_name);

                string file_contents_enc = Base64Encode(file_contents);
                encrypted_files.Add(Path.GetFileName(file_name), file_contents_enc);
                string write_var = "";
                int i = 0;
                while (i < encrypted_files.Count)
                {
                    write_var = write_var + encrypted_files.ElementAt(i).Key + "," + encrypted_files.ElementAt(i).Value + Environment.NewLine;
                    i++;
                }
                print("File: Uploaded");
                encryption.encrypt_file(volume, write_var);
            }
        }
        else
        {
            print("File not Found");
        }

    }
    public static void dir()
    {

        int i = 0;
        while (i < encrypted_files.Count)
        {
            print(i.ToString() + ". " + encrypted_files.ElementAt(i).Key + "  Size: " + encrypted_files.ElementAt(i).Value.Length.ToString());
            i++;
        }
        
    }
    public static void print(string message)
    {
        Console.WriteLine(message);
    }
    public static string Base64Encode(byte[] plainText)
    {
        return Convert.ToBase64String(plainText);
    }

    public static byte[] Base64Decode(string base64EncodedData)
    {
        return System.Convert.FromBase64String(base64EncodedData);
    }
}



public static class encryption
{
    public static bool encrypt_file(string file_name, string file_contents)
    {
        try
        {
            byte[] encrypted = Encrypt(Encoding.UTF8.GetBytes(file_contents), key, iv);
            File.WriteAllBytes(file_name, encrypted);
            return true;
        }
        catch
        {
            return false;
        }

    }
    public static string decrypt_file(string file_name)
    {
        byte[] decrypted = Decrypt(File.ReadAllBytes(file_name), key, iv);
        return Encoding.UTF8.GetString(decrypted);
    }

    public static void set_key(byte[] key_to_set)
    {
        key = key_to_set;
        byte[] iv_toset = new byte[16];
        int i = 0;
        while(i < 15)
        {
            iv_toset[i] = (key_to_set[i]);
            i++;
        }
        iv = iv_toset;

    }

    static byte[] key = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    static byte[] iv = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
    {
        using (var aes = Aes.Create())
        {
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Padding = PaddingMode.Zeros;

            aes.Key = key;
            aes.IV = iv;

            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            {
                return PerformCryptography(data, encryptor);
            }
        }
    }
    public static byte[] sha256(string text)
    {
        byte[] bytes = Encoding.Unicode.GetBytes(text);
        var hashstring = SHA256.Create();
        byte[] hash = hashstring.ComputeHash(bytes);
        return hash;
    }
    public static  byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
    {
        using (var aes = Aes.Create())
        {
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Padding = PaddingMode.Zeros;

            aes.Key = key;
            aes.IV = iv;

            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            {
                return PerformCryptography(data, decryptor);
            }
        }
    }
    private static byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
    {
        using (var ms = new MemoryStream())
        using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
        {
            cryptoStream.Write(data, 0, data.Length);
            cryptoStream.FlushFinalBlock();

            return ms.ToArray();
        }
    }
}