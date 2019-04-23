using System;
using System.IO;
using System.Linq;
using System.Text;

namespace SymbiontPE
{
    class Program
    {
        static void Banner()
        {
            Console.WriteLine("   ____                  _     _             _   ____  _____\n  / ___| _   _ _ __ ___ | |__ (_) ___  _ __ | |_|####\\|#####|\n  \\___ \\| | | | '_ ` _ \\| '_ \\| |/ _ \\| '_ \\| __|#|_)#|###|\n   ___) | |_| | | | | | | |_) | | (_) | | | | |_|####/|#|___\n  |____/ \\__, |_| |_| |_|_.__/|_|\\___/|_| |_|\\__|#|   |#####|\n         |___/\n\n   (c) 2019, Xi-Tauw, https://amonitoring.ru\n");
        }

        static void Usage()
        {
            Console.WriteLine("  Usage:\n    SymbiontPE pathToInputDll importDllName importFunction pathToOutputDll\n  Parameters:\n    <pathToInputDll> - path to existing dll (target of proxy)\n    <importDllName> - name of dll to be added to import\n    <importFunction> - name of function to be added to import\n    <pathToOutputDll> - path to save output proxy dll\n  Notes:\n    Any overlay (e.g. embedded signature) from input dll will be removed.\n    importFunction must be present in importDllName for correct loading of library, but it will not be invoked. Payload must be executed from DllEntry.\n  Example:\n    SymbiontPE C:\\windows\\system32\\version.dll my.dll func C:\\data\\version.dll\n  The command create proxy library, that acts like version.dll, but load my.dll at start.");
        }

        static void Main(string[] args)
        {
            Banner();
            if (args.Length != 4)
            {
                Usage();
                return;
            }
            AddImportTableFunction(args[0], args[1], args[2], args[3]);
        }
        
        private static void AddImportTableFunction(string path, string dllName, string dllFunc, string outputPath)
        {
            try
            {
                Console.WriteLine(" [!] Parse PE file");
                var pe = new PEFile(path);
                
                var newImportSize = pe.CalcNewImportSize(dllName, dllFunc);

                Console.WriteLine(" [!] Parse sections");
                var sections = pe.GetSections();
                var lastSection = sections[sections.Count - 1];
                var sectParams = pe.GetSectionParams(lastSection);

                Console.WriteLine(" [!] Change last section parameters");
                var originalSize = sectParams.SizeOfRawData;
                sectParams.Characteristics |= 0xC0000000;
                var addSize = pe.Align(originalSize, 0x1000) + pe.Align(newImportSize, 0x200) - originalSize;
                sectParams.VirtualSize += addSize;
                sectParams.SizeOfRawData += addSize;
                pe.SetSectionParams(lastSection, sectParams);

                Console.WriteLine(" [!] Create new import");
                var newImport = pe.CreateNewImport(lastSection, pe.Align(originalSize, 0x1000), dllName, dllFunc);

                Console.WriteLine(" [!] Write new import");
                pe.WriteDataAndTrim(lastSection, originalSize, newImport);
                pe.RedirectImportDataDir(lastSection, pe.Align(originalSize, 0x1000));
                pe.FixSizeOfImage();

                Console.WriteLine(" [!] Save result");
                pe.Save(outputPath);
                Console.WriteLine(" [!] Done");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Crash. Message: {e.Message}");
            }
        }
    }
}
