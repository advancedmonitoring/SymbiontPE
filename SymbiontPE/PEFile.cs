using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SymbiontPE
{
    public class PEFile
    {
        // Data
        private byte[] _content;
        private bool _is64;

        // Offsets
        private int _PEHeaderOffset;
        private int _sectionsOffset;
        private int _importDataDirRVAOffset;
        private int _importDataDirSizeOffset;

        // Sections
        private List<string> _sections;
        private List<PESectionParameters> _sectionParameters;

        // Import Data
        private byte[] _importData;

        // Consts
        //private const int SECTION_DESCRIPTOR_SIZE = 40;

        public PEFile(string path)
        {
            _content = File.ReadAllBytes(path);
            // DOS header
            if (((_content[0] == 0x4d) && (_content[1] == 0x5a)) || (((_content[0] == 0x5a) && (_content[1] == 0x4d))))
                // MZ
            {
                _PEHeaderOffset = (Int32) BitConverter.ToUInt32(_content, 0x3c);
                // PE header
                if ((_content[_PEHeaderOffset] == 0x50) && (_content[_PEHeaderOffset + 1] == 0x45)) // PE
                {
                    const int MACHINE_OFFSET = 4;
                    var machine = BitConverter.ToUInt16(_content, _PEHeaderOffset + MACHINE_OFFSET);
                    if (machine == 0x014c)
                    {
                        Console.WriteLine("   [.] Machine: pe32");
                        _is64 = false;
                    }
                    else if (machine == 0x8664)
                    {
                        Console.WriteLine("   [.] Machine: pe64");
                        _is64 = true;
                    }
                    else
                        throw new Exception("Unsupported machine value");

                    const int SECTION_COUNT_OFFSET = MACHINE_OFFSET + 2;
                    var countOfSections = BitConverter.ToUInt16(_content, _PEHeaderOffset + SECTION_COUNT_OFFSET);
                    Console.WriteLine($"   [.] Sections count: {countOfSections}");

                    const int OPTIONAL_HEADER_SIZE_OFFSET = SECTION_COUNT_OFFSET + 14;
                    var optionalHeaderSize = BitConverter.ToUInt16(_content,
                        _PEHeaderOffset + OPTIONAL_HEADER_SIZE_OFFSET);
                    Console.WriteLine($"   [.] Optional header size: {optionalHeaderSize}");

                    // Optional Header
                    const int OPTIONAL_HEADER_OFFSET = OPTIONAL_HEADER_SIZE_OFFSET + 4;
                    var optionalHeaderMagic = BitConverter.ToUInt16(_content, _PEHeaderOffset + OPTIONAL_HEADER_OFFSET);
                    bool isMagic64;
                    if (optionalHeaderMagic == 0x010b)
                    {
                        Console.WriteLine("   [.] OptHeader Magic: 32bit");
                        isMagic64 = false;
                    }
                    else if (optionalHeaderMagic == 0x020b)
                    {
                        Console.WriteLine("   [.] OptHeader Magic: 64bit");
                        isMagic64 = true;
                    }
                    else
                        throw new Exception("Unsupported OptHeader magic value");
                    if (_is64 != isMagic64)
                        throw new Exception("OptHeader magic does not match machine");

                    // Data Directories
                    const int DATADIR_COUNT = 16;
                    const int DATADIR_SIZE = 8;
                    int dataDirsOffset = OPTIONAL_HEADER_OFFSET + optionalHeaderSize - DATADIR_COUNT * DATADIR_SIZE;
                    _importDataDirRVAOffset = dataDirsOffset + 8;
                    var importDataDirRVA = BitConverter.ToUInt32(_content, _PEHeaderOffset + _importDataDirRVAOffset);

                    _importDataDirSizeOffset = _importDataDirRVAOffset + 4;
                    var importDataDirSize = BitConverter.ToUInt32(_content, _PEHeaderOffset + _importDataDirSizeOffset);

                    // Sections Table
                    _sectionsOffset = OPTIONAL_HEADER_OFFSET + optionalHeaderSize;
                    var index = _sectionsOffset;
                    _sections = new List<string>();
                    _sectionParameters = new List<PESectionParameters>();
                    for (var i = 0; i < countOfSections; i++)
                    {
                        var sectionBytes = new byte[PESectionParameters.SECTION_DESCRIPTOR_SIZE];
                        Array.Copy(_content, _PEHeaderOffset + index, sectionBytes, 0,
                            PESectionParameters.SECTION_DESCRIPTOR_SIZE);
                        index += PESectionParameters.SECTION_DESCRIPTOR_SIZE;
                        var p = new PESectionParameters(sectionBytes);
                        _sectionParameters.Add(p);
                        _sections.Add(p.Name);
                        Console.WriteLine($"   [.] Find section: '{p.Name}'");
                    }

                    // Find section with import
                    var sectionWithImport = -1;
                    for (var i = 0; i < _sectionParameters.Count; i++)
                    {
                        var p = _sectionParameters[i];
                        if ((p.VirtualAddress <= importDataDirRVA) &&
                            (p.VirtualAddress + p.SizeOfRawData >= importDataDirRVA + importDataDirSize))
                            sectionWithImport = i;
                    }
                    if (sectionWithImport == -1)
                        throw new Exception("Unable to find section with Import Directory");
                    Console.WriteLine($"   [.] Import found at section '{_sectionParameters[sectionWithImport].Name}'");

                    var importDataDirOffset = importDataDirRVA - _sectionParameters[sectionWithImport].VirtualAddress + _sectionParameters[sectionWithImport].PointerToRawData;
                    _importData = new byte[importDataDirSize];
                    Array.Copy(_content, importDataDirOffset, _importData, 0, importDataDirSize);
                    return;
                }
            }
            throw new Exception("Bad PE");
        }

        public void FixSizeOfImage()
        {
            var size = _sectionParameters[_sectionParameters.Count - 1].VirtualSize + _sectionParameters[_sectionParameters.Count - 1].VirtualAddress;
            if (size % 0x1000 != 0)
                size = ((size / 0x1000) + 1) * 0x1000;
            Array.Copy(BitConverter.GetBytes(size), 0, _content, _PEHeaderOffset + 80, 4);
            Console.WriteLine("   [.] SizeOfImage fixed");
        }
        
        public List<string> GetSections()
        {
            var rv = new List<string>();
            rv.AddRange(_sections);
            return rv;
        }

        public PESectionParameters GetSectionParams(string sectionName)
        {
            foreach (var p in _sectionParameters)
            {
                if (p.Name == sectionName)
                    return p;
            }
            throw new Exception($"Section '{sectionName}' not found (GetSectionParams)");
        }

        public void SetSectionParams(string sectionName, PESectionParameters sectParams)
        {
            for (var i = 0; i < _sectionParameters.Count; i++)
            {
                if (_sectionParameters[i].Name == sectionName)
                {
                    _sectionParameters[i] = sectParams;
                    Array.Copy(sectParams.ToBytes(), 0, _content,
                        _PEHeaderOffset + _sectionsOffset + PESectionParameters.SECTION_DESCRIPTOR_SIZE * i,
                        PESectionParameters.SECTION_DESCRIPTOR_SIZE);
                    return;
                }
            }
            throw new Exception($"Section '{sectionName}' not found (SetSectionParams)");
        }

        public void WriteDataAndTrim(string sectionName, UInt32 offset, byte[] bytes)
        {
            for (var i = 0; i < _sectionParameters.Count; i++)
            {
                if (_sectionParameters[i].Name == sectionName)
                {
                    var beginSize = _sectionParameters[i].PointerToRawData + offset;
                    var beginAlign = _sectionParameters[i].PointerToRawData + Align(offset, 0x1000);
                    var endAlign = Align((UInt32) bytes.Length, 0x200);
                    var newContent = new byte[beginAlign + endAlign];
                    Array.Copy(_content, 0, newContent, 0, beginSize);
                    Array.Copy(bytes, 0, newContent, beginAlign, bytes.Length);
                    _content = newContent;
                    Console.WriteLine($"   [.] File new size: {_content.Length}");
                    return;
                }
            }
            throw new Exception($"Section '{sectionName}' not found (WriteDataAndTrim)");
        }

        public void Save(string outputPath)
        {
            File.WriteAllBytes(outputPath, _content);
        }

        public UInt32 Align(UInt32 length, UInt32 align)
        {
            UInt32 rv = 0;
            while (rv < length)
                rv += align;
            return rv;
        }

        public UInt32 CalcNewImportSize(string dllName, string dllFunc)
        {
            return (UInt32)(_importData.Length + 20 + dllName.Length + 1 + 2 + dllFunc.Length + 1 + 0x10 + 0x10);
        }

        public byte[] CreateNewImport(string sectionName, UInt32 offset, string dllName, string dllFunc)
        {
            for (var i = 0; i < _sectionParameters.Count; i++)
            {
                if (_sectionParameters[i].Name == sectionName)
                {
                    var rv = new byte[CalcNewImportSize(dllName, dllFunc)];
                    UInt32 BaseAddr = _sectionParameters[i].VirtualAddress + offset;
                    using (var mem = new MemoryStream(rv))
                    using (var bw = new BinaryWriter(mem))
                    {
                        // Write original without last line (originalImport.Length - 20)
                        bw.Write(_importData, 0, _importData.Length - 20);
                        // Write IMPORT ENTRY (20)
                        bw.Write4(BaseAddr + (_importData.Length + 20 + dllName.Length + 1 + 2 + dllFunc.Length + 1 + 0x10));
                        bw.WriteZero(4);
                        bw.WriteZero(4);
                        bw.Write4(BaseAddr + (_importData.Length + 20));
                        bw.Write4(BaseAddr + (_importData.Length + 20 + dllName.Length + 1 + 2 + dllFunc.Length + 1));
                        // Write last line (20)
                        bw.WriteZero(20);
                        // Write dll (dllName.Length + 1)
                        bw.Write(Encoding.ASCII.GetBytes(dllName));
                        bw.WriteZero();
                        // Write zero-struct (2)
                        bw.WriteZero(2);
                        // Write func (dllFunc.Length + 1)
                        bw.Write(Encoding.ASCII.GetBytes(dllFunc));
                        bw.WriteZero();
                        // Write Thunks (0x20)
                        bw.Write4(BaseAddr + (_importData.Length + 20 + dllName.Length + 1));
                        bw.WriteZero(12);
                        bw.Write4(BaseAddr + (_importData.Length + 20 + dllName.Length + 1));
                        bw.WriteZero(12);
                    }
                    // Copy 
                    return rv;
                }
            }
            throw new Exception($"Section '{sectionName}' not found (CreateNewImport)");
        }

        public void RedirectImportDataDir(string sectionName, UInt32 offset)
        {
            for (var i = 0; i < _sectionParameters.Count; i++)
            {
                if (_sectionParameters[i].Name == sectionName)
                {
                    var newImportOff = _sectionParameters[i].VirtualAddress + offset;
                    Array.Copy(BitConverter.GetBytes(newImportOff), 0, _content,
                        _PEHeaderOffset + _importDataDirRVAOffset, 4);
                    var newImportSize = BitConverter.ToUInt32(_content, _PEHeaderOffset + _importDataDirSizeOffset);
                    newImportSize += 0x14; // FIXME
                    Array.Copy(BitConverter.GetBytes(newImportSize), 0, _content,
                        _PEHeaderOffset + _importDataDirSizeOffset, 4);
                    return;
                }
            }
            throw new Exception($"Section '{sectionName}' not found (RedirectImportDataDir)");
        }
    }
}