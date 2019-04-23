using System;
using System.IO;
using System.Text;

namespace SymbiontPE
{
    public class PESectionParameters
    {
        public const int SECTION_DESCRIPTOR_SIZE = 40;

        public readonly string Name;
        public UInt32 VirtualSize;
        public readonly UInt32 VirtualAddress;
        public UInt32 SizeOfRawData;
        public readonly UInt32 PointerToRawData;
        /*
        public readonly UInt32 PointerToRelocations;
        public readonly UInt32 PointerToLinenumbers;
        public readonly UInt16 NumberOfRelocations;
        public readonly UInt16 NumberOfLinenumbers;
        */
        public UInt32 Characteristics;

        public PESectionParameters(byte[] sectionBytes)
        {
            if (sectionBytes.Length != SECTION_DESCRIPTOR_SIZE)
                throw new Exception("Bad section");
            using (var mem = new MemoryStream(sectionBytes))
            using (var br = new BinaryReader(mem))
            {
                var nameBts = br.ReadBytes(8);
                Name = Encoding.ASCII.GetString(nameBts).TrimEnd('\0');
                VirtualSize = br.ReadUInt32();
                VirtualAddress = br.ReadUInt32();
                SizeOfRawData = br.ReadUInt32();
                PointerToRawData = br.ReadUInt32();
                br.ReadUInt32(); // PointerToRelocations
                br.ReadUInt32(); // PointerToLinenumbers
                br.ReadUInt16(); // NumberOfRelocations
                br.ReadUInt16(); // NumberOfLinenumbers
                Characteristics = br.ReadUInt32();
            }
        }

        public byte[] ToBytes()
        {
            var rv = new byte[SECTION_DESCRIPTOR_SIZE];
            using (var mem = new MemoryStream(rv))
            using (var bw = new BinaryWriter(mem))
            {
                var nameBts = new byte[8];
                Array.Copy(Encoding.ASCII.GetBytes(Name), nameBts, Name.Length);
                bw.Write(nameBts);
                bw.Write(VirtualSize);
                bw.Write(VirtualAddress);
                bw.Write(SizeOfRawData);
                bw.Write(PointerToRawData);
                bw.WriteZero(4); // PointerToRelocations
                bw.WriteZero(4); // PointerToLinenumbers
                bw.WriteZero(2); // NumberOfRelocations
                bw.WriteZero(2); // NumberOfLinenumbers
                bw.Write(Characteristics);
            }
            return rv;
        }
    }
}