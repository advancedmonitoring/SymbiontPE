using System;
using System.IO;

namespace SymbiontPE
{
    public static class BWExtensions
    {
        public static void WriteZero(this BinaryWriter bw, int count = 1)
        {
            var zeroes = new byte[count];
            bw.Write(zeroes);
        }

        public static void Write4(this BinaryWriter bw, long qword)
        {
            // Cast once, instead of everytime
            bw.Write((UInt32)qword);
        }
    }
}