using System.Text;

namespace CalcRor13Hash.Library
{
    internal class Helpers
    {
        public static uint CalcRor13(uint code)
        {
            return (((code >> 13) | (code << (32 - 13))) & 0xFFFFFFFF);
        }


        public static uint GetHashFromAsciiString(string asciiString)
        {
            uint hash = 0;
            var asciiBytes = Encoding.ASCII.GetBytes(asciiString);

            for (var index = 0; index < asciiBytes.Length; index++)
                hash = CalcRor13(hash) + asciiBytes[index];

            return hash;
        }


        public static uint GetHashFromUnicodeString(string unicodeString)
        {
            uint hash = 0;
            var unicodeBytes = Encoding.Unicode.GetBytes(unicodeString);

            for (var index = 0; index < unicodeBytes.Length; index++)
                hash = CalcRor13(hash) + unicodeBytes[index];

            return hash;
        }
    }
}
