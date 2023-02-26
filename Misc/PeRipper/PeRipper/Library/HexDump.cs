using System;
using System.Runtime.InteropServices;
using System.Text;

namespace PeRipper.Library
{
    internal class HexDump
    {
        public static void Dump(byte[] data, int nIndentCount)
        {
            IntPtr pBufferToRead = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, pBufferToRead, data.Length);

            Dump(pBufferToRead, new IntPtr(-1), (uint)data.Length, nIndentCount);

            Marshal.FreeHGlobal(pBufferToRead);
        }


        public static void Dump(byte[] data, uint nRange, int nIndentCount)
        {
            IntPtr pBufferToRead = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, pBufferToRead, data.Length);

            Dump(pBufferToRead, new IntPtr(-1), nRange, nIndentCount);

            Marshal.FreeHGlobal(pBufferToRead);
        }


        public static void Dump(byte[] data, IntPtr pBaseAddress, uint nRange, int nIndentCount)
        {
            IntPtr pBufferToRead = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, pBufferToRead, data.Length);

            Dump(pBufferToRead, pBaseAddress, nRange, nIndentCount);

            Marshal.FreeHGlobal(pBufferToRead);
        }


        public static void Dump(IntPtr pBufferToRead, uint nRange, int nIndentCount)
        {
            Dump(pBufferToRead, new IntPtr(-1), nRange, nIndentCount);
        }


        public static void Dump(
            IntPtr pBufferToRead,
            IntPtr pBaseAddress,
            uint nRange,
            int nIndentCount)
        {
            IntPtr address;
            IntPtr pByteToRead;
            byte readByte;
            string addressFormat;
            string headFormat;
            string lineFormat;
            string indent = new string(' ', nIndentCount * 4);
            var hexBuffer = new StringBuilder();
            var charBuffer = new StringBuilder();

            if (pBaseAddress == new IntPtr(-1))
            {
                pBaseAddress = IntPtr.Zero;
                addressFormat = "X8";
                headFormat = string.Format("{{0}}{{1,{0}}}   {{2,-47}}\n", 8);
                lineFormat = string.Format("{{0}}{{1,{0}}} | {{2,-47}} | {{3}}", 8);
            }
            else
            {
                addressFormat = (IntPtr.Size == 8) ? "X16" : "X8";
                headFormat = string.Format("{{0}}{{1,{0}}}   {{2,-47}}\n", (IntPtr.Size * 2));
                lineFormat = string.Format("{{0}}{{1,{0}}} | {{2,-47}} | {{3}}", (IntPtr.Size * 2));
            }

            if (nRange > 0)
                Console.WriteLine(headFormat, indent, string.Empty, "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
            else
                return;

            for (var idx = 0; idx < nRange; idx++)
            {
                address = new IntPtr(pBaseAddress.ToInt64() + (idx & (~0x0Fu)));
                pByteToRead = new IntPtr(pBufferToRead.ToInt64() + idx);
                readByte = Marshal.ReadByte(pByteToRead);
                hexBuffer.Append(string.Format("{0}", readByte.ToString("X2")));

                if (IsPrintable((char)readByte))
                    charBuffer.Append((char)readByte);
                else
                    charBuffer.Append(".");

                if (((idx + 1) % 8 == 0) && ((idx + 1) % 16 != 0) && ((idx + 1) != nRange))
                {
                    hexBuffer.Append("-");
                    charBuffer.Append(" ");
                }
                else if (((idx + 1) % 16 != 0) && ((idx + 1) != nRange))
                {
                    hexBuffer.Append(" ");
                }

                if ((idx + 1) % 16 == 0)
                {
                    Console.WriteLine(
                        lineFormat,
                        indent,
                        address.ToString(addressFormat),
                        hexBuffer,
                        charBuffer);
                    hexBuffer.Clear();
                    charBuffer.Clear();
                }
                else if ((idx + 1) == nRange)
                {
                    Console.WriteLine(
                        lineFormat,
                        indent,
                        address.ToString(addressFormat),
                        hexBuffer,
                        charBuffer);
                    hexBuffer.Clear();
                    charBuffer.Clear();
                }
            }
        }


        private static bool IsPrintable(char code)
        {
            return (Char.IsLetterOrDigit(code) || Char.IsPunctuation(code) || Char.IsSymbol(code));
        }
    }
}
