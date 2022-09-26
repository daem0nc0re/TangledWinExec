using System;
using System.Runtime.InteropServices;
using System.Text;

namespace ProcMemScan.Library
{
    internal class Hexdump
    {
        public static void Dump(byte[] data, int nIndentCount)
        {
            IntPtr pBufferToRead = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, pBufferToRead, data.Length);

            Dump(pBufferToRead, IntPtr.Zero, (uint)data.Length, nIndentCount);

            Marshal.FreeHGlobal(pBufferToRead);
        }


        public static void Dump(byte[] data, uint nRange, int nIndentCount)
        {
            IntPtr pBufferToRead = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, pBufferToRead, data.Length);

            Dump(pBufferToRead, IntPtr.Zero, nRange, nIndentCount);

            Marshal.FreeHGlobal(pBufferToRead);
        }


        public static void Dump(IntPtr pBufferToRead, uint nRange, int nIndentCount)
        {
            Dump(pBufferToRead, IntPtr.Zero, nRange, nIndentCount);
        }


        public static void Dump(
            IntPtr pBufferToRead,
            IntPtr pBaseAddress,
            uint nRange,
            int nIndentCount)
        {
            StringBuilder hexBuffer = new StringBuilder();
            StringBuilder charBuffer = new StringBuilder();
            string indent = new string(' ', nIndentCount * 4);
            IntPtr pByteToRead;
            byte readByte;
            IntPtr address = pBaseAddress;
            string addressFormat = (IntPtr.Size == 8) ? "X16" : "X8";

            for (var idx = 0; idx < nRange; idx++)
            {
                if (idx % 16 == 0)
                {
                    address = new IntPtr(pBaseAddress.ToInt64() + (idx & (~0x0Fu)));
                    hexBuffer.Clear();
                    charBuffer.Clear();
                }

                pByteToRead = new IntPtr(pBufferToRead.ToInt64() + idx);
                readByte = Marshal.ReadByte(pByteToRead);
                hexBuffer.Append(string.Format("{0}", readByte.ToString("X2")));

                if (IsPrintable((char)readByte))
                {
                    charBuffer.Append((char)readByte);
                }
                else
                {
                    charBuffer.Append(".");
                }

                if ((idx + 1) % 8 == 0 &&
                    (idx + 1) % 16 != 0 &&
                    (idx + 1) != nRange)
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
                    Console.WriteLine("{0}{1} | {2} | {3}",
                        indent, address.ToString(addressFormat), hexBuffer, charBuffer);
                }
                else if ((idx + 1) == nRange)
                {
                    Console.WriteLine("{0}{1} | {2,-47} | {3}",
                        indent, address.ToString("X8"), hexBuffer, charBuffer);
                }
            }
        }

        private static bool IsPrintable(char code)
        {
            return Char.IsLetterOrDigit(code) ||
                        Char.IsPunctuation(code) ||
                        Char.IsSymbol(code);
        }
    }
}
