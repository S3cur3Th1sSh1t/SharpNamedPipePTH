using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;

namespace SharpNamedPipePTH
{
    class Utilities
    {
        public static ushort DataLength(int length_start, byte[] string_extract_data)
        {
            byte[] bytes = { string_extract_data[length_start], string_extract_data[length_start + 1] };
            ushort string_length = BitConverter.ToUInt16(GetByteRange(string_extract_data, length_start, length_start + 1), 0);
            return string_length;
        }
        public static byte[] GetByteRange(byte[] array, int start, int end)
        {
            var newArray = array.Skip(start).Take(end - start + 1).ToArray();
            return newArray;
        }

        public static byte[] ConvertStringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static byte[] ConvertFromPacketOrderedDictionary(OrderedDictionary packet_ordered_dictionary)
        {
            List<byte[]> byte_list = new List<byte[]>();
            foreach (DictionaryEntry de in packet_ordered_dictionary)
            {
                byte_list.Add(de.Value as byte[]);
            }

            var flattenedList = byte_list.SelectMany(bytes => bytes);
            byte[] byte_Array = flattenedList.ToArray();

            return byte_Array;
        }
    }
}
