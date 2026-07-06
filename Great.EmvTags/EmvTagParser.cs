using System;
using System.Collections.Generic;
using System.Text;

namespace Great.EmvTags
{
    public static class EmvTagParser
    {
        /// <summary>
        /// Delegate to handle multi-byte length tag in a custom manner. Return the index of the last byte of the length field.
        /// </summary>
        /// <param name="primaryLengthByte">The initial length byte of the multi-byte length field.</param>
        /// <param name="currentTagBytes">The current tag whose length data is being calculated.</param>
        /// <returns>The index of the last byte of the length field.</returns>
        public delegate int EmvTagMultiByteLengthDelegateCallback(byte primaryLengthByte, byte[] currentTagBytes);
        
        /// <summary>
        /// Some EMV readers may not follow the EMV standard for multi-byte length tags where bits 0-6 are used to indicate the number of subsequent length bytes.
        /// This delegate allows you to provide a custom handler for such cases. IDTech's EMV readers, for example, use bits 5 &amp; 6 for encryption and masking indicators and would otherwise
        /// completely throw off the length calculation.
        /// </summary>
        /// <example language="csharp">
        /// var tag5A = new byte[] { 0x5A };
        /// var tag57 = new byte[] { 0x57 };
        /// EmvTagParser.EmvTagMultiByteLengthHandler = (primaryLengthByte, currentTagBytes) =>
        /// {
        ///     int i = 0;
        ///     var specialTag = currentTagBytes.SequenceEqual(tag5A) || currentTagBytes.SequenceEqual(tag57);
        ///
        ///     if ((primaryLengthByte &amp; 0x40) == 0x40 &amp;&amp; specialTag)
        ///         i = primaryLengthByte - 0xC0; //Subtract to remove 11xx xxxx bits from the length byte to get the actual length of the length field
        ///     else if ((primaryLengthByte &amp; 0x20) == 0x20 &amp;&amp; specialTag)
        ///         i = primaryLengthByte - 0xA0; //Subtract to remove 1x1x xxxx bits from the length byte to get the actual length of the length field
        ///     else
        ///         i = primaryLengthByte - 0x80; //Subtract to remove 1xxx xxxx bits from the length byte to get the actual length of the length field
        ///
        ///     return i;
        /// };
        /// </example>
        public static EmvTagMultiByteLengthDelegateCallback EmvTagMultiByteLengthHandler { get; set; }
        
        public static EmvTlvList ParseDol(ExtendedByteArray rawDol)
        {
            EmvTlvList result = new EmvTlvList();
            int i = 0;
            while (i < rawDol.Bytes.Length && i != -1)
            {
                Tuple<int, EmvTlv> t = Parse(rawDol.Bytes, i, false);
                if (t.Item2 != null)
                    result.Add(t.Item2);

                i = t.Item1;
            }
            return result;
        }

        public static EmvTlv ParseTlv(ExtendedByteArray rawTlv)
        {
            return Parse(rawTlv.Bytes).Item2;
        }

        public static EmvTlvList ParseTlvList(ExtendedByteArray rawTlv)
        {
            EmvTlvList result = new EmvTlvList();
            int i = 0;
            while (i < rawTlv.Bytes.Length && i != -1)
            {
                Tuple<int, EmvTlv> t = Parse(rawTlv.Bytes, i);
                if (t.Item2 != null)
                    result.Add(t.Item2);

                i = t.Item1;
            }
            return result;
        }

        //private static ParseResult ParseTag(ref byte[] data, int position = 0)
        //{
        //    ParseResult r = new ParseResult();

        //    int start = position;
        //    int end = position;

        //    // 0x00 can be used as padding before, between, and after tags

        //    while (data[start].IsNullByte())
        //    {
        //        end = ++start;
        //    }

        //    if (data[start].IsMultiByteTag())
        //    {
        //        while (!data[++end].IsLastTagByte()) ;
        //    }

        //    int lengthOfTag = (end - start) + 1;
        //    byte[] tag = new byte[lengthOfTag];
        //    Array.Copy(data, start, tag, 0, lengthOfTag);



        //    return r;

        //}

        private static Tuple<int, EmvTlv> Parse(byte[] rawTlv, int offset = 0, bool parseValue = true)
        {
            EmvTlv tlv = null;

            // `start` and `i` represent cursors along our TLV data. We will move start
            // along until we find the start byte of our tag, length, or value. then
            // we will move i along until we find the end of it. Using their positions
            // we then extract that data, and push them forward one step to look for our
            // next tag, length, or value.

            // rawTlv: PPTTLLLVVVVVVVVPP
            //  start:     ^
            //      i:       ^

            for (int i = offset, start = offset; i < rawTlv.Length; start = i)
            {

                // 0x00 can be used as padding before, between, and after tags
                if (rawTlv[i].IsNullByte())
                {
                    i++;
                    continue;
                }


                // RETRIEVE TAG
                if (rawTlv[i].IsMultiByteTag())
                {
                    while (!rawTlv[++i].IsLastTagByte()) ;
                }

                int lengthOfTag = (i - start) + 1;
                byte[] tag = new byte[lengthOfTag];
                Array.Copy(rawTlv, start, tag, 0, lengthOfTag);
                start = ++i;


                // RETRIEVE LENGTH
                if (rawTlv[i].IsMultiByteLength())
                {
                    start++;

                    if (EmvTagMultiByteLengthHandler != null)
                        i += EmvTagMultiByteLengthHandler(rawTlv[i], tag);
                    else
                        i += rawTlv[i] - 0x80;
                }

                int lengthOfLength = (i - start) + 1;
                byte[] length = new byte[lengthOfLength];
                Array.Copy(rawTlv, start, length, 0, lengthOfLength);
                start = ++i;

                if(parseValue)
                {
                    // RETRIEVE VALUE
                    int lengthOfValue = length.ByteArrayToInt();
                    byte[] value = new byte[lengthOfValue];
                    Array.Copy(rawTlv, start, value, 0, lengthOfValue);
                    start = (i += lengthOfValue);


                    // build the tag!
                    tlv = new EmvTlv(tag, value);

                    // if this was a constructed tag, parse its value into individual Tlv children as well
                    if (tag[0].IsConstructedTag())
                    {
                        tlv.Children.AddRange(ParseTlvList(tlv.Value.Bytes));
                    }
                } 
                else
                {
                    // Not retrieving the value, just create the object (DOL parsing)
                    tlv = new EmvTlv(tag, length.ByteArrayToInt());
                }

                

                return new Tuple<int, EmvTlv>(start, tlv);
            }

            return new Tuple<int, EmvTlv>(-1, null);
        }
    }
}
