package org.khpi.secure.systems.utils;

import org.apache.commons.collections4.ListUtils;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class ByteUtils {

    private ByteUtils() {}

    public static List<Byte> toByteList(byte[] bytesArray) {
        ArrayList<Byte> byteList = new ArrayList<>(bytesArray.length);

        for (byte value : bytesArray) {
            byteList.add(value);
        }

        return byteList;
    }

    public static byte[] toPrimitiveByteArray(List<Byte> byteList) {
        byte[] bytes = new byte[byteList.size()];
        for (int i = 0; i < byteList.size(); i++) {
            bytes[i] = byteList.get(i);
        }
        return bytes;
    }

    public static List<Integer> splitOnWords(List<Byte> byteList) {
        return new ArrayList<>(ListUtils.partition(byteList, Integer.BYTES)).stream()
                .map(ByteUtils::toPrimitiveByteArray)
                .map(ByteBuffer::wrap)
                .map(ByteBuffer::getInt)
                .collect(Collectors.toList());
    }
}
