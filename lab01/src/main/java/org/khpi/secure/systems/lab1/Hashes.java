package org.khpi.secure.systems.lab1;

import org.apache.commons.collections4.ListUtils;
import org.khpi.secure.systems.utils.ByteUtils;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class Hashes {
    private static final List<Integer> HASH_CONSTANTS_64 = List.of(
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2);

    private Hashes() {}

    public static String sha256(String input) {
        List<Integer> hashConstants8 = new ArrayList<>(List.of(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19));

        byte[] inputByteArray = input.getBytes();
        byte[] sizeInBytesArray = longToBytes((long) inputByteArray.length * Long.BYTES);

        List<Byte> sizeInByteList = ByteUtils.toByteList(sizeInBytesArray);
        List<Byte> byteList = ByteUtils.toByteList(inputByteArray);
        byteList.add(Byte.MIN_VALUE);
        byteList.addAll(sizeInByteList);

        while (notMultipleOf512(byteList)) {
            byteList.add(byteList.size() - Long.BYTES, (byte) 0);
        }

        List<List<Byte>> batch512Bits = ListUtils.partition(byteList, Long.SIZE);

        for (List<Byte> list512Bit : batch512Bits) {

            List<Integer> words = ByteUtils.splitOnWords(list512Bit);

            while (words.size() != Long.SIZE) {
                words.add(0);
            }

            for (int i = 16; i < words.size(); i++) {
                int s0 = computeS0(words.get(i - 15));
                int s1 = computeS1(words.get(i - 2));

                words.set(i, words.get(i - 16) + s0 + words.get(i - 7) + s1);
            }

            int a = hashConstants8.get(0);
            int b = hashConstants8.get(1);
            int c = hashConstants8.get(2);
            int d = hashConstants8.get(3);
            int e = hashConstants8.get(4);
            int f = hashConstants8.get(5);
            int g = hashConstants8.get(6);
            int h = hashConstants8.get(7);

            for (int i = 0; i < words.size(); i++) {
                int compressVal1 = Integer.rotateRight(e, 6) ^ Integer.rotateRight(e, 11)
                        ^ Integer.rotateRight(e, 25);

                int ch = (e & f) ^ ((~e) & g);
                int temp1 = h + compressVal1 + ch + HASH_CONSTANTS_64.get(i) + words.get(i);

                int compressVal0 = Integer.rotateRight(a, 2) ^ Integer.rotateRight(a, 13)
                        ^ Integer.rotateRight(a, 22);

                int maj = (a & b) ^ (a & c) ^ (b & c);
                int temp2 = compressVal0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            hashConstants8.set(0, hashConstants8.get(0) + a);
            hashConstants8.set(1, hashConstants8.get(1) + b);
            hashConstants8.set(2, hashConstants8.get(2) + c);
            hashConstants8.set(3, hashConstants8.get(3) + d);
            hashConstants8.set(4, hashConstants8.get(4) + e);
            hashConstants8.set(5, hashConstants8.get(5) + f);
            hashConstants8.set(6, hashConstants8.get(6) + g);
            hashConstants8.set(7, hashConstants8.get(7) + h);
        }

        return hashConstants8.stream()
                .map(constant -> String.format("%08x", constant))
                .collect(Collectors.joining());
    }

    private static int computeS0(int word) {
        int rotatedBy7 = Integer.rotateRight(word, 7);
        int rotatedBy18 = Integer.rotateRight(word, 18);
        int shiftedBy3 = word >>> 3;

        return rotatedBy7 ^ rotatedBy18 ^ shiftedBy3;
    }

    private static int computeS1(int word) {
        int rotatedBy17 = Integer.rotateRight(word, 17);
        int rotatedBy19 = Integer.rotateRight(word, 19);
        int shiftedBy10 = word >>> 10;

        return rotatedBy17 ^ rotatedBy19 ^ shiftedBy10;
    }

    private static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }

    private static boolean notMultipleOf512(List<Byte> byteList) {
        return !multipleOf512(byteList);
    }

    private static boolean multipleOf512(List<Byte> byteList) {
        return byteList.size() * 8 % 512 == 0;
    }
}
