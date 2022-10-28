package org.khpi.secure.systems.lab2;

import org.apache.commons.collections4.ListUtils;
import org.khpi.secure.systems.utils.ByteUtils;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class AES {
    private static final List<Integer> S_BOX_TABLE = List.of(
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    );

    private static final int[] ROUND_CONSTANTS = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
            0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xed, 0xc5};

    private static final int[][] FIXED_MIX_MATRIX = {
            {2, 3, 1, 1},
            {1, 2, 3, 1},
            {1, 1, 2, 3},
            {3, 1, 1, 2}
    };

    private static final int MATRIX_ROW_SIZE = 4;

    public static String encrypt(String text, String key) {

        if (key.length() != 16) {
            throw new IllegalArgumentException("Length of secret key should be 16 for 128 bits key size");
        }

        List<Integer> byteList = ByteUtils.toByteList(text.getBytes()).stream()
                .map(bValue -> ByteBuffer.wrap(new byte[]{0, 0, 0, bValue}))
                .map(ByteBuffer::getInt)
                .collect(Collectors.toList());

        List<List<Integer>> blocks = ListUtils.partition(byteList, 128 / Byte.SIZE);
        List<List<Byte>> roundKeys = getRoundKeys(key);

        List<List<Integer>> cipheredBlocks = new ArrayList<>();

        for (List<Integer> columnsBlock : blocks) {
            addRoundKey(columnsBlock, roundKeys.get(0));
            List<Integer> result = null;

            for (int i = 0; i < 8; i++) {
                List<Integer> substituted = subBytes(columnsBlock);
                List<Integer> shifted = shiftRows(substituted);
                List<Integer> mixed = mixColumns(shifted);
                addRoundKey(mixed, roundKeys.get(i + 1));

                result = mixed;
            }

            Objects.requireNonNull(result);

            List<Integer> substituted = subBytes(result);
            List<Integer> shifted = shiftRows(substituted);
            addRoundKey(shifted, roundKeys.get(10));

            cipheredBlocks.add(shifted);
        }

        return cipheredBlocks.stream()
                .flatMap(List::stream)
                .map(intValue -> String.format("%02X", intValue))
                .collect(Collectors.joining());
    }

    private static List<List<Byte>> getRoundKeys(String key) {
        List<List<Byte>> result = new ArrayList<>();

        List<Byte> byteList = ByteUtils.toByteList(key.getBytes());

        for (int round = 0; round < 11; round++) {
            result.add(byteList);

            List<LinkedList<Byte>> words = ListUtils.partition(byteList, Integer.BYTES).stream()
                    .map(LinkedList::new)
                    .collect(Collectors.toList());

            LinkedList<Integer> w3 = words.get(3)
                    .stream()
                    .map(bValue -> ByteBuffer.wrap(new byte[]{0, 0, 0, bValue}))
                    .map(ByteBuffer::getInt)
                    .collect(Collectors.toCollection(LinkedList::new));

            Integer firstByte = w3.poll();
            w3.addLast(firstByte);

            List<Integer> substituted = subBytes(w3);

            int addRConst = substituted.get(0) ^ ROUND_CONSTANTS[round];
            substituted.set(0, addRConst);

            LinkedList<Byte> w4 = new LinkedList<>();
            LinkedList<Byte> w5 = new LinkedList<>();
            LinkedList<Byte> w6 = new LinkedList<>();
            LinkedList<Byte> w7 = new LinkedList<>();

            for (int i = 0; i < Integer.BYTES; i++) {
                w4.add((byte) (words.get(0).get(i) ^ substituted.get(i)));
                w5.add((byte) (w4.get(i) ^ words.get(1).get(i)));
                w6.add((byte) (w5.get(i) ^ words.get(2).get(i)));
                w7.add((byte) (w6.get(i) ^ words.get(3).get(i)));
            }

            w4.addAll(w5);
            w4.addAll(w6);
            w4.addAll(w7);

            byteList = new ArrayList<>(w4);
        }

        AtomicInteger i = new AtomicInteger(0);

        result.forEach(l -> {
            System.out.printf("Round %2d: ", i.getAndAdd(1));
            l.forEach(bValue -> System.out.printf("%02x ", bValue));
            System.out.println();
        });
        System.out.println();

        return result;
    }

    private static List<Integer> subBytes(List<Integer> stateMatrix) {
        return stateMatrix.stream()
                .map(S_BOX_TABLE::get)
                .collect(Collectors.toList());
    }

    private static void addRoundKey(List<Integer> matrixColumns, List<Byte> roundKey) {
        for (int i = 0; i < matrixColumns.size(); i++) {
            int added = matrixColumns.get(i) ^ roundKey.get(i);
            matrixColumns.set(i, added);
        }
    }

    private static List<Integer> shiftRows(List<Integer> columnsValues) {
        List<Integer> rowsValues = changeLogicalDirection(columnsValues);

        for (int i = 1; i < rowsValues.size(); i++) {
            Integer row = rowsValues.get(i);
            int rotated = Integer.rotateLeft(row, i);
            rowsValues.set(i, rotated);
        }

        List<Integer> byteRowsValues = new ArrayList<>(rowsValues.size() * Integer.BYTES);

        for (int row : rowsValues) {
            byte[] bytes = ByteBuffer.allocate(Integer.BYTES)
                    .putInt(row)
                    .array();

            ByteUtils.toByteList(bytes).stream()
                    .map(bValue -> ByteBuffer.wrap(new byte[]{0, 0, 0, bValue}))
                    .map(ByteBuffer::getInt)
                    .forEach(byteRowsValues::add);
        }

        return changeLogicalDirection(byteRowsValues);
    }

    private static List<Integer> changeLogicalDirection(List<Integer> values) {
        List<Integer> viceVersaDirection = new ArrayList<>(values.size() / 4);
        List<List<Integer>> forwardDirection = ListUtils.partition(values, MATRIX_ROW_SIZE);

        for (int i = 0; i < MATRIX_ROW_SIZE; i++) {
            for (int j = 0; j < MATRIX_ROW_SIZE; j++) {
                Integer value = forwardDirection.get(j).get(i);
                viceVersaDirection.add(value);
            }

        }

        return viceVersaDirection;
    }

    private static List<Integer> mixColumns(List<Integer> values) {
        List<Integer> result = new ArrayList<>();
        List<List<Integer>> columns = ListUtils.partition(values, MATRIX_ROW_SIZE);

        columns.forEach(column -> {
            for (int i = 0; i < MATRIX_ROW_SIZE; i++) {
                int[] fixedMixMatrixRow = FIXED_MIX_MATRIX[i];

                for (int j = 0; j < column.size(); j++) {
                    int mixedValue = fixedMixMatrixRow[j] ^ column.get(j);
                    result.add(mixedValue);
                }
            }
        });

        return result;
    }

    public static void main(String[] args) {

        System.out.println(getRoundKeys("Thats my Kung Fu"));
        System.out.println(getRoundKeys("I ♥ RadioGatun"));


        System.out.println(encrypt("Two One Nine Two", "Thats my Kung Fu"));
    }
}
