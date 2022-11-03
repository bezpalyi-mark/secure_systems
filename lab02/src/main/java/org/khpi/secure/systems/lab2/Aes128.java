package org.khpi.secure.systems.lab2;

import org.apache.commons.collections4.ListUtils;
import org.khpi.secure.systems.utils.ByteUtils;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * AES/ECB/PKCS5Padding (128)
 */
public class Aes128 {
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

    private static final int BYTES_BLOCK_SIZE = 16;

    private static final int MATRIX_ROW_SIZE = 4;

    private Aes128() {}

    public static byte[] encrypt(String text, String key) {

        if (key.length() != BYTES_BLOCK_SIZE) {
            throw new IllegalArgumentException("Length of secret key should be 16 for 128 bits key size");
        }

        List<Byte> byteList = ByteUtils.toByteList(text.getBytes());

        List<List<Byte>> blocks = ListUtils.partition(byteList, 128 / Byte.SIZE);

        addPKCS5Padding(blocks);

        List<List<Byte>> roundKeys = getRoundKeys(key);

        List<List<Byte>> cipheredBlocks = new ArrayList<>();

        for (List<Byte> columnsBlock : blocks) {
            List<Byte> currentStateMatrix = addRoundKey(columnsBlock, roundKeys.get(0));

            for (int i = 0; i < 9; i++) {
                List<Byte> substituted = subBytes(currentStateMatrix);
                List<Byte> shifted = shiftRows(substituted);
                List<Byte> mixed = mixColumns(shifted);
                currentStateMatrix = addRoundKey(mixed, roundKeys.get(i + 1));
            }

            List<Byte> substituted = subBytes(currentStateMatrix);
            List<Byte> shifted = shiftRows(substituted);
            List<Byte> fullyEncoded = addRoundKey(shifted, roundKeys.get(10));

            cipheredBlocks.add(fullyEncoded);
        }

        List<Byte> bytes = cipheredBlocks.stream()
                .flatMap(Collection::stream)
                .collect(Collectors.toList());

        return ByteUtils.toPrimitiveByteArray(bytes);
    }

    private static List<List<Byte>> getRoundKeys(String key) {
        List<List<Byte>> result = new ArrayList<>();

        List<Byte> byteList = ByteUtils.toByteList(key.getBytes());

        for (int round = 0; round < 11; round++) {
            result.add(byteList);

            List<LinkedList<Byte>> words = ListUtils.partition(byteList, Integer.BYTES).stream()
                    .map(LinkedList::new)
                    .collect(Collectors.toList());

            LinkedList<Byte> w3 = new LinkedList<>(words.get(3));

            Byte firstByte = w3.poll();
            w3.addLast(firstByte);

            List<Byte> substituted = subBytes(w3);

            int addRConst = substituted.get(0) ^ ROUND_CONSTANTS[round];
            substituted.set(0, (byte) addRConst);

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

        return result;
    }

    private static List<Byte> subBytes(List<Byte> stateMatrix) {
        List<Integer> intValues = stateMatrix.stream()
                .map(bValue -> new byte[]{0, 0, 0, bValue})
                .map(ByteBuffer::wrap)
                .map(ByteBuffer::getInt)
                .collect(Collectors.toList());

        return intValues.stream()
                .map(S_BOX_TABLE::get)
                .map(Integer::byteValue)
                .collect(Collectors.toList());
    }

    private static List<Byte> addRoundKey(List<Byte> matrixColumns, List<Byte> roundKey) {
        List<Byte> result = new ArrayList<>();

        for (int i = 0; i < matrixColumns.size(); i++) {
            int added = matrixColumns.get(i) ^ roundKey.get(i);
            result.add((byte) added);
        }

        return result;
    }

    private static List<Byte> shiftRows(List<Byte> columnsValues) {
        List<Byte> rowsValues = changeLogicalDirection(columnsValues);

        List<List<Byte>> rows = ListUtils.partition(rowsValues, MATRIX_ROW_SIZE);

        List<List<Byte>> rotatedRows = new ArrayList<>();
        rotatedRows.add(rows.get(0));

        for (int i = 1; i < rows.size(); i++) {
            List<Byte> row = rows.get(i);

            int intValue = ByteBuffer.wrap(ByteUtils.toPrimitiveByteArray(row))
                    .getInt();

            int rotated = Integer.rotateLeft(intValue, i * Byte.SIZE);

            byte[] rotatedByteArray = ByteBuffer.allocate(Integer.BYTES).putInt(rotated).array();

            List<Byte> rotatedRow = ByteUtils.toByteList(rotatedByteArray);
            rotatedRows.add(rotatedRow);
        }

        List<Byte> rotatedValues = rotatedRows.stream()
                .flatMap(List::stream)
                .collect(Collectors.toList());

        return changeLogicalDirection(rotatedValues);
    }

    private static List<Byte> changeLogicalDirection(List<Byte> values) {
        List<Byte> viceVersaDirection = new ArrayList<>(values.size() / 4);
        List<List<Byte>> forwardDirection = ListUtils.partition(values, MATRIX_ROW_SIZE);

        for (int i = 0; i < MATRIX_ROW_SIZE; i++) {
            for (int j = 0; j < MATRIX_ROW_SIZE; j++) {
                Byte value = forwardDirection.get(j).get(i);
                viceVersaDirection.add(value);
            }

        }

        return viceVersaDirection;
    }

    private static List<Byte> mixColumns(List<Byte> values) {
        List<Byte> result = new ArrayList<>();
        List<List<Byte>> columns = ListUtils.partition(values, MATRIX_ROW_SIZE);

        columns.forEach(column -> {
            for (int i = 0; i < MATRIX_ROW_SIZE; i++) {
                int[] fixedMixMatrixRow = FIXED_MIX_MATRIX[i];
                List<Byte> rowValue = new ArrayList<>();

                for (int j = 0; j < column.size(); j++) {
                    byte mixedValue = gMul(column.get(j), fixedMixMatrixRow[j]);
                    rowValue.add(mixedValue);
                }

                Byte mixedValue = rowValue.stream()
                        .reduce((b1, b2) -> (byte) (b1 ^ b2))
                        .orElseThrow(() -> new IllegalStateException("There are no values for mixing columns"));

                result.add(mixedValue);
            }
        });

        return result;
    }

    private static byte gMul(byte matrixValue, int multiplier) {
        if (multiplier == 1) {
            return matrixValue;
        } else if (multiplier == 2) {
            return gMul2(matrixValue);
        } else if (multiplier == 3) {
            return gMul3(matrixValue);
        }

        throw new IllegalStateException("FIXED_MIX_MATRIX can include only following values: 1, 2 or 3");
    }

    private static byte gMul2(byte value) {
        int highBit = value & 0x80;
        int result = value << 1;

        if (highBit == 0x80) {
            result = result ^ 0x1b;
        }

        return (byte) result;
    }

    private static byte gMul3(byte value) {
        return (byte) (value ^ gMul2(value));
    }

    private static void addPKCS5Padding(List<List<Byte>> blocks) {

        int size = blocks.size();
        List<Byte> lastBlock = blocks.get(size - 1);

        int paddingData = BYTES_BLOCK_SIZE - lastBlock.size();

        while (lastBlock.size() != BYTES_BLOCK_SIZE) {
            lastBlock.add((byte) paddingData);
        }
    }
}
