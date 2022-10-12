package org.khpi.safe.systems.lab1;

public class Lab1App {
    public static void main(String[] args) {
        String result = Hashes.sha256("hello world one two three four");
        System.out.println(result);
    }
}
