# Лабораторна робота №3

## Асиметричне шифрування

#### Виконав: Безпалий Марко Леонідович, КН-М922в

### Завдання:

Розробити додаток обміну таємними посиланнями між двома клієнтами за допомогою алгоритму шифрування RSA

* Реалізувати алгоритм генерації ключів (public / private keys) для алгоритму RSA. Створити ключі заданої довжини (напр.
  1024 біт)
* Реалізувати та продемонструвати роботу алгоритму шифрування та дешифрування повідомлення RSA
* Підтвердити роботу реалізованого алгоритму шляхом порівняння результату кодування з існуючим алгоритмом (наприклад,
  використовуючи утиліту openssl або вбудовані системи шифрування обраної мови програмування)

### Опис роботи:

Алгоритм асиметричного шифрування RSA потребує створення двох ключів: публічного та приватного.
Суть полягає в тому, що шифрування відбувається за допомогою публічного ключа, а це означає, що зашифрувати
повідомлення може кожен, хто має публічний ключ. Але розшифрувати може лише той, хто має приватний ключ.

Наприклад: ви заходите в месенджер, він одразу ж зв'язується з сервером, який генерує ключі, публічний відсилає вам, а
приватний залишається тільки в нього. Тож коли ви будете відсилати комусь повідомлення, месенджер зашифрує його
публічним ключем, що отримав від сервера. Тож якщо хтось перехопить ваше повідомлення, він не зможе його прочитати,
тому що воно зашифроване. Сервер отримує повідомлення, розшифровує його й зберігає (або що він там повинен робити).

Публічний і приватний ключі є функціями двох великих простих чисел розрядністю 100…200 десяткових цифр і навіть більше.
Відновлення відкритого тексту за шифротекстом та публічним ключем є рівнозначне до розкладання числа на два великі
прості множники.

Розглянемо алгоритм створення ключей. Пам'ятаємо, що вони залежні один від одного математичними законами, тому не можна
взяти публічний ключ з однієї пари та приватний з іншої пари.

### Обираємо два прості числа `p` та `q`

Для початку нам треба обрати два прості числа. Нехай це будуть `q = 61` та `p = 53`.

### Знаходимо модуль `n`

Далі знаходимо так званий "модуль" або `n`, який є добутком `q` та `p`. В нашому випадку `n = q * p = 61 * 53 = 3233`
Модуль є складовою частиною як публічного ключа, так і приватного.

### Обчислення функції Ейлера `Ф(n)`

Загалом Функція Ейлера `Ф(n)`, де `n` — натуральне число, — це цілочисельна функція, яка показує кількість натуральних
чисел, що не є більшими за `n` і є взаємно простими з ним.
Обрахувати функцію Ейлера можна за простою формулою `Ф(n) = (q - 1) * (p - 1)`.

В нашому випадку це: `(61 - 1) * (53 - 1) = 3120`

### Відкрита експонента `e`

Відкрита експонента це число, що є взаємно простим до `Ф(n)`, та виконує вимогу: `1 < e < Ф(n)`. Оберемо число 17.
Для того, щоб знайти взаємно просте число, треба було знайти прості числа менші за `Ф(n)`. З цією задачею чудово
справляється алгоритм під назвою "Решето Аткіна", асимптотична швидкість алгоритму — `O(N / log log(N))`.

### Секретна експонента `d`

Секретна експонента знаходиться за допомогою розширеного алгоритму Евкліда, оскільки, завдяки тому, що e та Ф(n) є
взаємно простими, зазначене рівняння є формою тотожності Безу, де d є одним із коефіцієнтів, та обчислюється за
наступною формулою:

`e * d ≡ 1 (mod Ф(n))`

На превеликий жаль, в ході роботи я не зміг опанувати цей метод. Але також відомо, що з формули вище витікає наступне
співвідношення:

`e * d = k * Ф(n) + 1`, де k - коефіцієнт, який можна знайти методом підбору, а вже потім знайти `d`.

В нашому випадку `d = 2753`

### Створення ключів

Публічний ключ складається з модуля та відкритої експоненти `(n, e)`, а приватний з модуля та приватної експоненти
`(n, d)`.

### Шифрування

Шифрування відбувається наступним чином:

* переводимо текст повідомлення в байти та складаємо з них число
* отримане число зводимо в ступінь `е` (відкрита експонента)
* отримуємо залишок від ділення результату на модуль `n`

Тобто це виглядає наступним чином `с = (p ^ e) mod n`, де `c` - зашифрований текст у вигляді числа, а `p` - початковий
текст у вигляді числа.

Нехай числове представлення `p` дорівнює `123`, тоді зашифрований текст дорівнює `(123 ^ 17) % 3233 = 855`

### Розшифрування

Розшифрування відбувається наступним чином:

* переводимо зашифрований текст повідомлення в байти та складаємо з них число
* отримане число зводимо в ступінь `d` (закрита експонента)
* отримуємо залишок від ділення результату на модуль `n`

Тобто це виглядає наступним чином `p = (с ^ d) mod n`, де `c` - зашифрований текст у вигляді числа, а `p` - початковий
текст у вигляді числа.

Розшифруємо текст із числовим представленням `855`: `(855 ^ 2753) % 3233 = 123`. Ми отримали початкове повідомлення.

### Довжина ключів

У реальному житті використовують ключі довжиною не менш ніж 1024 біт, а це означає, що наші початкові випадкові прості
числа мають в добутку давати таку ж довжину.

### Довжина повідомлення

Максимальна довжина повідомлення є довжиною публічного ключа, яка може бути 512 біт, 1024 біт і.д. З довжиною ключів, як
у прикладі ми зможемо зашифрувати лише 1 байт.

## Код

### Генерація ключів

````
public static RSAKeyPair generateKeys(int q, int p) {
    long n = (long) q * p;

    int phi = (q - 1) * (p - 1);

    int e = findCoPrime(phi);
    int d = -1;

    for (int k = 0; d < 0; k++) {
        int remainder = (1 + k * phi) % e;

        if (remainder == 0) {
            d = (1 + k * phi) / e;
        }
    }

    RSAPublicKey rsaPublicKey = new RSAPublicKey(BigInteger.valueOf(n), BigInteger.valueOf(e));
    RSAPrivateKey rsaPrivateKey = new RSAPrivateKey(BigInteger.valueOf(n), BigInteger.valueOf(d));

    return new RSAKeyPair(rsaPublicKey, rsaPrivateKey);
}
````

### Знаходження взаємно простих чисел для даного числа

````
private static int findCoPrime(int phi) {
    List<Integer> sieveOfAtkinPrimes = findSieveOfAtkinPrimes(phi);

    for (Integer prime : sieveOfAtkinPrimes) {
        if (gcdEuclidean(prime, phi) == 1) {
            return prime;
        }
    }

    throw new IllegalStateException("No one co-prime is found for number: " + phi);
}
````

В цьому методі ми спочатку знаходимо всі прості числа менші за `phi`, а потім знаходимо те число, що є взаємно простим,
тобто їхнє найбільше спільне кратне дорівнює 1.

### Найбільше спільне кратне

````
private static int gcdEuclidean(int a, int b) {
    int remainder = a % b;

    while (remainder > 0) {
        a = b;
        b = remainder;
        remainder = a % b;
    }

    return b;
}
````

НСК знаходиться за методом Евкліда: береться залишок `r` від ділення `a` на `b`. Потім ми знаходимо залишок від ділення
`b` на `r`. Тобто наші нові `a` та `b` - це `b` та `r` відповідно. Робимо це, поки `r > 0`. Повертаємо `b`.

## Ближче до реальності

### Генерація ключей

Мінімальна більш-менш безпечна довжина ключа повинна бути не менше 1024 біт, що дорівнює 128 байтів. У мові
програмування Java примітивні типи не можуть настільки довгі числа, тому використовується об'єктний тип `BigInteger`.

В ньому вже реалізовані такі методи, як `gcd` (greatest common divisor), `modInverse` для знаходження `d`, а також
методи `pow` та `mod` для зведення в ступінь та знаходження залишку від ділення, але є також метод `modPow`, який
виконує ці дії послідовно.

Далі для того, щоб створювати початкові прості числа з довжиною половини довжини ключа (в нашому випадку це 512 бітів),
використовується випадковий набір чисел потрібної довжини, які перевіряються на те, чи вони прості. Робиться це за
допомогою методу `BigInteger.probablePrime`, який як аргумент приймає довжину бітів числа та об'єкт типу `Random`, з
якого й буде "витягувати" випадкові числа.

В житті важливо, щоб зловмисники ніяк не могли перехопити генерацію випадкових чисел, адже тоді вони зможуть отримати
початкові `q` та `p` і легко зламати шифрування, тому в цій роботі ми використовуємо `SecureRandom` об'єкт, який
проводить криптографічно стійку генерацію випадкових чисел.

Реалізацію було розроблено на основі класів із бібліотеки `sun.security.rsa`. Загалом виходить наступний метод генерації
ключів (де `LENGTH` - константа, що дорівнює `1024`):

````
public static RSAKeyPair generateRSAKeys() {
    int lp = (LENGTH + 1) >> 1;
    int lq = LENGTH - lp;

    BigInteger n;
    BigInteger phi;

    do {
        BigInteger p = BigInteger.probablePrime(lp, new SecureRandom());
        BigInteger q = BigInteger.probablePrime(lq, new SecureRandom());

        n = p.multiply(q);

        BigInteger xMinusOne = p.subtract(BigInteger.ONE);
        BigInteger yMinusOne = q.subtract(BigInteger.ONE);

        phi = xMinusOne.multiply(yMinusOne);

    } while (!PUBLIC_EXPONENT.gcd(phi).equals(BigInteger.ONE));

    BigInteger d = PUBLIC_EXPONENT.modInverse(phi);

    RSAPublicKey rsaPublicKey = new RSAPublicKey(n, PUBLIC_EXPONENT);
    RSAPrivateKey rsaPrivateKey = new RSAPrivateKey(n, d);

    return new RSAKeyPair(rsaPublicKey, rsaPrivateKey);
}
````

### Що до відкритої експоненти `e`

Як можна побачити на попередньому блоці коду, `PUBLIC_EXPONENT` є константою, що дорівнює `65537`. Чому так?
RSA працює значно повільніше симетричних алгоритмів. Для підвищення швидкості шифрування відкритий показник `e`
вибирається невеликим, звичайно 3, 17 або 65537 (2 обрати не можна, бо `e`, повинно бути взаємно простим із Ф(n)).
Ці числа у двійковому вигляді містять тільки по дві одиниці, що зменшує число необхідних операцій множення при
зведенні в ступінь.

### Шифрування

````
public static byte[] encrypt(RSAPublicKey publicKey, byte[] msg) {

    if (msg.length > 128) {
        throw new IllegalArgumentException("Message length cannot be more than 128");
    }

    BigInteger integerMessage = new BigInteger(1, msg);
    BigInteger encrypted = integerMessage.modPow(publicKey.getE(), publicKey.getN());
    return encrypted.toByteArray();
}
````

Як вже було зазначено вище, використовується метод `modPow`.

### Розшифрування

````
public static byte[] decrypt(RSAPrivateKey privateKey, byte[] ciphered) {
    BigInteger msg = new BigInteger(1, ciphered);
    BigInteger decrypted = msg.modPow(privateKey.getD(), privateKey.getN());
    return decrypted.toByteArray();
}
````