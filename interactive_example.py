#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Інтерактивні приклади використання шифрів
Цей файл можна використовувати для тестування окремих шифрів
"""

from cryptography import (
    VigenereCipher,
    TranspositionCipher,
    DoubleTranspositionCipher,
    TabularCipher,
    CombinedCipher
)


def example_vigenere():
    """Приклад використання шифру Віженера"""
    print("\n" + "="*60)
    print("ПРИКЛАД: Шифр Віженера")
    print("="*60)

    # Створюємо шифр з ключем
    cipher = VigenereCipher("CRYPTOGRAPHY")

    # Ваш текст для шифрування
    my_text = "Hello World! This is a secret message."

    print(f"\nОригінальний текст: {my_text}")

    # Шифруємо
    encrypted = cipher.encrypt(my_text)
    print(f"Зашифрований текст: {encrypted}")

    # Дешифруємо
    decrypted = cipher.decrypt(encrypted)
    print(f"Дешифрований текст: {decrypted}")

    # Перевірка
    print(f"\n✓ Співпадає з оригіналом: {decrypted == my_text}")


def example_transposition():
    """Приклад використання шифру перестановки"""
    print("\n" + "="*60)
    print("ПРИКЛАД: Шифр перестановки")
    print("="*60)

    cipher = TranspositionCipher("SECRET")

    my_text = "This is a secret message"

    print(f"\nОригінальний текст: {my_text}")

    encrypted = cipher.encrypt(my_text)
    print(f"Зашифрований текст: {encrypted}")

    decrypted = cipher.decrypt(encrypted)
    print(f"Дешифрований текст: {decrypted}")


def example_double_transposition():
    """Приклад подвійної перестановки"""
    print("\n" + "="*60)
    print("ПРИКЛАД: Подвійна перестановка")
    print("="*60)

    cipher = DoubleTranspositionCipher("SECRET", "CRYPTO")

    my_text = "Top secret information"

    print(f"\nОригінальний текст: {my_text}")

    encrypted = cipher.encrypt(my_text)
    print(f"Зашифрований текст: {encrypted}")

    decrypted = cipher.decrypt(encrypted)
    print(f"Дешифрований текст: {decrypted}")


def example_tabular():
    """Приклад табличного шифру"""
    print("\n" + "="*60)
    print("ПРИКЛАД: Табличний шифр")
    print("="*60)

    cipher = TabularCipher("MATRIX")

    my_text = "Meet me at midnight"

    print(f"\nОригінальний текст: {my_text}")

    encrypted = cipher.encrypt(my_text)
    print(f"Зашифрований текст: {encrypted}")

    decrypted = cipher.decrypt(encrypted)
    print(f"Дешифрований текст: {decrypted}")


def example_combined():
    """Приклад комбінованого шифру"""
    print("\n" + "="*60)
    print("ПРИКЛАД: Комбінований шифр (Віженера + Табличний)")
    print("="*60)

    cipher = CombinedCipher("CRYPTOGRAPHY", "CRYPTO")

    my_text = "The treasure is buried under the old oak tree"

    print(f"\nОригінальний текст: {my_text}")

    encrypted = cipher.encrypt(my_text)
    print(f"Зашифрований текст: {encrypted}")

    decrypted = cipher.decrypt(encrypted)
    print(f"Дешифрований текст: {decrypted}")


def example_cryptanalysis():
    """Приклад криптоаналізу"""
    print("\n" + "="*60)
    print("ПРИКЛАД: Криптоаналіз шифру Віженера")
    print("="*60)

    # Створюємо невідомий шифр
    unknown_key = "SECRETKEY"
    cipher = VigenereCipher(unknown_key)

    # Довгий текст для аналізу
    long_text = """
    The quick brown fox jumps over the lazy dog. The quick brown fox jumps
    over the lazy dog. The quick brown fox jumps over the lazy dog. The quick
    brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy
    dog. The quick brown fox jumps over the lazy dog.
    """ * 3

    encrypted = cipher.encrypt(long_text)

    print(f"Реальна довжина ключа: {len(unknown_key)}")

    # Спробуємо визначити довжину ключа
    kasiski_length = VigenereCipher.kasiski_examination(encrypted)
    friedman_length = VigenereCipher.friedman_test(encrypted)

    print(f"\nМетод Касіскі передбачає довжину: {kasiski_length}")
    print(f"Тест Фрідмана передбачає довжину: {friedman_length}")

    if kasiski_length == len(unknown_key):
        print("✓ Метод Касіскі точно визначив довжину ключа!")

    if abs(friedman_length - len(unknown_key)) <= 2:
        print("✓ Тест Фрідмана близький до реальної довжини!")


def custom_example():
    """Шифрування власного тексту"""
    print("\n" + "="*60)
    print("ВАШЕ ВЛАСНЕ ПОВІДОМЛЕННЯ")
    print("="*60)

    print("\nВведіть ваш текст для шифрування:")
    print("(або натисніть Enter для використання тексту за замовчуванням)")

    user_text = input("> ").strip()

    if not user_text:
        user_text = "This is my secret message for cryptography class!"

    print("\nВиберіть ключ (або натисніть Enter для 'CRYPTOGRAPHY'):")
    user_key = input("> ").strip().upper()

    if not user_key:
        user_key = "CRYPTOGRAPHY"

    print("\nВиберіть шифр:")
    print("1. Шифр Віженера")
    print("2. Шифр перестановки")
    print("3. Табличний шифр")
    print("4. Комбінований шифр")

    choice = input("> ").strip()

    print("\n" + "-"*60)

    if choice == "1":
        cipher = VigenereCipher(user_key)
        cipher_name = "Віженера"
    elif choice == "2":
        cipher = TranspositionCipher(user_key)
        cipher_name = "перестановки"
    elif choice == "3":
        cipher = TabularCipher(user_key)
        cipher_name = "табличний"
    elif choice == "4":
        cipher = CombinedCipher(user_key, "MATRIX")
        cipher_name = "комбінований"
    else:
        print("Невірний вибір. Використовується шифр Віженера.")
        cipher = VigenereCipher(user_key)
        cipher_name = "Віженера"

    encrypted = cipher.encrypt(user_text)
    decrypted = cipher.decrypt(encrypted)

    print(f"\nШифр: {cipher_name}")
    print(f"Ключ: {user_key}")
    print(f"\nОригінал:      {user_text}")
    print(f"Зашифровано:   {encrypted}")
    print(f"Дешифровано:   {decrypted}")
    print(f"\n✓ Перевірка: {decrypted == user_text or decrypted.replace(' ', '') == user_text.replace(' ', '')}")


def main():
    """Головне меню"""
    while True:
        print("\n" + "="*60)
        print("ІНТЕРАКТИВНІ ПРИКЛАДИ КРИПТОГРАФІЇ")
        print("="*60)
        print("\nВиберіть приклад:")
        print("1. Шифр Віженера")
        print("2. Шифр перестановки")
        print("3. Подвійна перестановка")
        print("4. Табличний шифр")
        print("5. Комбінований шифр")
        print("6. Криптоаналіз")
        print("7. Зашифрувати власний текст")
        print("8. Показати всі приклади")
        print("0. Вийти")

        choice = input("\n> ").strip()

        if choice == "1":
            example_vigenere()
        elif choice == "2":
            example_transposition()
        elif choice == "3":
            example_double_transposition()
        elif choice == "4":
            example_tabular()
        elif choice == "5":
            example_combined()
        elif choice == "6":
            example_cryptanalysis()
        elif choice == "7":
            custom_example()
        elif choice == "8":
            example_vigenere()
            example_transposition()
            example_double_transposition()
            example_tabular()
            example_combined()
            example_cryptanalysis()
        elif choice == "0":
            print("\nДо побачення!")
            break
        else:
            print("\nНевірний вибір. Спробуйте ще раз.")

        input("\nНатисніть Enter для продовження...")


if __name__ == "__main__":
    main()
