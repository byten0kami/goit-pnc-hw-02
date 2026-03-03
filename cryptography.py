#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Криптографічне завдання: Шифрування тексту з передмови до "Портрета Доріана Ґрея"
Реалізація шифрів Віженера, перестановки та табличного шифру
"""

import re
from collections import Counter
import math


class VigenereCipher:
    """Шифр Віженера - поліалфавітний шифр підстановки"""

    def __init__(self, key):
        self.key = key.upper()

    def encrypt(self, plaintext):
        """Шифрування тексту"""
        ciphertext = []
        key_index = 0

        for char in plaintext:
            if char.isalpha():
                # Визначаємо базовий символ (A або a)
                base = ord('A') if char.isupper() else ord('a')
                # Шифруємо символ
                key_char = self.key[key_index % len(self.key)]
                shift = ord(key_char) - ord('A')
                encrypted_char = chr((ord(char) - base + shift) % 26 + base)
                ciphertext.append(encrypted_char)
                key_index += 1
            else:
                ciphertext.append(char)

        return ''.join(ciphertext)

    def decrypt(self, ciphertext):
        """Дешифрування тексту"""
        plaintext = []
        key_index = 0

        for char in ciphertext:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                key_char = self.key[key_index % len(self.key)]
                shift = ord(key_char) - ord('A')
                decrypted_char = chr((ord(char) - base - shift) % 26 + base)
                plaintext.append(decrypted_char)
                key_index += 1
            else:
                plaintext.append(char)

        return ''.join(plaintext)

    @staticmethod
    def kasiski_examination(ciphertext, min_length=3):
        """Метод Касіскі для визначення довжини ключа"""
        # Видаляємо всі символи крім букв
        text = ''.join(filter(str.isalpha, ciphertext.upper()))

        # Знаходимо повторювані послідовності
        sequences = {}
        for length in range(min_length, min(20, len(text) // 2)):
            for i in range(len(text) - length):
                seq = text[i:i + length]
                positions = []
                for j in range(i + length, len(text) - length + 1):
                    if text[j:j + length] == seq:
                        positions.append(j - i)
                if positions:
                    if seq not in sequences:
                        sequences[seq] = []
                    sequences[seq].extend(positions)

        # Знаходимо НСД відстаней
        if not sequences:
            return None

        distances = []
        for seq, dists in sequences.items():
            distances.extend(dists)

        if not distances:
            return None

        # Визначаємо найбільш ймовірну довжину ключа
        gcd_result = distances[0]
        for dist in distances[1:]:
            gcd_result = math.gcd(gcd_result, dist)

        return gcd_result

    @staticmethod
    def friedman_test(ciphertext):
        """Тест Фрідмана для визначення довжини ключа"""
        text = ''.join(filter(str.isalpha, ciphertext.upper()))
        n = len(text)

        # Підрахунок частот
        freq = Counter(text)

        # Обчислення індексу збігу
        ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

        # Оцінка довжини ключа
        # IC для англійської мови ≈ 0.065, для випадкового тексту ≈ 0.038
        key_length = (0.027 * n) / ((n - 1) * ic - 0.038 * n + 0.065)

        return round(key_length)


class TranspositionCipher:
    """Шифр перестановки - зміна порядку символів"""

    def __init__(self, key):
        self.key = key.upper()
        self.order = self._get_order()

    def _get_order(self):
        """Визначає порядок перестановки на основі ключа"""
        # Створюємо список кортежів (символ, індекс)
        sorted_key = sorted(enumerate(self.key), key=lambda x: x[1])
        # Повертаємо порядок індексів
        return [i for i, _ in sorted_key]

    def encrypt(self, plaintext):
        """Шифрування з простою перестановкою"""
        # Видаляємо пробіли для простоти
        text = plaintext.replace(' ', '')
        key_len = len(self.key)

        # Доповнюємо текст до кратності довжині ключа
        padding = (key_len - len(text) % key_len) % key_len
        text += 'X' * padding

        # Розбиваємо текст на блоки
        blocks = [text[i:i + key_len] for i in range(0, len(text), key_len)]

        # Переставляємо символи в кожному блоці
        ciphertext = []
        for block in blocks:
            encrypted_block = [''] * key_len
            for i, char in enumerate(block):
                encrypted_block[self.order[i]] = char
            ciphertext.append(''.join(encrypted_block))

        return ''.join(ciphertext)

    def decrypt(self, ciphertext):
        """Дешифрування"""
        key_len = len(self.key)
        blocks = [ciphertext[i:i + key_len] for i in range(0, len(ciphertext), key_len)]

        # Створюємо зворотний порядок
        reverse_order = [0] * key_len
        for i, pos in enumerate(self.order):
            reverse_order[pos] = i

        plaintext = []
        for block in blocks:
            decrypted_block = [''] * key_len
            for i, char in enumerate(block):
                decrypted_block[reverse_order[i]] = char
            plaintext.append(''.join(decrypted_block))

        return ''.join(plaintext).rstrip('X')


class DoubleTranspositionCipher:
    """Подвійний шифр перестановки"""

    def __init__(self, key1, key2):
        self.cipher1 = TranspositionCipher(key1)
        self.cipher2 = TranspositionCipher(key2)

    def encrypt(self, plaintext):
        """Подвійне шифрування"""
        temp = self.cipher1.encrypt(plaintext)
        return self.cipher2.encrypt(temp)

    def decrypt(self, ciphertext):
        """Подвійне дешифрування"""
        temp = self.cipher2.decrypt(ciphertext)
        return self.cipher1.decrypt(temp)


class TabularCipher:
    """Табличний шифр (Route Cipher)"""

    def __init__(self, key):
        self.key = key.upper()
        self.key_length = len(key)
        self.order = self._get_order()

    def _get_order(self):
        """Визначає порядок стовпців"""
        sorted_key = sorted(enumerate(self.key), key=lambda x: x[1])
        return [i for i, _ in sorted_key]

    def encrypt(self, plaintext):
        """Шифрування табличним методом"""
        # Видаляємо пробіли
        text = plaintext.replace(' ', '')

        # Визначаємо розмір таблиці
        num_rows = -(-len(text) // self.key_length)  # Округлення вгору

        # Доповнюємо текст
        padding = (num_rows * self.key_length) - len(text)
        text += 'X' * padding

        # Створюємо таблицю
        table = []
        for i in range(num_rows):
            row = list(text[i * self.key_length:(i + 1) * self.key_length])
            table.append(row)

        # Зчитуємо за стовпцями в порядку ключа
        ciphertext = []
        for col_index in self.order:
            for row in table:
                ciphertext.append(row[col_index])

        return ''.join(ciphertext)

    def decrypt(self, ciphertext):
        """Дешифрування"""
        num_rows = len(ciphertext) // self.key_length

        # Створюємо порожню таблицю
        table = [['' for _ in range(self.key_length)] for _ in range(num_rows)]

        # Заповнюємо таблицю за стовпцями в порядку ключа
        index = 0
        for col_index in self.order:
            for row in range(num_rows):
                table[row][col_index] = ciphertext[index]
                index += 1

        # Зчитуємо по рядках
        plaintext = []
        for row in table:
            plaintext.extend(row)

        return ''.join(plaintext).rstrip('X')


class CombinedCipher:
    """Комбінований шифр (Віженера + Табличний)"""

    def __init__(self, vigenere_key, tabular_key):
        self.vigenere = VigenereCipher(vigenere_key)
        self.tabular = TabularCipher(tabular_key)

    def encrypt(self, plaintext):
        """Шифрування: спочатку Віженера, потім табличний"""
        temp = self.vigenere.encrypt(plaintext)
        return self.tabular.encrypt(temp)

    def decrypt(self, ciphertext):
        """Дешифрування: спочатку табличний, потім Віженера"""
        temp = self.tabular.decrypt(ciphertext)
        return self.vigenere.decrypt(temp)


def main():
    """Головна функція для демонстрації всіх шифрів"""

    # Текст для шифрування
    wilde_text = """The artist is the creator of beautiful things. To reveal art and conceal the artist is art's aim. The critic is he who can translate into another manner or a new material his impression of beautiful things. The highest, as the lowest, form of criticism is a mode of autobiography. Those who find ugly meanings in beautiful things are corrupt without being charming. This is a fault. Those who find beautiful meanings in beautiful things are the cultivated. For these there is hope. They are the elect to whom beautiful things mean only Beauty. There is no such thing as a moral or an immoral book. Books are well written, or badly written. That is all. The nineteenth-century dislike of realism is the rage of Caliban seeing his own face in a glass. The nineteenth-century dislike of Romanticism is the rage of Caliban not seeing his own face in a glass. The moral life of man forms part of the subject matter of the artist, but the morality of art consists in the perfect use of an imperfect medium. No artist desires to prove anything. Even things that are true can be proved. No artist has ethical sympathies. An ethical sympathy in an artist is an unpardonable mannerism of style. No artist is ever morbid. The artist can express everything. Thought and language are to the artist instruments of an art. Vice and virtue are to the artist materials for an art. From the point of view of form, the type of all the arts is the art of the musician. From the point of view of feeling, the actor's craft is the type. All art is at once surface and symbol. Those who go beneath the surface do so at their peril. Those who read the symbol do so at their peril. It is the spectator, and not life, that art really mirrors. Diversity of opinion about a work of art shows that the work is new, complex, vital. When critics disagree the artist is in accord with himself. We can forgive a man for making a useful thing as long as he does not admire it. The only excuse for making a useless thing is that one admires it intensely. All art is quite useless."""

    print("=" * 80)
    print("КРИПТОГРАФІЧНЕ ЗАВДАННЯ: ШИФРУВАННЯ ТЕКСТУ ОСКАРА ВАЙЛЬДА")
    print("=" * 80)
    print()

    # ========================================================================
    # ЗАВДАННЯ 1: ШИФР ВІЖЕНЕРА
    # ========================================================================
    print("ЗАВДАННЯ 1: ШИФР ВІЖЕНЕРА")
    print("-" * 80)

    # Рівень 1: Шифрування та дешифрування
    print("\n[Рівень 1] Шифрування з ключем 'CRYPTOGRAPHY'")
    vigenere = VigenereCipher("CRYPTOGRAPHY")
    vigenere_encrypted = vigenere.encrypt(wilde_text)
    print(f"\nЗашифрований текст (перші 200 символів):")
    print(vigenere_encrypted[:200] + "...")

    vigenere_decrypted = vigenere.decrypt(vigenere_encrypted)
    print(f"\nДешифрований текст (перші 200 символів):")
    print(vigenere_decrypted[:200] + "...")

    # Перевірка
    if vigenere_decrypted == wilde_text:
        print("✓ Дешифрування успішне!")

    # Рівень 2: Криптоаналіз
    print("\n[Рівень 2] Криптоаналіз методом Касіскі та тестом Фрідмана")
    kasiski_length = VigenereCipher.kasiski_examination(vigenere_encrypted)
    friedman_length = VigenereCipher.friedman_test(vigenere_encrypted)
    print(f"Метод Касіскі - передбачувана довжина ключа: {kasiski_length}")
    print(f"Тест Фрідмана - передбачувана довжина ключа: {friedman_length}")
    print(f"Реальна довжина ключа 'CRYPTOGRAPHY': {len('CRYPTOGRAPHY')}")

    # ========================================================================
    # ЗАВДАННЯ 2: ШИФР ПЕРЕСТАНОВКИ
    # ========================================================================
    print("\n\n" + "=" * 80)
    print("ЗАВДАННЯ 2: ШИФР ПЕРЕСТАНОВКИ")
    print("-" * 80)

    # Рівень 1: Проста перестановка
    print("\n[Рівень 1] Проста перестановка з ключем 'SECRET'")
    transposition = TranspositionCipher("SECRET")
    trans_encrypted = transposition.encrypt(wilde_text)
    print(f"\nЗашифрований текст (перші 200 символів):")
    print(trans_encrypted[:200] + "...")

    trans_decrypted = transposition.decrypt(trans_encrypted)
    print(f"\nДешифрований текст (перші 200 символів):")
    print(trans_decrypted[:200] + "...")

    # Рівень 2: Подвійна перестановка
    print("\n[Рівень 2] Подвійна перестановка з ключами 'SECRET' та 'CRYPTO'")
    double_trans = DoubleTranspositionCipher("SECRET", "CRYPTO")
    double_encrypted = double_trans.encrypt(wilde_text)
    print(f"\nЗашифрований текст (перші 200 символів):")
    print(double_encrypted[:200] + "...")

    double_decrypted = double_trans.decrypt(double_encrypted)
    print(f"\nДешифрований текст (перші 200 символів):")
    print(double_decrypted[:200] + "...")

    # ========================================================================
    # ЗАВДАННЯ 3: ТАБЛИЧНИЙ ШИФР
    # ========================================================================
    print("\n\n" + "=" * 80)
    print("ЗАВДАННЯ 3: ТАБЛИЧНИЙ ШИФР")
    print("-" * 80)

    # Рівень 1: Табличний шифр
    print("\n[Рівень 1] Табличний шифр з ключем 'MATRIX'")
    tabular = TabularCipher("MATRIX")
    tabular_encrypted = tabular.encrypt(wilde_text)
    print(f"\nЗашифрований текст (перші 200 символів):")
    print(tabular_encrypted[:200] + "...")

    tabular_decrypted = tabular.decrypt(tabular_encrypted)
    print(f"\nДешифрований текст (перші 200 символів):")
    print(tabular_decrypted[:200] + "...")

    # Рівень 2: Комбінований шифр
    print("\n[Рівень 2] Комбінований шифр: Віженера ('CRYPTOGRAPHY') + Табличний ('CRYPTO')")
    combined = CombinedCipher("CRYPTOGRAPHY", "CRYPTO")
    combined_encrypted = combined.encrypt(wilde_text)
    print(f"\nЗашифрований текст (перші 200 символів):")
    print(combined_encrypted[:200] + "...")

    combined_decrypted = combined.decrypt(combined_encrypted)
    print(f"\nДешифрований текст (перші 200 символів):")
    print(combined_decrypted[:200] + "...")

    # ========================================================================
    # ЗБЕРЕЖЕННЯ РЕЗУЛЬТАТІВ
    # ========================================================================
    print("\n\n" + "=" * 80)
    print("ЗБЕРЕЖЕННЯ РЕЗУЛЬТАТІВ")
    print("-" * 80)

    results = {
        "vigenere": vigenere_encrypted,
        "transposition": trans_encrypted,
        "double_transposition": double_encrypted,
        "tabular": tabular_encrypted,
        "combined": combined_encrypted
    }

    for name, encrypted in results.items():
        filename = f"{name}_encrypted.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(encrypted)
        print(f"✓ Збережено: {filename}")

    print("\n" + "=" * 80)
    print("ЗАВДАННЯ ВИКОНАНО!")
    print("=" * 80)


if __name__ == "__main__":
    main()
