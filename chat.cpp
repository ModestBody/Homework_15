#include "chat.h"
#include "iostream"
#include "string.h"
#include "sha1.h"

Chat::Chat() {
    data_count = 0;
}

uint multiplyHash(const char* str, int length) {
    uint hash = 0;
    uint multiplier = 31; // Выбираем произвольный множитель

    for (int i = 0; i < length; ++i) {
        hash = hash * multiplier + static_cast<uint>(str[i]);
    }

    return hash;
}

int quadraticProbe(int index, int attempt, int size) {
    return (index + attempt * attempt) % size;
}

void Chat::reg(char _login[LOGINLENGTH], char _pass[], int pass_length) {
    if (data_count >= SIZE) {
        std::cerr << "Chat is full" << std::endl;
        return;
    }

    // Хешируем пароль
    uint* pass_hash = new uint[SHA1HASHLENGTHUINTS];
    sha1::calc(_pass, pass_length, pass_hash);

    // Получаем хеш логина
    uint login_hash = multiplyHash(_login, LOGINLENGTH);

    // Проверяем, не занят ли уже этот хеш
    int index = login_hash % SIZE;
    int attempt = 1;
    while (data[index].pass_sha1_hash != nullptr) {
        index = quadraticProbe(index, attempt++, SIZE);
    }

    // Добавляем пару логин-хеш в хеш-таблицу
    data[index] = AuthData(_login, pass_hash);
    data_count++;
}

bool Chat::login(char _login[LOGINLENGTH], char _pass[], int pass_length) {
    // Получаем хеш логина
    uint login_hash = multiplyHash(_login, LOGINLENGTH);

    // Проверяем, есть ли такой логин в хеш-таблице
    int index = login_hash % SIZE;
    int attempt = 1;
    while (data[index].pass_sha1_hash != nullptr) {
        if (strcmp(data[index].login, _login) == 0) {
            // Логин найден, проверяем пароль
            uint* pass_hash = new uint[SHA1HASHLENGTHUINTS];
            sha1::calc(_pass, pass_length, pass_hash);
            bool password_match = true;
            for (int i = 0; i < SHA1HASHLENGTHUINTS; ++i) {
                if (data[index].pass_sha1_hash[i] != pass_hash[i]) {
                    password_match = false;
                    break;
                }
            }
            delete[] pass_hash;
            if (password_match) {
                // Пароль совпадает, успешный вход
                return true;
            }
            else {
                // Пароль не совпадает
                return false;
            }
        }
        index = quadraticProbe(index, attempt++, SIZE);
    }

    // Логин не найден
    return false;
}


