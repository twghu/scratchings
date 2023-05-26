#include <iostream>
#include <string>
#include <vector>
#include "absl/strings/str_split.h"
#include "openssl/ssl.h"

static constexpr absl::string_view WhitespaceChars = " \t\f\v\n\r";
static char ciphers_string []  =
"[ECDHE-ECDSA-AES128-GCM-SHA256|ECDHE-ECDSA-CHACHA20-POLY1305]:[ECDHE-RSA-AES128-GCM-SHA256|ECDHE-RSA-CHACHA20-POLY1305]:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:AES256-GCM-SHA384:AES256-SHA]";


int set_strict_cipher_list(SSL_CTX* ctx, const char* str) {
    std::cout << "Processing string " << str << std::endl;
    if ( !SSL_CTX_set_cipher_list(ctx, str) ) {
        std::cout << "Error setting cipher list " << std::endl;
        return 0;
    }

    STACK_OF(SSL_CIPHER)* ciphers = SSL_CTX_get_ciphers(ctx);
    char* dup = strdup(str);
    char* token = std::strtok(dup, ":+![|]");
    while (token != NULL) {
        std::string str1(token);
        bool found = false;
        for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
            const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);
            std::string str2(SSL_CIPHER_get_name(cipher));
            if (str1.compare(str2) == 0) {
                found = true;
            }
        }

        if (!found && str1.compare("-ALL") && str1.compare("ALL")) {
            free(dup);
            return 0;
        }

        token = std::strtok(NULL, ":[]|");
    }

    free(dup);
    return 1;
}

absl::string_view ltrim(absl::string_view source) {
    const absl::string_view::size_type pos = source.find_first_not_of(WhitespaceChars);
    if (pos != absl::string_view::npos) {
        source.remove_prefix(pos);
    } else {
        source.remove_prefix(source.size());
    }
    return source;
}

absl::string_view rtrim(absl::string_view source) {
    const absl::string_view::size_type pos = source.find_last_not_of(WhitespaceChars);
    if (pos != absl::string_view::npos) {
        source.remove_suffix(source.size() - pos - 1);
    } else {
        source.remove_suffix(source.size());
    }
    return source;
}

absl::string_view trim(absl::string_view source) { return ltrim(rtrim(source)); }

std::vector<absl::string_view> splitToken(absl::string_view source,
                                          absl::string_view delimiters,
                                          bool keep_empty_string = false,
                                          bool trim_whitespace = false) {
    std::vector<absl::string_view> result;

    if (keep_empty_string) {
        result = absl::StrSplit(source, absl::ByAnyChar(delimiters));
    } else {
        if (trim_whitespace) {
            result = absl::StrSplit(source, absl::ByAnyChar(delimiters), absl::SkipWhitespace());
        } else {
            result = absl::StrSplit(source, absl::ByAnyChar(delimiters), absl::SkipEmpty());
        }
    }

    if (trim_whitespace) {
        for_each(result.begin(), result.end(), [](auto& v) { v = trim(v); });
    }
    return result;
}

int main() {
    {
        auto list = strdup(ciphers_string);
        auto ciphers = splitToken(list, ":+![|]", false);

        for (const auto &cipher: ciphers) {
            std::string cipher_str(cipher);
            std::cout << "split: " << cipher_str << std::endl;
        }
        free(list);
    }

    {
        auto list = strdup(ciphers_string);
        // try strtok
        char *token = std::strtok(list, ":+![|]");
        while (token != NULL) {
            std::cout << "strtok: " << token << std::endl;
            token = std::strtok(NULL, ":[]|");
        }
        free(list);
    }

    // try a SSL_CTX
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    if ( ctx == NULL ) {
        std::cout << "Unable to initialize SSL_CTX" << std::endl;
    }
    else {
        auto list = strdup(ciphers_string);

        int result = set_strict_cipher_list(ctx, list);
        std::cout << "set_string_cipher_list returned " << result << std::endl;
        SSL_CTX_free(ctx);

        free(list);
    }
}
