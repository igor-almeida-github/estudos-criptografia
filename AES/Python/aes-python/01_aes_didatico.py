"""
Essa é uma implementação "from scratch" da cifra AES-128
Implementação feita separando as etapas de criptografia add_round_key, sub_bytes, shift_rows e mix_columns.
Computacionalmente ineficiente, porém didático.

Verificar se é possível validar utilizando este site:
https://www.cryptool.org/en/cto/aes-step-by-step

Autor: Igor Goulart de Almeida (igor-almeida-github)
"""

# AES S-BOX Indexação [x][y]
AES_S_BOX = \
    (
        (0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76),
        (0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0),
        (0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15),
        (0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75),
        (0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84),
        (0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF),
        (0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8),
        (0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2),
        (0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73),
        (0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB),
        (0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79),
        (0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08),
        (0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A),
        (0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E),
        (0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF),
        (0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16)
    )


def aes_sub_bytes(byte: int) -> int:
    """
    Operação de substituição de bytes com a S-box
    :param byte: Byte a ser substituído (inteiro de 0 a 255)
    :return: Byte substituto
    """
    if not (0 <= byte <= 255):
        raise ValueError(f'Apenas um byte deve ser informado')

    x = (byte & 0xF0) >> 4
    y = byte & 0x0F

    return AES_S_BOX[x][y]


class AES128Key:

    def __init__(self, key: bytes) -> None:
        """
        :param key: chave de 128 bits
        """

        # Verifica se a chave informada é válida
        self.__check_aes_key(key)

        # Valor da chave original
        self.__key = key

        # Armazena as chaves de cada round obtidas por meio de Key Expansion
        self.__round_keys = self.__get_round_keys()

    @property
    def round_keys(self):
        """
        :return: Lista com as chaves de cada round [K0 ... K10]
        """
        return self.__round_keys

    def __get_round_keys(self) -> list:
        """
        Computa a expansão da chave AES-128
        :return: Lista com as chaves de cada round
        """
        round_keys = [self.__key]

        for current_round_number in range(0, 10):

            # Obtém a chave do round anterior
            current_key = round_keys[-1]

            # Obtém a chave do round seguinte
            next_key = self.__get_next_aes_key(current_key, current_round_number)

            # Adiciona a chave do round seguinte na lista de chaves
            round_keys.append(next_key)

        return round_keys

    def __get_next_aes_key(self, current_key: bytes, current_round_number: int) -> bytes:
        """
        Obtém a chave AES do round seguinte
        :param current_key: Chave atual
        :param current_round_number: Número do round da chave informada 0 ... 9
        :return: Chave AES do round seguinte
        """

        # Obtém as palavras da chave atual
        w0 = current_key[0:4]
        w1 = current_key[4:8]
        w2 = current_key[8:12]
        w3 = current_key[12:]

        # Aplica as transformações na última palavra da chave do round atual
        wxor = self.__aes_rot_word(w3)
        wxor = self.__aes_sub_word(wxor)
        wxor = self.__aes_rcon(wxor, current_round_number)

        # Obtém as palavas da chave do round seguinte
        w4 = self.__aes_word_xor(w0, wxor)
        w5 = self.__aes_word_xor(w1, w4)
        w6 = self.__aes_word_xor(w2, w5)
        w7 = self.__aes_word_xor(w3, w6)

        # Monta a chave do round seguinte
        next_key = b''.join((w4, w5, w6, w7))

        return next_key

    @classmethod
    def __aes_rot_word(cls, word32: bytes) -> bytes:
        """
        Rotaciona uma palavra um byte à esquerda
        :param word32: 4 bytes
        :return: 4 bytes rotacionados uma vez
        """
        cls.__aes_check_word_size(word32)
        return word32[1:] + word32[:1]

    @classmethod
    def __aes_sub_word(cls, word32: bytes) -> bytes:
        """
        Aplica a S-box do AES em cada byte da palavra
        :param word32: 4 bytes
        :return: 4 bytes substituídos
        """
        cls.__aes_check_word_size(word32)

        return b''.join(aes_sub_bytes(byte).to_bytes(1, byteorder='little') for byte in word32)

    @classmethod
    def __aes_rcon(cls, word32: bytes, current_round_number) -> bytes:
        """
        :param word32: 4 bytes
        :param current_round_number: Número do round atual (ex: se for de 0 para 1, colocar 0)
        :return: 4 bytes XOR com o RCON[j] do round atual
        """
        cls.__aes_check_word_size(word32)

        rcon_table = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)

        rcon_xor = word32[0] ^ rcon_table[current_round_number]
        rcon_xor = rcon_xor.to_bytes(1, byteorder='little')

        return rcon_xor + word32[1:]

    @classmethod
    def __aes_word_xor(cls, word32_1: bytes, word32_2: bytes) -> bytes:
        """
        Operação de XOR entre duas palavras de 4 bytes
        :param word32_1: primeira palavra de 4 bytes
        :param word32_2: segunda palavra de 4 bytes
        :return: word32_1 XOR word32_2
        """
        cls.__aes_check_word_size(word32_1)
        cls.__aes_check_word_size(word32_2)

        parts = []
        for b1, b2 in zip(word32_1, word32_2):
            parts.append(bytes([b1 ^ b2]))
        return b''.join(parts)

    @staticmethod
    def __check_aes_key(key: bytes):
        """
        Verifica se key é uma chave AES é válida e força um erro caso não seja
        :param key: Chave AES
        """
        # Verifica se a chave tem 128 bits
        if len(key) != 16:
            raise ValueError(f'Chave inválida. A chave informada tem {len(key)} bytes, porém 16 bytes são necessários')

    @staticmethod
    def __aes_check_word_size(word32):
        """
        Verifica se palavra de 32 bits possuí o tamanho correto
        :param word32: 4 bytes
        """
        if len(word32) != 4:
            raise ValueError(f'Palavra inválida. A palavra informada tem {len(word32)} bytes, porém '
                             f'4 bytes são necessários')


if __name__ == '__main__':
    aes_key = AES128Key(bytes.fromhex('1a 00 00 00   3e 00 00 00   00 00 00 00   00 00 00 00'))

    for r_key in aes_key.round_keys:
        print(r_key.hex())
