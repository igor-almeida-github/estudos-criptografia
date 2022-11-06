"""
Essa é uma implementação "from scratch" da cifra AES-128
Implementação feita separando as etapas de criptografia add_round_key, sub_bytes, shift_rows e mix_columns.
Computacionalmente ineficiente, porém didático.

Verificar se é possível validar utilizando este site:
https://www.cryptool.org/en/cto/aes-step-by-step

"""


class AES128Key:
    def __init__(self, key: bytes) -> None:
        """
        :param key: chave de 128 bits
        """

        # Verifica se a chave tem 128 bits
        if len(key) != 16:
            raise ValueError(f'Chave inválida. A chave informada tem {len(key)} bytes, porém 16 bytes são necessários')

        # Valor imutável da chave original
        self.__key = key

        # Armazena as chaves de cada round obtidas por meio de Key Expansion
        self.__round_keys = self.__get_round_keys()

    def __get_round_keys(self) -> list:

        round_keys = [self.__key]

        while len(round_keys) < 11:
            last_key = round_keys[-1]
            next_key = self.__get_next_aes_key(last_key)
            round_keys.append(next_key)

        return round_keys

    @staticmethod
    def __get_next_aes_key(last_key: bytes) -> bytes:
        return last_key


if __name__ == '__main__':
    AES128Key(bytes(16))
