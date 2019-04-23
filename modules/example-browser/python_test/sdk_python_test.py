
import binascii
import base64

from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider, RawMasterKey

from aws_encryption_sdk import encrypt, decrypt

fromBrowser = 'AYAAFGVNaGnMMCa8VuZcEaWzN6cAAAABABNXRUItQ1JZUFRPLVJTQS1PQUVQACg4Q0VEMkZEMjBGQzg4QTlDMDZFRkRCMDczNzA3RUIxRUYxNjU1NzgwAQBz3EkIH1lTOcfIVfeXFVdXDG/hG1ce5VKkDN8m5cR/XMAVl9uX1i1IT7PiMDpSWM/U4I8BovvInyaEmkIHkvZ7hYnHp2MINogKPt4JF2saa3KQFTgLYSzWsABq1xvQGhcKspdh4v6XM8Bv8JwLOTt7OIMuvEZrLmoy05uK2M8Tcv1bfisL5SKeeagiYXKjKDQ1F2end6VHV6a1ClO+8EH/16g/Fw07Q0FkkYvjaZ4QVYOtFce3Tba0kV33DsxuM/sbEn53A+ILPX7CH8fiVsWcBfygLUxGDZ6R6dXCy2xPaKfr5WTGXrtwO9TscCXVBG4hX3PjmDpN8BhUg2LN7J1cAgAAAAAMAAAABgAAAAAAAAAAAAAAAC6ASPz9MRZkdKKjrCT1VR//////AAAAAQAAAAAAAAAAAAAAAQAAAAUJA9NjAjglR570QddFhD+1syLEOR4='
browserCipherBlob = base64.b64decode(fromBrowser)

public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6k/jrxg7mpz7CzgAr6eR
qJr1VlvjJ9uQY71hadkDZkLLZHiMl7hz73lqq3w2MfHCa3Pf3BVo5TCXGYuxKOlP
b7bH0WWpMeAzOKR/X27UqfA8MBVGb4YO5HXqw0jup8+I+Zi3CQAmP87uE6GDuh7x
zeAcwpGD5xE0N74+uWq3YS92PFHCavtryx+ad9VGTgfAbkV3k1+RSxIiZjzbAt3e
xBAn5EjMfF6FMI70/HYqO+5xGv/aAPSa1OMc/buK5QACN7gmFwqHBzw98v93iyGU
c4/XJNL+jPzKNP4AT1zMc6p6RxF3SYytNq7iXIjUmm+oY8fvCSmT1F13XKdzv7DL
OwIDAQAB
-----END PUBLIC KEY-----
""".encode('utf-8')


private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDqT+OvGDuanPsL
OACvp5GomvVWW+Mn25BjvWFp2QNmQstkeIyXuHPveWqrfDYx8cJrc9/cFWjlMJcZ
i7Eo6U9vtsfRZakx4DM4pH9fbtSp8DwwFUZvhg7kderDSO6nz4j5mLcJACY/zu4T
oYO6HvHN4BzCkYPnETQ3vj65ardhL3Y8UcJq+2vLH5p31UZOB8BuRXeTX5FLEiJm
PNsC3d7EECfkSMx8XoUwjvT8dio77nEa/9oA9JrU4xz9u4rlAAI3uCYXCocHPD3y
/3eLIZRzj9ck0v6M/Mo0/gBPXMxzqnpHEXdJjK02ruJciNSab6hjx+8JKZPUXXdc
p3O/sMs7AgMBAAECggEAXcAlS3OYtZ5F3BFGRQH5B8soiqstUk9JkH6/sUhBUfM7
yjFpn3MQACtGgOKsFIO01KWCVl7Cn6E3c+MuuT3QqNQrUx8n+WrJU8qNpDOGJ5CV
pG9+xTSQVNzRV92gj8g7+BIgehtzMmirXXNsb1XeTg9zsm3iptt9VyhplGqcgOdm
m72sT1Z8ZmkagaElHSg0dR1ZNGgzSfTtRg/J1tTh7cmFb1LVz069o6cRaa5ueOPN
KxmEslBdVWsDo9naxd/keLiqOOMIQp+KlLuQ+Zhn5fZyqxkRPGjTKZZHitgurzfW
G4ERjjrYCbZsOjEt9Tj8FXXUB8bd3qRPy5UkN+XLEQKBgQD10a4HAQN44cXAn8BB
ccFa7ndu/8vX/2WHZf40QE7UHtgyFha7acypcS8unC8+rIFfBae4918aq7oEe/bZ
EMAXsu7+hSyGr713NLAXFoLk9DY3C0efPT7PCETMITdDD23rf85dfzuCOnm/Lpzl
u9vcH0RtlTfdd/2epUQmHMWt5QKBgQD0BDShiFy0FsW4i7iO3UcGapAYYAQJuFAA
zDfbgxfylVSDoY60XRfzbaISyrtoh9jy7mdNa7WQqXqzzhRLXIgjSwmZbYmPvbav
lVgMivGTnH+YtDqNeZ+4faSX4u/OjpochWQMsgr4ho+3m15LAbvVB8A8OBHp2sgC
5IWclnYCnwKBgFfEGHVpuDqlqXxfzT3Qhq+Xqs7Xx4kEJ9TS5pLzTvHPXXNsjYs2
eBsbTTRAEWI4JyytETgqIiucmprVQ8o2f882VLxNAhvIjUYNar2jjPJ/+wdmIJlL
PayfkCitx1RLIvzNMfoR3kZd6HAJDX28t//8rerONxb8q3HEIfPVnAK9AoGANT5l
rYlvkOwXIHl8P9AQm1nNL0RkHSrWahYlagRkyU3ELySlWr2laDxXzPnngpuBvyA9
8iq6Z2JTn8ArtXXvTqQk6BF6np6qqg1QNQxsQeU4Aj3xOMV9EGh57Zpa8Rs0jVyd
xBdlRW03Fr0UChHKxmT2kS0622gdlGQAs3YxMckCgYEAmfoT9tmXPhLBanX5Mg76
pO21NAXR1aAQ76tS1/hJZYxP8iZtmlEdvvAMIdSibvIt7Gfi60rBPnxqmmKuitJf
zIVCd4sVLjIVEjT/njjLAzU+NTQdGugPCWWo8jB8NyeFy6nrZa/Hy52ijBn+Xt5G
8pzvz5lF5gRfCe09y14oNeQ=
-----END RSA PRIVATE KEY-----
""".encode('utf-8')

key_id = '8CED2FD20FC88A9C06EFDB073707EB1EF1655780'

wrappingPublic = WrappingKey(
  wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA1_MGF1,
  wrapping_key=public_key,
  wrapping_key_type=EncryptionKeyType.PUBLIC
)

public = RawMasterKey(
  provider_id = 'WEB-CRYPTO-RSA-OAEP',
  key_id = key_id,
  wrapping_key = wrappingPublic
)

wrappingPrivate = WrappingKey(
  wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA1_MGF1,
  wrapping_key=private_key,
  wrapping_key_type=EncryptionKeyType.PRIVATE
)

private = RawMasterKey(
  provider_id = 'WEB-CRYPTO-RSA-OAEP',
  key_id = key_id,
  wrapping_key = wrappingPrivate
)

raw = 'asdfasdfasdfasdf'

my_ciphertext, encryptor_header = encrypt(
  source= raw.encode('utf-8'),
  key_provider=public
)

decrypted_plaintext, decryptor_header = decrypt(
  source=my_ciphertext,
  key_provider=private
)

decrypted_browser, decryptor_header = decrypt(
  source=browserCipherBlob,
  key_provider=private
)
print('decrypted:', decrypted_browser)
