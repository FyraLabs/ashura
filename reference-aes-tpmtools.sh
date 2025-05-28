tpm2_createprimary -C o -G aes -g sha256 -c primary.ctx
# name-alg:
#   value: sha256
#   raw: 0xb
# attributes:
#   value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt
#   raw: 0x30072
# type:
#   value: symcipher
#   raw: 0x25
# sym-alg:
#   value: aes
#   raw: 0x6
# sym-mode:
#   value: null
#   raw: 0x10
# sym-keybits: 128
# symcipher: e7159fd463f4c9a8186db5fb469ab1bdfaf65c0ed8d4851e9638dee766e17a00


tpm2_create -C primary.ctx \
  -G aes128 \
  -u aes.pub \
  -r aes.priv

# name-alg:
#   value: sha256
#   raw: 0xb
# attributes:
#   value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign
#   raw: 0x60072
# type:
#   value: symcipher
#   raw: 0x25
# sym-alg:
#   value: aes
#   raw: 0x6
# sym-mode:
#   value: null
#   raw: 0x10
# sym-keybits: 128
# symcipher: 3299c92f2bf6b7c45b29f86d94e80a410b651df2475039c717c65dd7e43037a0

tpm2_load -C primary.ctx -u aes.pub -r aes.priv -c aes.ctx

echo "Hello world!" > test_data.txt

tpm2_encryptdecrypt -c aes.ctx -o data.enc -i data.in --encrypt

tpm2_encryptdecrypt -c aes.ctx -o data.out -i data.enc --decrypt