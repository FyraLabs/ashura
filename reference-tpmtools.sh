# Shell script to reference for tpm code, we want to mimic this to
# seal/unseal data in ashura

# One-time setup (creates the key files)
tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx

# name-alg:
#   value: sha256
#   raw: 0xb
# attributes:
#   value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt
#   raw: 0x30072
# type:
#   value: rsa
#   raw: 0x1
# exponent: 65537
# bits: 2048
# scheme:
#   value: null
#   raw: 0x10
# scheme-halg:
#   value: (null)
#   raw: 0x0
# sym-alg:
#   value: aes
#   raw: 0x6
# sym-mode:
#   value: cfb
#   raw: 0x43
# sym-keybits: 128
# rsa: df4ed3ff726bbaf845accb97b4e24f0dc82053b2b40ce6e14ce8f0e786abc8993acca703a0dea3105bdd3c37e50a02f6e97e68348213de487e26b8109130a01ba6cff6b0fd32418ea492b2ab44d9b0bc52dc5c421e43643096c87322458d7e78b45f653c6d593c1e8a4ba4804efdfcdd116f5634b5d4406897fd3565ae5619d625890a5a675d8af615492cd7d1a84d8e00967ae35cf628b476f627974784edca42e7d59914043ed4cf83b880aa644da3a1701ccfce2fef4e1ab84dc5890811d290367c23639f53a923dd2a986937c428893f4cc8329c0e9545bc4740111d1c1a7f68df23fd6d975cc3e19de23339f711bab2526478230524eba3a58dfa79fbcd

tpm2_create -G rsa2048:rsaes -g sha256 -u rsa.pub -r rsa.priv -C primary.ctx
#
# name-alg:
#   value: sha256
#   raw: 0xb
# attributes:
#   value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt
#   raw: 0x20072
# type:
#   value: rsa
#   raw: 0x1
# exponent: 65537
# bits: 2048
# scheme:
#   value: rsaes
#   raw: 0x15
# sym-alg:
#   value: null
#   raw: 0x10
# sym-mode:
#   value: (null)
#   raw: 0x0
# sym-keybits: 0
# rsa: c717cd8f3ca9b413ec31a815ff04ad6eb373c924f8e360e25cf61f452db2fc72e73cf949255650c3fb39a8951f05b45b9d30b6469c912e30fa25ddfe5bf16fd9e70357610f3ce07e92d59797a649b47f2059edc5a38d1a99e04f7494247275037b8d2ed5183c54925fe78ce746d3bdf22cd8558d08bb0d6ac06d8efe2b452cd6aeb3007ab1195525a091d637d8093d546ce319e426baea3cd71331b9bad6c01c02f8b683d82a73d497cb17e9a4c66e70e57c1f8171de6b3bb7146c192f0eaabd06ba7889a6f781acd7037efc9de83af59b4caef6cf768a80188bf04d85f1783908bc8a90eaed80924283b6114bf9428feff9cc10c4e2c0a0221ee50eaedefe79

# Every time you need to use the key (including after reboot)
tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx # Only needed if not already created
tpm2_load -C primary.ctx -u rsa.pub -r rsa.priv -c rsa.ctx

echo "Hello world!" > test_data.txt

# Now use it
tpm2_rsaencrypt -c rsa.ctx test_data.txt -o encrypted.dat

# To decrypt
tpm2_rsadecrypt -c rsa.ctx encrypted.dat 

# Now let's flush so it doesn't pollute the TPM RAM
tpm2_flushcontext rsa.ctx