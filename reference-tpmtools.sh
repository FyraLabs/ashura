# Shell script to reference for tpm code, we want to mimic this to
# seal/unseal data in ashura

# One-time setup (creates the key files)
tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx
tpm2_create -G rsa2048:rsaes -g sha256 -u rsa.pub -r rsa.priv -C primary.ctx

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