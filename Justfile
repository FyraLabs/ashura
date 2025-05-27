# Read .env
set dotenv-load

test:
    @cargo test -- --test-threads=1

swtpm:
    @swtpm socket \
            --tpm2 \
            --ctrl type=tcp,port=2322 \
            --server type=tcp,port=2321 \
            --tpmstate dir=/tmp/swtpm/state \
            --log level=20