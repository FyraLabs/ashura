# Read .env
set dotenv-load

test:
    @cargo test -- --test-threads=1 --nocapture --color=always --format pretty

swtpm:
    mkdir -p /tmp/swtpm/state
    swtpm socket \
            --tpm2 \
            --ctrl type=tcp,port=2322 \
            --server type=tcp,port=2321 \
            --flags startup-clear \
            --tpmstate dir=/tmp/swtpm/state \
            --log level=20