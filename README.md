# vru-kyber

## Test

### Prepare test vectors

```
tar xf test_vectors.tar.gz
```

### Check test vectors

```
./check_test_vectors.sh
```

See https://github.com/pq-crystals/kyber for reference values.

### Run tests

```
cargo test --release
```

## Benchmarks

```
cargo bench
```
