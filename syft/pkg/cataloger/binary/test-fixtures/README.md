# Binary cataloger test fixtures

To test the binary cataloger we run it against a set of files ("test fixtures"). There are two kinds of test fixtures:

- **Full binaries**: files downloaded and cached at test runtime
- **Snippets**: ~100 byte files checked into the repo

The upside with snippets is that they live with the test, don't necessarily require network access or hosting concerns, and are easy to add. The downside is that they are not the entire real binary so modifications may require recreating the snippet entirely.

The upside with full binaries is that they are the "Real McCoy" and allows the business logic to change without needing to update the fixture. The downside is that they require network access and take up a lot of space. For instance, downloading all binaries for testing today requires downloading ~15GB of container images and ends up being ~500MB of disk space.

You can find the test fixtures at the following locations:
```
syft/pkg/cataloger/binary/test-fixtures/
└── classifiers/
    ├── bin/        # full binaries
    ├── ...
    └── snippets/   # snippets
```

And use tooling to list and manage the fixtures:

- `make list` - list all fixtures
- `make download` - download binaries that are not covered by a snippet
- `make download-all` - download all binaries
- `go run ./manager add-snippet` - add a new snippet based off of a configured binary
- `capture-snippet.sh` - add a new snippet based off of a binary on your local machine (not recommended, but allowed)

There is a `config.yaml` that tracks all binaries that the tests can use. This makes it possible to download it at any time from a hosted source. Today the only method allowed is to download a container image and extract files out.

## Testing

The test cases have been setup to allow testing against full binaries or a mix of both (default).
To force running only against full binaries run with:

```bash
go test -must-use-full-binaries ./syft/pkg/cataloger/binary/test-fixtures/...
```

## Adding a new test fixture

### Adding a full binary

1. Add a new entry to `config.yaml` with the following fields
  - if you are adding a single binary, the `name` field does not need to be specified
  - the `name` field is useful for distinguishing a quality about the binary (e.g. `java` vs `java-jre-ibm`)

2. Run `make download` and ensure your new binary is downloaded


### Adding a snippet

Even if you are adding a snippet, it is best practice to:

- create that snippet from a full binary (not craft a snippet by hand)
- track where the binary is from and how to download it in `config.yaml`

1. Follow the steps above to [add a full binary](#adding-a-full-binary)

2. Run `go run ./manager add-snippet` and follow the prompts to create a new snippet
   - you should see your binary in the list of binaries to choose from. If not, check step 2
   - if the search results in no matching snippets, you can specify your own search with `--search-for <grep-pattern>`
   - you should see a new snippet file created in `snippets/`

3. Write a test that references your new snippet by `<name>/<version>/<architecture>`
   - `<name>` is the name of the binary (e.g. `curl`) or the name in `config.yaml` if specified
   - note that your test does not know about if it's running against a snippet or a full binary

### Adding a custom snippet

If you need to add a snippet that is not based off of a full binary, you can use the `capture-snippet.sh` script.

```bash
./capture-snippet.sh <binary-path> <version> [--search-for <pattern>] [--length <length>] [--prefix-length <prefix_length>] [--group <name>]
```


This is **not** recommended because it is not reproducible and does not allow for the test to be run against a full binary. 