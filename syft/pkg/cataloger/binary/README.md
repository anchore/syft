# Adding tests for the Binary cataloger

> [!TIP]
> **TL;DR** to add a test for a new classifier:
>  1. head to the correct directory: `cd test-fixtures`
>  2. add a new entry to `config.yaml` to track where to get the binary from (verify the entry with `make list`)
>  3. run `make download` to get the binary
>  4. run `make add-snippet` and follow the prompts (use `/` to search)
>  5. add a new test case to `Test_Cataloger_PositiveCases` in `../cataloger_test.go`


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

Here is an example entry in `config.yaml` for a binary reference from a container image:

```yaml
from-images:
  
  # note the group-name is assumed from the single binary name extracted: "redis-server"
  - version: 7.2.3
    images:
      # note we're pulling the same binary from multiple images (representing different architectures)
      - ref: redis:7.2.3@sha256:d4c84914b872521e215f77d8845914c2268a96b0e35bacd5691e1f5e1f88b500
        platform: linux/amd64
      - ref: redis:7.2.3@sha256:a0a0c38b31011b813cddf78d997f8ccba13019c27efd386984b0cfc1e4b618ff
        platform: linux/arm64
    # the paths to extract from the binary...
    paths:
      - /usr/local/bin/redis-server

  # since there are multiple binaries in the image, we need to specify the group-name
  - name: ruby-bullseye-shared-libs
    version: 2.7.7
    images:
      - ref: ruby:2.7.7-bullseye@sha256:055191740a063f33fef1f09423e5ed8f91143aae62a3772a90910118464c5120
        platform: linux/amd64
    paths:
      - /usr/local/bin/ruby
      - /usr/local/lib/libruby.so.2.7.7
      - /usr/local/lib/libruby.so.2.7
```


> [!NOTE]  
> You will need a system with `go`, `bash`, `strings`, and `xxd` installed to capture test snippets.


## Testing

The test cases have been setup to allow testing against full binaries or a mix of both (default).
To force running only against full binaries run with:

```bash
go test -must-use-full-binaries ./syft/pkg/cataloger/binary/test-fixtures/...
```

## Adding a new test fixture

### Adding a snippet (recommended)

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


### Adding a full binary

1. Add a new entry to `config.yaml` with the following fields
  - if you are adding a single binary, the `name` field does not need to be specified
  - the `name` field is useful for distinguishing a quality about the binary (e.g. `java` vs `java-jre-ibm`)

2. Run `make download` and ensure your new binary is downloaded


### Adding a custom snippet

If you need to add a snippet that is not based off of a full binary, you can use the `capture-snippet.sh` script.

```bash
./capture-snippet.sh <binary-path> <version> [--search-for <pattern>] [--length <length>] [--prefix-length <prefix_length>] [--group <name>]
```


This is **not** recommended because it is not reproducible and does not allow for the test to be run against a full binary. 