# collapse-white-space

[![Build][build-badge]][build]
[![Coverage][coverage-badge]][coverage]
[![Downloads][downloads-badge]][downloads]
[![Size][size-badge]][size]

Replace multiple whitespace characters with a single space.

## Install

This package is ESM only: Node 12+ is needed to use it and it must be `import`ed
instead of `require`d.

[npm][]:

```sh
npm install collapse-white-space
```

## Use

```js
import {collapseWhiteSpace} from 'collapse-white-space'

collapseWhiteSpace('\tfoo \n\tbar  \t\r\nbaz') //=> ' foo bar baz'
```

## API

This package exports the following identifiers: `collapseWhiteSpace`.
There is no default export.

### `collapseWhiteSpace(value)`

Replace multiple whitespace characters in `value` (`string`) with a single
space.

## License

[MIT][license] © [Titus Wormer][author]

<!-- Definitions -->

[build-badge]: https://github.com/wooorm/collapse-white-space/workflows/main/badge.svg

[build]: https://github.com/wooorm/collapse-white-space/actions

[coverage-badge]: https://img.shields.io/codecov/c/github/wooorm/collapse-white-space.svg

[coverage]: https://codecov.io/github/wooorm/collapse-white-space

[downloads-badge]: https://img.shields.io/npm/dm/collapse-white-space.svg

[downloads]: https://www.npmjs.com/package/collapse-white-space

[size-badge]: https://img.shields.io/bundlephobia/minzip/collapse-white-space.svg

[size]: https://bundlephobia.com/result?p=collapse-white-space

[npm]: https://docs.npmjs.com/cli/install

[license]: license

[author]: https://wooorm.com
