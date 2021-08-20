# node-merge-objects

Merge two objects and concatenate arrays that are values of the same object key.

Similar to extend in JQuery, but with arrays concatenation. Does deep merging too.

[![Build Status](https://secure.travis-ci.org/shevaroller/node-merge-objects.png)](http://travis-ci.org/shevaroller/node-merge-objects)


## Installation
	npm install merge-objects --save

## Usage
	var merge = require('merge-objects');

	var object1 = {a: 1, b: [2, 3]};
	var object2 = {b: [4, 5], c: 6};

	var result = merge(object1, object2);
	console.log(result); //logs {a: 1, b: [2, 3, 4, 5], c: 6}

## License

MIT