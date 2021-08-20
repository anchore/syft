var merge  = require('../lib/merge-objects');
var assert = require('assert');

var object1, object2, result;

/* Test not objects */
object1 = 0;
object2 = 'a string';
result = merge(object1, object2);

assert.deepEqual(result, [0, 'a string'], 'two not objects');

/* Test one object and one not object */
object1 = [0, 1];
object2 = 'a string';
result = merge(object1, object2);

assert.deepEqual(result, [0, 1, 'a string'], 'one object and one not object');

/* Test one not object and one object */
object1 = 0;
object2 = ['a string', 'string2'];
result = merge(object1, object2);

assert.deepEqual(result, ['a string', 'string2', 0], 'one not object and one object');

/* Test two objects with no depth */
object1 = {a: 1};
object2 = {b: 2};
result = merge(object1, object2);

assert.deepEqual(result, {a: 1, b: 2}, 'two objects with no depth');

/* Test two objects with equal keys */
object1 = {a: 1};
object2 = {a: 2};
result = merge(object1, object2);

assert.deepEqual(result, {a: 2}, 'two objects with equal keys');

/* Test array concatenation inside objects */
object1 = {a: 1, b: [2, 3]};
object2 = {b: [4, 5], c: 6};
result = merge(object1, object2);

assert.deepEqual(result, {a: 1, b: [2, 3, 4, 5], c: 6}, 'array concatenation inside objects');

/* Test two objects with depth and equal keys */
object1 = {a: {b: [0, 1], c: 'a'}};
object2 = {a: {b: [2, 3], c: 'b'}};
result = merge(object1, object2);

assert.deepEqual(result, {a: {b: [0, 1, 2, 3], c: 'b'}}, 'two objects with depth and equal keys');