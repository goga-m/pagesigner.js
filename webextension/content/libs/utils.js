
function assert(condition, message) {
  if (!condition) {
    throw message || "Assertion failed";
  }
}

//Turn a max 4 byte array (big-endian) into an int.
function ba2int(x) {
  assert(x.length <= 8, "Cannot convert bytearray larger than 8 bytes");
  var retval = 0;
  for (var i = 0; i < x.length; i++) {
    retval |= x[x.length - 1 - i] << 8 * i;
  }
  return retval;
}

module.exports = {
  ba2int,
  assert
}
