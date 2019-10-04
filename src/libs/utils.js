function assert(condition, message) {
  if (!condition) {
    throw message || 'Assertion failed'
  }
}

//Turn a max 4 byte array (big-endian) into an int.
function ba2int(x) {
  assert(x.length <= 8, 'Cannot convert bytearray larger than 8 bytes')
  var retval = 0
  for (var i = 0; i < x.length; i++) {
    retval |= x[x.length - 1 - i] << 8 * i
  }
  return retval
}

function arrayBufferToBufferCycle(ab) {
  var buffer = new Buffer(ab.byteLength)
  var view = new Uint8Array(ab)
  for (var i = 0; i < buffer.length; ++i) {
    buffer[i] = view[i]
  }
  return buffer
}

function formatSendData(data){
  var ab = new ArrayBuffer(data.length)
  var dv = new DataView(ab)
  for(var i=0; i < data.length; i++){
    dv.setUint8(i, data[i])
  }
  const buff = arrayBufferToBufferCycle(ab)
  return buff
}


function toArrayBuffer(buf) {
  var ab = new ArrayBuffer(buf.length)
  var view = new Uint8Array(ab)
  for (var i = 0; i < buf.length; ++i) {
    view[i] = buf[i]
  }
  return ab
}

module.exports = {
  ba2int,
  assert,
  arrayBufferToBufferCycle,
  formatSendData,
  toArrayBuffer
}
