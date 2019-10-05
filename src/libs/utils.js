const { Certificate, verifyCertChain } = require('./verifychain/verifychain')
const { ba2str, ua2ba } = require('./tlns_utils')

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

//converts string to bytearray
function str2ba(str) {
  if (typeof(str) !== 'string') {
    throw ('Only type string is allowed in str2ba')
  }
  ba = []
  for (var i = 0; i < str.length; i++) {
    ba.push(str.charCodeAt(i))
  }
  return ba
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

// Format
//data_with_headers is a string
function formatDataOutput(data_with_headers, pgsg, metaDomainName) {
  var rv = data_with_headers.split('\r\n\r\n')
  var headers = rv[0]
  var data = rv.splice(1).join('\r\n\r\n')
  var header_lines = headers.split('\r\n')
  var type = 'unknown'
  for (var i = 0; i < header_lines.length; i++) {
    if (header_lines[i].search(/content-type:\s*/i) > -1) {
      type = get_type(header_lines[i])
      break
    }
  }

  function get_type(line){
    var t
    var match = line.match('application/|text/|image/')
    if (!match) {
      t = 'unknown'
    }
    else {
      var afterslash = line.slice(match.index + match[0].length)
      //search until either + , ; or <space> is encountered
      var delimiter = afterslash.match(/\+|;| /)
      if (!delimiter) {
        t = afterslash
      }
      else {
        t = afterslash.slice(0, delimiter.index)
      }
    }
    if (!t.length) t = 'unknown'
    if (t == 'vnd.ms-excel') t = 'xls'
    if (t == 'vnd.openxmlformats-officedocument.spreadsheetml.sheet') t = 'xlsx'
    if (t == 'plain') t = 'txt'
    return t
  }


  if (type === 'html') {
    //disabling for now because there are no issues displaying without the marker
    //html needs utf-8 byte order mark
    //data = ''.concat(String.fromCharCode(0xef, 0xbb, 0xbf), data);
  }

  return {
    dataType: type,
    data: str2ba(data),
    metaDomainName,
    'pgsg.pgsg': pgsg,
    'raw.txt': data_with_headers
  }
}

function getModulus(cert) {
  var c = Certificate.decode(new Buffer(cert), 'der')
  var pk = c.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey.data
  var pkba = ua2ba(pk)
  //expected modulus length 256, 384, 512
  var modlen = 256
  if (pkba.length > 384) modlen = 384
  if (pkba.length > 512) modlen = 512
  var modulus = pkba.slice(pkba.length - modlen - 5, pkba.length - 5)
  return modulus
}

function getCommonName(cert) {
  var c = Certificate.decode(new Buffer(cert), 'der')
  var fields = c.tbsCertificate.subject.value
  for (var i = 0; i < fields.length; i++) {
    if (fields[i][0].type.toString() !== [2, 5, 4, 3].toString()) continue
    //first 2 bytes are DER-like metadata
    return ba2str(fields[i][0].value.slice(2))
  }
  return 'unknown'
}

function verifyCert(chain) {
  var chainperms = permutator(chain)
  for (var i = 0; i < chainperms.length; i++) {
    if (verifyCertChain(chainperms[i])) {
      return true
    }
  }
  return false
}

function permutator(inputArr) {
  var results = []

  function permute(arr, memo) {
    var cur, memo = memo || []

    for (var i = 0; i < arr.length; i++) {
      cur = arr.splice(i, 1)
      if (arr.length === 0) {
        results.push(memo.concat(cur))
      }
      permute(arr.slice(), memo.concat(cur))
      arr.splice(i, 0, cur[0])
    }

    return results
  }

  return permute(inputArr)
}

module.exports = {
  ba2int,
  assert,
  arrayBufferToBufferCycle,
  formatSendData,
  toArrayBuffer,
  formatDataOutput,
  getModulus,
  getCommonName,
  verifyCert
}
