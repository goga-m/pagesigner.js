const { ba2int, assert } = require('./utils')
const { fixcerts, verifyCertChain, Certificate } = require('./verifychain/verifychain')
const { ua2ba, bi2ba, str2ba, ba2str, sha256, getTime } = require('./tlns_utils')
const { TLSNClientSession, prepare_pms, get_certificate, decrypt_html, start_audit } = require('./tlsn')


function getHeaders(obj) {
  var x = obj.url.split('/')
  var host = x[2].split(':')[0]
  x.splice(0, 3)
  var resource_url = x.join('/')
  var headers = obj.method + ' /' + resource_url + ' HTTP/1.1' + '\r\n'
  headers += 'Host: ' + host + '\r\n'
  for (var i = 0; i < obj.requestHeaders.length; i++) {
    var h = obj.requestHeaders[i]
    headers += h.name + ': ' + h.value + '\r\n'
  }
  if (obj.method == 'GET') {
    headers += '\r\n'
  } else if (obj.method == 'POST') {
    var formData = obj.requestBody.formData
    var keys = Object.keys(formData)
    var content = ''
    for (var i = 0; i < keys.length; i++) {
      content += keys[i] + '=' + formData[keys[i]]
      if (i + 1 < keys.length) {
        content += '&'
      }
    }
    //Chrome doesn't expose Content-Length which chokes nginx
    headers += 'Content-Length: ' + parseInt(content.length) + '\r\n\r\n'
    headers += content
  }
  const port = 443
  if (obj.url.split(':').length === 3) {
    //the port is explicitely provided in URL
    port = parseInt(obj.url.split(':')[2].split('/')[0])
  }
  return {
    'headers': headers,
    'server': host,
    'port': port
  }
}

function startNotarizing(headers, server, port, chosen_notary, reliable_sites) {
  const random_uid = Math.random().toString(36).slice(-10)
  if (!chosen_notary) {
    console.log({
      title: 'PageSigner error',
      text: 'Cannot notarize because something is wrong with PageSigner server. Please try again later'
    })
    return
  }
  var modulus
  var certsha256
  var chain
  // loadBusyIcon();
  return get_certificate(server, port)
  .then(function(certchain) {
    chain = certchain
    if (!verifyCert(chain)) {
      console.log({
        title: 'PageSigner error',
        text: 'This website cannot be audited by PageSigner because it presented an untrusted certificate'
      })
      return
    }
    modulus = getModulus(chain[0])
    certsha256 = sha256(chain[0])

    const previous_session_start_time = new Date().getTime()
    //loop prepare_pms 10 times until succeeds
    return new Promise(function(resolve, reject) {
      var tries = 0
      var loop = function(resolve, reject) {
        tries += 1
        prepare_pms(modulus, undefined, reliable_sites, chosen_notary, random_uid).then(function(args) {
          resolve(args)
        }).catch(function(error) {
          console.log('caught error', error)
          if (error.startsWith('Timed out')) {
            reject(error)
            return
          }
          if (error != 'PMS trial failed') {
            reject('in prepare_pms: caught error ' + error)
            return
          }
          if (tries == 10) {
            reject('Could not prepare PMS after 10 tries')
            return
          }
          //else PMS trial failed
          loop(resolve, reject)
        })
      }
      loop(resolve, reject)
    })
  })
  .then(function(args) {
    return start_audit(modulus, certsha256, server, port, headers, args[0], args[1], args[2], chosen_notary, random_uid)
  })
  .then(function(args2) {
    return save_session_and_open_data(args2, server)
  })
  .catch(function(err) {
    //TODO need to get a decent stack trace
    // loadNormalIcon();
    console.log('There was an error: ' + err)
    if (err === 'Server sent alert 2,40') {
      console.log({
        title: 'PageSigner error',
        text: 'Pagesigner is not compatible with this website because the website does not use RSA ciphersuites'
      })
    } else if (err.startsWith('Timed out waiting for notary server to respond') &&
        ((new Date().getTime() - previous_session_start_time) < 60 * 1000)) {
      console.log({
        title: 'PageSigner error',
        text: 'You are signing pages way too fast. Please retry in 60 seconds'
      })
    } else {
      console.log({
        title: 'PageSigner error',
        text: err
      })
    }
  })
}



function save_session_and_open_data(args, server) {
  return new Promise(function(resolve, reject) {
    assert(args.length === 18, 'wrong args length')
    var cipher_suite = args[0]
    var client_random = args[1]
    var server_random = args[2]
    var pms1 = args[3]
    var pms2 = args[4]
    var server_certchain = args[5]
    var tlsver = args[6]
    var initial_tlsver = args[7]
    var fullresp_length = args[8]
    var fullresp = args[9]
    var IV_after_finished_length = args[10]
    var IV_after_finished = args[11]
    var notary_modulus_length = args[12]
    var signature = args[13]
    var commit_hash = args[14]
    var notary_modulus = args[15]
    var data_with_headers = args[16]
    var time = args[17]

    var server_chain_serialized = [] //3-byte length prefix followed by cert
    for (var i = 0; i < server_certchain.length; i++) {
      var cert = server_certchain[i]
      server_chain_serialized = [].concat(
        server_chain_serialized,
        bi2ba(cert.length, {
          'fixed': 3
        }),
        cert)
    }

    var pgsg = [].concat(
      str2ba('tlsnotary notarization file\n\n'), [0x00, 0x02],
      bi2ba(cipher_suite, {
        'fixed': 2
      }),
      client_random,
      server_random,
      pms1,
      pms2,
      bi2ba(server_chain_serialized.length, {
        'fixed': 3
      }),
      server_chain_serialized,
      tlsver,
      initial_tlsver,
      bi2ba(fullresp_length, {
        'fixed': 8
      }),
      fullresp,
      bi2ba(IV_after_finished_length, {
        'fixed': 2
      }),
      IV_after_finished,
      bi2ba(notary_modulus_length, {
        'fixed': 2
      }),
      signature,
      commit_hash,
      notary_modulus,
      time)

    var commonName = getCommonName(server_certchain[0])
    var creationTime = getTime()
    var session_dir = makeSessionDir(commonName, creationTime)
    const resultsData = writeDatafile(data_with_headers, session_dir)
    // Format result object
    resolve({
      creationTime,
      // Will add { dataType, data, raw.txt }
      ...resultsData,
      'pgsg.pgsg': pgsg,
      meta: session_dir.split('/').pop() ,
      metaDomainName: commonName

    })
  })
}


//data_with_headers is a string
function writeDatafile(data_with_headers, session_dir) {
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
    'dataType': type,
    'data': str2ba(data),
    'raw.txt': data_with_headers
  }
}



//imported_data is an array of numbers
// function verify_tlsn(data, from_past, chosen_notary) {
//   var offset = 0
//   if (ba2str(data.slice(offset, offset += 29)) !== 'tlsnotary notarization file\n\n') {
//     throw ('wrong header')
//   }
//   if (data.slice(offset, offset += 2).toString() !== [0x00, 0x02].toString()) {
//     throw ('wrong version')
//   }
//   var cs = ba2int(data.slice(offset, offset += 2))
//   var cr = data.slice(offset, offset += 32)
//   var sr = data.slice(offset, offset += 32)
//   var pms1 = data.slice(offset, offset += 24)
//   var pms2 = data.slice(offset, offset += 24)
//   var chain_serialized_len = ba2int(data.slice(offset, offset += 3))
//   var chain_serialized = data.slice(offset, offset += chain_serialized_len)
//   var tlsver = data.slice(offset, offset += 2)
//   var tlsver_initial = data.slice(offset, offset += 2)
//   var response_len = ba2int(data.slice(offset, offset += 8))
//   var response = data.slice(offset, offset += response_len)
//   var IV_len = ba2int(data.slice(offset, offset += 2))
//   var IV = data.slice(offset, offset += IV_len)
//   var sig_len = ba2int(data.slice(offset, offset += 2))
//   var sig = data.slice(offset, offset += sig_len)
//   var commit_hash = data.slice(offset, offset += 32)
//   var notary_pubkey = data.slice(offset, offset += sig_len)
//   var time = data.slice(offset, offset += 4)
//   assert(data.length === offset, 'invalid .pgsg length')
//
//   offset = 0
//   var chain = [] //For now we only use the 1st cert in the chain
//   while (offset < chain_serialized.length) {
//     var len = ba2int(chain_serialized.slice(offset, offset += 3))
//     var cert = chain_serialized.slice(offset, offset += len)
//     chain.push(cert)
//   }
//
//   var commonName = getCommonName(chain[0])
//   //verify cert
//   if (!verifyCert(chain)) {
//     throw ('certificate verification failed')
//   }
//   var modulus = getModulus(chain[0])
//   //verify commit hash
//   if (sha256(response).toString() !== commit_hash.toString()) {
//     throw ('commit hash mismatch')
//   }
//   //verify sig
//   var signed_data = sha256([].concat(commit_hash, pms2, modulus, time))
//   var signing_key
//   if (from_past) {
//     signing_key = notary_pubkey
//   } else {
//     signing_key = chosen_notary.modulus
//   }
//   if (!verify_commithash_signature(signed_data, sig, signing_key)) {
//     throw ('notary signature verification failed')
//   }
//
//   //decrypt html and check MAC
//   var s = new TLSNClientSession()
//   s.__init__()
//   s.unexpected_server_app_data_count = response.slice(0, 1)
//   s.chosen_cipher_suite = cs
//   s.client_random = cr
//   s.server_random = sr
//   s.auditee_secret = pms1.slice(2, 2 + s.n_auditee_entropy)
//   s.initial_tlsver = tlsver_initial
//   s.tlsver = tlsver
//   s.server_modulus = modulus
//   s.set_auditee_secret()
//   s.auditor_secret = pms2.slice(0, s.n_auditor_entropy)
//   s.set_auditor_secret()
//   s.set_master_secret_half() //#without arguments sets the whole MS
//   s.do_key_expansion() //#also resets encryption connection state
//   s.store_server_app_data_records(response.slice(1))
//   s.IV_after_finished = IV
//   s.server_connection_state.seq_no += 1
//   s.server_connection_state.IV = s.IV_after_finished
//   html_with_headers = decrypt_html(s)
//   return [html_with_headers, commonName, data, notary_pubkey]
// }



function makeSessionDir(server, creationTime, is_imported) {

  if (typeof(is_imported) === 'undefined') {
    is_imported = false
  }
  var imported_str = is_imported ? '-IMPORTED' : ''
  var server_sanitized = server
  if (server.search(/\*/) > -1) {
    var parts = server.split('.')
    server_sanitized = parts[parts.length - 2] + '.' + parts[parts.length - 1]
  }
  var name = 'session-' + creationTime + '-' + server_sanitized + imported_str
  return name
}


//imported_data is an array of numbers
// function verify_tlsn_and_show_data(imported_data, create, chosen_notary) {
//   try {
//     var a = verify_tlsn(imported_data, create, chosen_notary)
//   } catch (e) {
//     console.log({
//       title: 'PageSigner failed to import file',
//       text: 'The error was: ' + e
//     })
//     return
//   }
//   if (create) {
//     var data_with_headers = a[0]
//     var commonName = a[1]
//     var imported_data = a[2]
//     var creationTime = getTime()
//     var session_dir = makeSessionDir(commonName, creationTime, true)
//     writeFile(session_dir, 'creationTime', creationTime)
//     .then(function() {
//       return writeDatafile(data_with_headers, session_dir)
//     })
//     .then(function() {
//       console.log('resolved from writeDataFile')
//       return writePgsg(imported_data, session_dir, commonName)
//     })
//     .then(function() {
//       console.log('resolved from writePgsg')
//       // openTabs(session_dir);
//       // populateTable(); //refresh manager
//     })
//     .catch(function(error) {
//       console.log('got error in vtsh: ' + error)
//     })
//   }
// }

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

function verifyCert(chain) {
  var chainperms = permutator(chain)
  for (var i = 0; i < chainperms.length; i++) {
    if (verifyCertChain(chainperms[i])) {
      return true
    }
  }
  return false
}

function notarize({ chosen_notary, reliable_sites, url, headers, method = 'GET', formData = [] }) {
  assert(!!chosen_notary, 'Notarize init failed: \'chosen_notary\' is not provided')
  assert(!!reliable_sites && reliable_sites.length > 0, 'Notarize init failed: \'reliable_sites\' Array is not provided or empty')

  // Defaults
  const params = {
    method,
    requestHeaders: headers || [{
      'name':'Upgrade-Insecure-Requests',
      'value':'1'
    },{
      'name':'User-Agent',
      'value':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36'
    },{
      'name':'Sec-Fetch-Mode',
      'value':'navigate'
    },{
      'name':'Sec-Fetch-User',
      'value':'?1'
    },{
      'name':'DNT',
      'value':'1'
    },{
      'name':'Accept',
      'value':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3'
    }],
    'url': url,
    requestBody: { formData }
  }

  var rv = getHeaders(params)
  //we must return fast hence the async invocation
  console.log('Start notarization for', rv.headers, rv.server, rv.port, '\n')
  return startNotarizing(rv.headers, rv.server, rv.port, chosen_notary, reliable_sites)
}

module.exports = { notarize }
