const { ba2int, assert, formatDataOutput, getModulus, getCommonName, verifyCert } = require('./libs/utils')
const { ua2ba, bi2ba, str2ba, ba2str, sha256, getTime } = require('./libs/tlns_utils')
const { TLSNClientSession, prepare_pms, get_certificate, decrypt_html, start_audit, verify_commithash_signature } = require('./libs/tlsn')


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

function startNotarizing(headers, server, port, oracle, reliable_sites) {
  const random_uid = Math.random().toString(36).slice(-10)
  if (!oracle) {
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
        prepare_pms(modulus, undefined, reliable_sites, oracle, random_uid).then(function(args) {
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
    return start_audit(modulus, certsha256, server, port, headers, args[0], args[1], args[2], oracle, random_uid)
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

    const commonName = getCommonName(server_certchain[0])
    // Format result object
    const resultsData = formatDataOutput(data_with_headers, pgsg, commonName)
    resolve(resultsData)
  })
}

function notarize({ oracle, reliableSites, url, headers, method = 'GET', formData = [] }) {
  assert(!!oracle, 'Notarize init failed: \'oracle\' is not provided')
  assert(!!reliableSites && reliableSites.length > 0, 'Notarize init failed: \'reliableSites\' Array is not provided or empty')

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
  return startNotarizing(rv.headers, rv.server, rv.port, oracle, reliableSites)
}

module.exports = {
  startNotarizing: notarize
}
