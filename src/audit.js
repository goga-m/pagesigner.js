const { ba2int, assert, formatDataOutput, getModulus, getCommonName, verifyCert } = require('./libs/utils')
const { ua2ba, bi2ba, str2ba, ba2str, sha256, getTime } = require('./libs/tlns_utils')
const { TLSNClientSession, prepare_pms, get_certificate, decrypt_html, start_audit, verify_commithash_signature } = require('./libs/tlsn')

//imported_data is an array of numbers
function verify_tlsn(data,  oracle) {
  const pgsg = data
  var offset = 0
  if (ba2str(data.slice(offset, offset += 29)) !== 'tlsnotary notarization file\n\n') {
    throw ('wrong header')
  }
  if (data.slice(offset, offset += 2).toString() !== [0x00, 0x02].toString()) {
    throw ('wrong version')
  }
  var cs = ba2int(data.slice(offset, offset += 2))
  var cr = data.slice(offset, offset += 32)
  var sr = data.slice(offset, offset += 32)
  var pms1 = data.slice(offset, offset += 24)
  var pms2 = data.slice(offset, offset += 24)
  var chain_serialized_len = ba2int(data.slice(offset, offset += 3))
  var chain_serialized = data.slice(offset, offset += chain_serialized_len)
  var tlsver = data.slice(offset, offset += 2)
  var tlsver_initial = data.slice(offset, offset += 2)
  var response_len = ba2int(data.slice(offset, offset += 8))
  var response = data.slice(offset, offset += response_len)
  var IV_len = ba2int(data.slice(offset, offset += 2))
  var IV = data.slice(offset, offset += IV_len)
  var sig_len = ba2int(data.slice(offset, offset += 2))
  var sig = data.slice(offset, offset += sig_len)
  var commit_hash = data.slice(offset, offset += 32)
  var notary_pubkey = data.slice(offset, offset += sig_len)
  var time = data.slice(offset, offset += 4)
  assert(data.length === offset, 'invalid .pgsg length')

  offset = 0
  var chain = [] //For now we only use the 1st cert in the chain
  while (offset < chain_serialized.length) {
    var len = ba2int(chain_serialized.slice(offset, offset += 3))
    var cert = chain_serialized.slice(offset, offset += len)
    chain.push(cert)
  }

  const commonName = getCommonName(chain[0])
  //verify cert
  if (!verifyCert(chain)) {
    throw ('certificate verification failed')
  }
  var modulus = getModulus(chain[0])
  //verify commit hash
  if (sha256(response).toString() !== commit_hash.toString()) {
    throw ('commit hash mismatch')
  }
  //verify sig
  var signed_data = sha256([].concat(commit_hash, pms2, modulus, time))
  var signing_key
  if (!oracle) {
    signing_key = notary_pubkey
  } else {
    signing_key = oracle.modulus
  }
  if (!verify_commithash_signature(signed_data, sig, signing_key)) {
    throw ('notary signature verification failed')
  }

  //decrypt html and check MAC
  var s = new TLSNClientSession()
  s.__init__()
  s.unexpected_server_app_data_count = response.slice(0, 1)
  s.chosen_cipher_suite = cs
  s.client_random = cr
  s.server_random = sr
  s.auditee_secret = pms1.slice(2, 2 + s.n_auditee_entropy)
  s.initial_tlsver = tlsver_initial
  s.tlsver = tlsver
  s.server_modulus = modulus
  s.set_auditee_secret()
  s.auditor_secret = pms2.slice(0, s.n_auditor_entropy)
  s.set_auditor_secret()
  s.set_master_secret_half() //#without arguments sets the whole MS
  s.do_key_expansion() //#also resets encryption connection state
  s.store_server_app_data_records(response.slice(1))
  s.IV_after_finished = IV
  s.server_connection_state.seq_no += 1
  s.server_connection_state.IV = s.IV_after_finished
  html_with_headers = decrypt_html(s)

  const resultsData = formatDataOutput(html_with_headers, pgsg, commonName)
  return resultsData
}


module.exports = {
  verify: verify_tlsn
}
