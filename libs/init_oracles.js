// Utils
const { assert } = require('./utils')
const { ba2hex, hex2ba, sha256 } = require('./tlns_utils')
const { check_oracle } = require('./oracles.js')

function init({ oracles, pubkeys, imageID, snapshotID }) {
  assert(!!oracles && oracles.length > 0, 'init notarization failed: \'oracles\' Array is not provided')
  assert(!!pubkeys, 'init notarization failed: \'pubkeys\' String/Function is not provided')
  assert(!!imageID, 'init notarization failed: \'imageID\' String is not provided')
  assert(!!snapshotID, 'init notarization failed: \'snapshotID\' String is not provided')

  const chosen_notary = oracles[Math.random() * (oracles.length) << 0]
  const oracle_hash = ba2hex(sha256(JSON.stringify(chosen_notary)))
  const was_oracle_verified = false

  return import_reliable_sites(pubkeys)
  .then(reliable_sites => {
    console.debug('\nReliable sites are: ', reliable_sites.map(s => s.name), '\n')
    return check_oracle(chosen_notary, imageID, snapshotID)
    .then(() => {
      return {
        reliable_sites,
        chosen_notary,
        was_oracle_verified: true
      }
    })
  })
}

function import_reliable_sites(pubkeys) {
  if(typeof pubkeys === 'string') {
    return Promise.resolve(parse_reliable_sites(pubkeys))
  }

  if(typeof pubkeys === 'function') {
    return Promise.all([pubkeys()])
    .then(([data]) => parse_reliable_sites(data))
  }
  return Promise.reject('\'pubkeys\' should either be a string or a function')
}


function parse_reliable_sites(text) {
  const reliable_sites = []
  var lines = text.split('\n')
  var name = ''
  var expires = ''
  var modulus = []
  var i = -1
  var x
  var mod_str
  var line
  while (true) {
    i += 1
    if (i >= lines.length) {
      return reliable_sites
      break
    }
    x = lines[i]
    if (x.startsWith('#')) {
      continue
    } else if (x.startsWith('Name=')) {
      name = x.slice('Name='.length)
    } else if (x.startsWith('Expires=')) {
      expires = x.slice('Expires='.length)
    } else if (x.startsWith('Modulus=')) {
      mod_str = ''
      while (true) {
        i += 1
        if (i >= lines.length) {
          break
        }
        line = lines[i]
        if (line === '') {
          break
        }
        mod_str += line
      }
      modulus = []
      var bytes = mod_str.split(' ')
      for (var j = 0; j < bytes.length; j++) {
        if (bytes[j] === '') {
          continue
        }
        modulus.push(hex2ba(bytes[j])[0])
      }
      //Don't use pubkeys which expire less than 3 months from now
      var ex = expires.split('/')
      var extime = new Date(parseInt(ex[2]), parseInt(ex[0]) - 1, parseInt(ex[1])).getTime()
      var now = new Date().getTime()
      if ((extime - now) < 1000 * 60 * 60 * 24 * 90) {
        continue
      }
      reliable_sites.push({
        'name': name,
        'port': 443,
        'expires': expires,
        'modulus': modulus
      })
    }
  }
}

module.exports = { init }
