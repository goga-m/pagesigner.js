const fs = require('fs')
const path = require('path')
// Utils
const { startNotarizing } = require('./notarize')
const { init } = require('./init_oracles')
const { assert } = require('./libs/utils')
const tlsnotaryOracle = require('./tlsnotary_oracles.json')
const defaultPubkeys = fs.readFileSync(path.resolve(__dirname,'default_pubkeys.txt'), 'utf8')

const PageSigner = ({ oracleOptions = {}, pubkeys: { pubkeysUTF8 } }) => {
  // Parameters
  let oracle = oracleOptions.oracle
  let imageID = oracleOptions.imageID
  let snapshotID = oracleOptions.snapshotID
  let pubkeys = pubkeysUTF8

  let reliableSites
  let oracleChecked = false
  /**
   * Check oracle server
   *
   * @name async
   * @function
   */
  const checkOracle = async () => {
    return init({ oracle, snapshotID, imageID, pubkeys })
    .then(res => {
      reliableSites = res.reliableSites
      oracleChecked = true
      return res
    })
  }

  /**
   * Validate initial parameters if not set by defaults
   *
   * @name validateOptions
   * @function
   */
  const validateOptions = () => {
    assert(!!oracle, 'PageSigner creation failed: \'oracle\' Object is not provided')
    assert(!!pubkeys, 'PageSigner creation failed: \'pubkeys\' String/Function is not provided')
    assert(!!imageID, 'PageSigner creation failed: \'imageID\' String is not provided')
    assert(!!snapshotID, 'PageSigner creation failed: \'snapshotID\' String is not provided')
  }

  /**
   * Notarize given url
   *
   * @name async
   * @function
   * @param {String} data.url
   * @param {String} data.method
   * @param {Array<Object>} data.headers
   * @param {Array<Object>} data.formData // for POST
   */
  const notarize = async (data = {}) => {
    if(!oracleChecked) await checkOracle()

    return startNotarizing({
      oracle,
      reliableSites,
      ...data
    })
  }

  /**
   * Add default parameters if not provided
   *
   * @name async
   * @function
   */
  const defaultOptions = async () => {

    if(!oracle) {
      oracle = tlsnotaryOracle.oracle
      imageID = tlsnotaryOracle.imageID
      snapshotID = tlsnotaryOracle.snapshotID
      console.log('added default options', oracle)
    }

    if(!pubkeys) {
      pubkeys = defaultPubkeys
    }

  }

  defaultOptions()
  validateOptions()

  return { checkOracle, notarize }
}

module.exports = PageSigner
