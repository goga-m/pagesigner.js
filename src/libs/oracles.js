/**
 * File: oracles.js
 */
const axios = require('axios')
const convert = require('xml-js')

const { assert } = require('./utils')
const { ba2str, b64decode } = require('./tlns_utils')

const xml2json = xml => {
  const jsonData101 = convert.xml2json(xml, { compact: true })
  const jsonDataJson = JSON.parse(jsonData101)
  return jsonDataJson
}

//assuming both events happened on the same day, get the time
//difference between them in seconds
//the time string looks like "2015-04-15T19:00:59.000Z"
function getSecondsDelta(later, sooner) {
  assert(later.length == 24)
  if (later.slice(0, 11) !== sooner.slice(0, 11)) {
    return 999999 //not on the same day
  }
  var laterTime = later.slice(11, 19).split(':')
  var soonerTime = sooner.slice(11, 19).split(':')
  var laterSecs = parseInt(laterTime[0]) * 3600 + parseInt(laterTime[1]) * 60 + parseInt(laterTime[2])
  var soonerSecs = parseInt(soonerTime[0]) * 3600 + parseInt(soonerTime[1]) * 60 + parseInt(soonerTime[2])
  return laterSecs - soonerSecs
}



function modulus_from_pubkey(pem_pubkey) {
  var b64_str = ''
  var lines = pem_pubkey.split('\n')
  //omit header and footer lines
  for (var i = 1; i < (lines.length - 1); i++) {
    b64_str += lines[i]
  }
  var der = b64decode(b64_str)
  //last 5 bytes are 2 DER bytes and 3 bytes exponent, our pubkey is the preceding 512 bytes
  var pubkey = der.slice(der.length - 517, der.length - 5)
  return pubkey
}



function checkDescribeInstances(data, instanceId, IP, imgId) {

  assert('DescribeInstancesResponse' in data)
  const res = data.DescribeInstancesResponse

  assert('reservationSet' in res)
  const rs = res.reservationSet


  assert('item' in rs)
  const rsItem = rs.item

  var ownerId = rsItem.ownerId._text

  assert('instancesSet' in rsItem)
  assert('item' in rsItem.instancesSet)

  var instance = rsItem.instancesSet.item

  assert('instanceId' in instance)
  assert('imageId' in instance)
  assert('instanceState' in instance)
  assert('launchTime' in instance)
  assert(instance.instanceId._text === instanceId)
  assert(instance.imageId._text === imgId)
  assert(instance.instanceState.name._text === 'running')

  var launchTime = instance.launchTime._text

  assert(instance.ipAddress._text === IP)
  assert(instance.rootDeviceType._text === 'ebs')
  assert(instance.rootDeviceName._text === '/dev/xvda')
  assert('item' in instance.blockDeviceMapping)

  var device = instance.blockDeviceMapping.item
  assert(device.deviceName._text === '/dev/xvda')
  assert('status' in device.ebs)
  assert(device.ebs.status._text === 'attached')

  var volAttachTime = device.ebs.attachTime._text
  var volumeId = device.ebs.volumeId._text

  assert(getSecondsDelta(volAttachTime, launchTime) <= 3)
  assert(instance.virtualizationType._text === 'hvm')


  return {
    'ownerId': ownerId,
    'volumeId': volumeId,
    'volAttachTime': volAttachTime,
    'launchTime': launchTime
  }
}


function checkDescribeVolumes(data, instanceId, volumeId, volAttachTime, snapId) {
  assert('DescribeVolumesResponse' in data)
  const res = data.DescribeVolumesResponse

  assert('volumeSet' in res)
  assert('item' in res.volumeSet)

  const volume = res.volumeSet.item

  assert('volumeId' in volume)
  assert('attachmentSet' in volume)
  assert('item' in volume.attachmentSet)

  assert(volume.volumeId._text === volumeId)
  assert(volume.snapshotId._text === snapId)
  assert(volume.status._text === 'in-use')

  var volCreateTime = volume.createTime._text
  var attVolume = volume.attachmentSet.item
  assert(attVolume.volumeId._text === volumeId)
  assert(attVolume.instanceId._text === instanceId)
  assert(attVolume.device._text === '/dev/xvda')
  assert(attVolume.status._text === 'attached')

  var attTime =  attVolume.attachTime._text
  assert(attTime === volAttachTime)
  // //Crucial: volume was created from snapshot and attached at the same instant
  // //this guarantees that there was no time window to modify it
  assert(getSecondsDelta(attTime, volCreateTime) === 0)
  return true
}


function checkGetConsoleOutput(data, instanceId, launchTime) {

  assert('GetConsoleOutputResponse' in data)
  const res = data.GetConsoleOutputResponse

  assert('instanceId' in res)
  assert(res.instanceId._text === instanceId)

  var timestamp = res.timestamp._text
  // assert(xmlDoc.getElementsByTagName('instanceId')[0].textContent === instanceId);
  // var timestamp = xmlDoc.getElementsByTagName('timestamp')[0].textContent;
  //prevent funny business: last consoleLog entry no later than 5 minutes after instance starts
  //However, it was once observed that timestamp was switched on 2018-01-01. Maybe AWS resets it
  //every first day of the year?
  //
  // TODO: GOGA EDIT: Allow oracle check
  // assert(getSecondsDelta(timestamp, launchTime) <= 300)
  // var b64data = xmlDoc.getElementsByTagName('output')[0].textContent;
  var b64data = res.output._text
  var logstr = ba2str(b64decode(b64data))
  var sigmark = 'PageSigner public key for verification'
  var pkstartmark = '-----BEGIN PUBLIC KEY-----'
  var pkendmark = '-----END PUBLIC KEY-----'

  var mark_start = logstr.search(sigmark)
  assert(mark_start !== -1)
  var pubkey_start = mark_start + logstr.slice(mark_start).search(pkstartmark)
  var pubkey_end = pubkey_start + logstr.slice(pubkey_start).search(pkendmark) + pkendmark.length
  var chunk = logstr.slice(pubkey_start, pubkey_end)
  var lines = chunk.split('\n')
  var pk = pkstartmark + '\n'
  for (var i = 1; i < lines.length-1; i++) {
    var words = lines[i].split(' ')
    pk = pk + words[words.length-1] + '\n'
  }
  pk = pk + pkendmark
  assert(pk.length > 0)

  return pk
}

// "userData" allows to pass an arbitrary script to the instance at launch. It MUST be empty.
// This is a sanity check because the instance is stripped of the code which parses userData.
function checkDescribeInstanceAttributeJSON(data, instanceId) {
  assert('DescribeInstanceAttributeResponse' in data)
  const res = data.DescribeInstanceAttributeResponse

  assert(res.instanceId._text === instanceId)
  assert(!('_text' in res.userData))
  return true
}


function checkGetUser(data, ownerId) {
  assert('GetUserResponse' in data)
  const res = data.GetUserResponse

  assert('GetUserResult' in res)
  assert('User' in res.GetUserResult)

  const usr = res.GetUserResult.User
  assert(usr.UserId === ownerId)
  assert(usr.Arn.indexOf(`${ownerId}:root`) > -1)
  return true
}


function check_oracle(o, imageID, snapshotID) {
  // DI
  console.log('[checkDescribeInstances] get', o.DI, '\n')
  return axios.get(o.DI)
  .then(({ data }) => {
    return checkDescribeInstances(xml2json(data), o.instanceId, o.IP, imageID)
  })

  // DV
  .then(args => {
    console.log('[checkDescribeVolumes] get', o.DV, '\n')
    return axios.get(o.DV)
    .then(({ data }) => {
      const result = checkDescribeVolumes(xml2json(data), o.instanceId, args.volumeId, args.volAttachTime, snapshotID)
      return {
        'ownerId': args.ownerId,
        'launchTime': args.launchTime
      }
    })
  })

  // GU
  .then(args => {
    console.log('[checkGetUser] get', o.GU, '\n')
    return axios.get(o.GU)
    .then(({ data }) => {
      const result = checkGetUser(data, args.ownerId)
      return args.launchTime
    })
  })

  // GCO
  .then(launchTime => {
    console.log('[checkGetConsoleOutput] get', o.GCO, '\n')
    return axios.get(o.GCO)
    .then(({ data }) => {
      try {
        var result = checkGetConsoleOutput(xml2json(data), o.instanceId, launchTime)
      }
      catch (e) {
        console.log(e)
        throw(e)
      }

      if (modulus_from_pubkey(result).toString() !== o.modulus.toString()) {
        throw('modulus_from_pubkey')
      }

      return
    })
  })

  // DIA
  .then(() => {
    console.log('[checkDescribeInstanceAttributeJSON] get', o.DIA, '\n')
    return axios.get(o.DIA)
    .then(({ data }) => {
      const result = checkDescribeInstanceAttributeJSON(xml2json(data), o.instanceId)
      return
    })
  })
  .then(() => {
    var mark = 'AWSAccessKeyId='
    var start
    var id
    var ids = []
    //"AWSAccessKeyId" should be the same to prove that the queries are made on behalf of AWS user "root".
    //The attacker can be a user with limited privileges for whom the API would report only partial information.
    for (var url in [o.DI, o.DV, o.GU, o.GCO, o.DIA]) {
      start = url.search(mark) + mark.length
      id = url.slice(start, start + url.slice(start).search('&'))
      ids.push(id)
    }
    assert(new Set(ids).size === 1)
    return true
  })

}

module.exports = {
  check_oracle
}
