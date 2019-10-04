const fs = require('fs')
const PageSigner = require('../src/factory')

const { oracle, imageID, snapshotID } = JSON.parse(fs.readFileSync('./oracles.json'))
const pubkeys = fs.readFileSync('./pubkeys.txt', 'utf8')

const p = PageSigner({
  oracleOptions: {
    imageID,
    snapshotID,
    oracle
  },
  pubkeys
})

p.notarize({
  url: 'https://graph.facebook.com',
})
.then(res => {
  console.log('finished', res)
  fs.writeFile('notarizenew.pgsg', new Buffer(res['pgsg.pgsg']))
})
