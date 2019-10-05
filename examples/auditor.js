const fs = require('fs')
const PageSigner = require('../src/factory')


// const { oracle, imageID, snapshotID } = JSON.parse(fs.readFileSync('./oracles.json'))
// const pubkeys = fs.readFileSync('./pubkeys.txt', 'utf8')

// Read a pgsg file
const file = fs.readFileSync('./notarizenew.pgsg')

// Convert it to array of numbers
const buffer =  [...file]

// PageSigner instace
const p = PageSigner({})

// Audit file
p.audit(buffer)
.then(res => {
  console.log( typeof res )
  console.log(res)
})
.catch(console.log())
