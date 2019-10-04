const fs = require('fs')
// Utils
const { notarize } = require('./libs/notarize')
const { init } = require('./libs/init_oracles')


const { oracles, imageID, snapshotID } = JSON.parse(fs.readFileSync('./oracles.json'))
const pubkeys = fs.readFileSync('./pubkeys.txt', 'utf8')

// Initialize oracles and reliable sites
init({ oracles, snapshotID, imageID, pubkeys })
.then(({ chosen_notary, reliable_sites }) => {
  console.log('chosen_notary', chosen_notary)
  // Notarize url
  notarize({
    chosen_notary,
    reliable_sites,
    url: 'https://graph.facebook.com/v4.0/me?fields=id%2cname&access_token=eaaftxg7davibanhzagzbivoeo92pul3otscsoftirpiivo40kmug5ve9gor0lc8dadbp9pymjzc0wgpffz6sqvlekqhqzbrzanbf4r69crmzbgdvxdcuekzcsnygtlzbjwnnn7kavkjycga1g2sdske4oeb3ucueqgfdlyya2aaeuvdl7d5zc7i80zaj2mpphvimzd',
  })
  .then(results => {
    console.log('Finished notarization succesffully')
    console.log('results', Object.keys(results))
    fs.writeFile('notarize2.pgsg', new Buffer(results['pgsg.pgsg']))
  })
  .catch(err => {
    console.log('error on notarization')
  })
})
.catch(err => {
  console.log('Error on checking oracles', err)
})
