# pagesigner.js

Using the **TLSNotary** cryptographic mechanism, prove that you received certain response data from an https server.

It allows you to 'notarize' web requests and generate proofs that allow you to provide evidence to a third party auditor that certain web traffic occurred between you and a server, without compromising your secret keys or sensitive data (request url parameters or request headers). The evidence is
irrefutable as long as the auditor trusts the server’s public key.

This library is a port from the existing [Pagesigner](https://tlsnotary.org/pagesigner.html) browser extention to NodeJS, refactoring the necessary parts to run it as a standalone library.

For more information on how TLSNotary technology works see
[https://tlsnotary.org](https://tlsnotary.org/)


This is not an official repository of the TLSNotary. Please refer to [https://github.com/tlsnotary](https://github.com/tlsnotary) for more information.

**Important Notice**: TLSNotary by design, only supports TLS 1.0 and 1.1 versions which are deprecated due to known vulnerabilities.

## Installation

```bash
npm install pagesigner.js
```

## Usage
#### 1. Notarize
Basic usage with default configuration options.
```javascript
const fs = require('fs')
const PageSigner = require('pagesigner.js')

// Instance
const ps = PageSigner()

// Notarize a url
ps.notarize({
  url: 'https://api-pub.bitfinex.com/v2/tickers?symbols=tBTCUSD',
  // Optional parameters
  //
  // headers: [{
  //   'name':'User-Agent',
  //   'value':'Mozilla/5.0 (X11; Linux x86_64)...'
  // }]
})
.then(res => {
  // Request successfully notarized.
  // Response data
  // res = {
  //   'datatype':       Response data type e.g 'json' (String)
  //   'data':           Server's response data (byte array),
  //   'pgsg.pgsg':      Notarized file data (byte array),
  //                     including server's response headers & data,
  //   'metaDomainName': Server's domain name (String),
  //   'raw.txt':        Notarize filed raw text format (String)
  // }

  // Do something with the pgsg data. E.g save notarized file somewhere
  fs.writeFile('path/to/notarized.pgsg', new Buffer(res['pgsg.pgsg']))
})
.catch(error => {
  // Notarization failed.
})

```

#### 2. Auditor
You can verify your notarized files using the official [Pagesigner browser extention](https://tlsnotary.org/pagesigner.html) by importing the `*.pgsg` file and seeing the validation results.

To programmatically audit and verify a `*.pgsg` file, you can use the `audit()` function as below:
```javascript
const fs = require('fs')
const PageSigner = require('pagesigner.js')

// Instance
const ps = PageSigner()

// Read a pgsg file
const pgsg = fs.readFileSync('path/to/notarized.pgsg')

// Convert it to byte array
const pgsgData =  [...pgsg]

// Verify and parse the notarized data
ps.audit(pgsgData)
.then(res => {
  // Succesfully audited and parsed pgsg file.
  //
  // Parsed output:
  // res = {
  //   'datatype':       Response data type e.g 'json' (String)
  //   'data':           Server's response data (byte array),
  //   'pgsg.pgsg':      Notarized file data (byte array),
  //                     including server's response headers & data,
  //   'metaDomainName': Server's domain name (String),
  //   'raw.txt':        Notarized file raw text format (String)
  // }

  console.log(res)
})
.catch(error => {
  // Auditing failed.
})

```

### Oracle Customization

Note that currently the settings are for the official tlsnotarygroup5 pagesigner oracle. Bear in mind that this oracle server rate currently limits on a per-IP basis; for high frequency runs this may cause notarization to fail.

In order to build your own custom oracle server, please see the pagesigner-oracles repo for details on the setup of the oracle server on Amazon AWS:

[https://github.com/tlsnotary/pagesigner-oracles](https://github.com/tlsnotary/pagesigner-oracles)

In such case, see the example below to use custom oracle settings on your TLSNotary instance:



```javascript
const fs = require('fs')
const PageSigner = require('pagesigner.js')

const { oracle, imageID, snapshotID } = JSON.parse(fs.readFileSync('./oracles.json'))

// Instance with custom oracle settings
const ps = PageSigner({
  oracleOptions: {
    imageID,
    snapshotID,
    oracle
  }
})

// Start notarizing
ps.notarize({
  url: 'https://api-pub.bitfinex.com/v2/tickers?symbols=tBTCUSD'
})
.then(console.log)
.catch(console.log)

```
You can see the format of oracles settings in `/examples/oracles.json` [here](https://github.com/goga-m/pagesigner.js/blob/master/examples/oracles.json).




## References

* Official TLSNotary Website - [https://tlsnotary.org](https://tlsnotary.org/)
* TLSNotary whitepaper - [https://tlsnotary.org/TLSNotary.pdf](https://tlsnotary.org/TLSNotary.pdf)
* Official PageSigner browser addon - [https://tlsnotary.org/pagesigner.html](https://tlsnotary.org/pagesigner.html)
* TLSNotary github page - [https://github.com/tlsnotary](https://github.com/tlsnotary)
