// Nodejs depedencies
var fs = require('fs')
var XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;
var axios = require('axios')
var convert = require('xml-js');
var atob = require('atob')
var btoa = require('btoa')
var crypto = require('crypto')
var getRandomValues = require('get-random-values')

// Libs
var AbstractSocket = require('./libs/socket')

// Utils
var { ba2int, assert } = require('./libs/utils')


// CryptoJS libraries
var CryptoJS = require('./libs/CryptoJS/core')

// tlns_utils
var {
  ab2ba,
  ba2ab,
  ba2ua,
  ua2ba,
  wa2ba,
  ba2hex,
  hex2ba,
  bi2ba,
  str2ba,
  ba2str,
  sha256,
  log,
  getTime
} = require('./libs/tlns_utils')

var { check_oracle } = require('./libs/oracles.js')
var { 
  TLSNClientSession,
  prepare_pms,
  get_certificate,
  decrypt_html,
  start_audit
} = require('./libs/tlsn')


// Globals 

// TODO: Make these parameters configurable for custom oracle server
var snapshotID = 'snap-03bae56722ceec3f0';
var imageID = 'ami-1f447c65';
var oracles_intact = false; //must be explicitely set to true

var oracle = {
  'name': 'tlsnotarygroup5',
  'IP': '54.158.251.14',
  'port': '10011',
'DI':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeInstances&Expires=2025-01-01&InstanceId=i-0858c02ad9a33c579&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=AWkxF%2FlBVL%2FBl2WhQC62qGJ80qhL%2B%2B%2FJXvSp8mm5sIg%3D',
'DV':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeVolumes&Expires=2025-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&VolumeId=vol-056223d4e1ce55d9c&Signature=DCYnV1vNqE3cyTm6bmtNS1idGdBT7DcbeLtZfcm3ljo%3D',
'GCO':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=GetConsoleOutput&Expires=2025-01-01&InstanceId=i-0858c02ad9a33c579&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=I%2F1kp7oSli9GvYrrP5HD52D6nOy7yCq9dowaDomSAOQ%3D',
'GU':'https://iam.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=GetUser&Expires=2025-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-05-08&Signature=N%2BsdNA6z3QReVsHsf7RV4uZLzS5Pqi0n3QSfqBAMs8o%3D',
'DIA':'https://ec2.us-east-1.amazonaws.com/?AWSAccessKeyId=AKIAIHZGACNJKBHFWOTQ&Action=DescribeInstanceAttribute&Attribute=userData&Expires=2025-01-01&InstanceId=i-0858c02ad9a33c579&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=ENM%2Bw9WkB4U4kYDMN6kowJhZenuCEX3c1G7xSuu6GZA%3D',
  'instanceId': 'i-0858c02ad9a33c579',
  'modulus': [186,187,68,57,92,215,243,62,188,248,16,13,3,29,40,217,208,206,78,13,202,184,82,121,26,51,203,41,169,11,4,102,228,127,110,117,170,48,210,212,160,51,175,246,110,178,43,106,94,255,69,0,217,91,225,7,84,133,193,43,177,254,75,191,109,50,212,190,177,61,64,230,188,105,56,252,40,3,91,190,117,1,52,30,210,137,136,13,216,110,83,21,164,56,248,215,33,159,129,149,85,236,130,194,79,227,184,135,133,61,85,201,243,225,121,233,36,84,207,218,86,68,99,21,150,252,28,220,4,93,81,57,214,94,147,56,234,236,0,178,93,39,48,143,21,120,241,33,73,239,185,255,255,79,112,194,72,226,84,158,182,96,159,33,111,57,212,27,23,133,223,152,101,240,98,181,94,38,147,195,187,245,226,158,11,102,91,91,47,146,178,65,180,73,176,209,32,27,99,183,254,161,115,38,186,31,132,165,252,189,226,72,152,219,177,52,47,178,121,45,30,143,78,142,223,133,112,136,72,165,166,225,18,62,249,119,157,198,68,114,69,199,32,121,201,72,159,13,37,66,160,210,83,163,131,128,54,178,219,5,74,94,214,244,43,123,140,156,192,89,120,211,61,192,76,70,176,122,247,198,21,220,79,212,200,192,88,126,200,115,71,102,66,92,102,60,179,213,125,123,86,195,67,204,71,222,249,46,242,179,11,111,12,158,91,189,215,72,190,15,165,11,102,51,1,91,116,127,31,12,55,193,249,170,15,231,13,189,60,73,8,239,238,18,44,131,78,190,164,46,41,169,139,43,230,105,2,170,231,202,203,126,74,202,172,112,217,194,26,202,140,71,183,45,239,213,254,213,139,27,95,163,172,27,176,189,233,59,181,49,225,220,125,90,182,120,183,236,62,100,170,130,122,202,206,193,77,130,250,167,187,238,39,197,216,183,56,203,72,122,168,64,217,225,8,233,13,164,224,23,255,239,230,44,90,31,149,106,207,28,9,249,154,163,84,231,149,167,59,194,193,41,106,239,30,137,188,78,45,66,30,224,233,181,132,146,106,227,135,229,106,71,168,69,149,167,154,150,106,29,130,114,109,11,66,120,42,128,247,166,248,152,103,131,56,88,37,46,19,240,110,135,15,234,44,39,87,65,232,105,2,163]
}


//there can be potentially multiple oracles to choose from
var oracles = [];
oracles.push(oracle);
//all servers trusted to perform notary (including non-oracles)

const { fixcerts, verifyCertChain, Certificate } = require('./libs/verifychain/verifychain')

// End dependencies paste


const reliable_sites = []; //read from content/pubkeys.txt
let chosen_notary;
var valid_hashes = [];

const MemoryStorage = {}
const ResultsStorage = {}


function getPref(pref) {
  return new Promise(function(resolve, reject) {
    if (Object.keys(MemoryStorage).length === 0) {
      resolve('undefined')
      return;
    } else {
      resolve(MemoryStorage[pref])
    }
  })
}

function setPref(pref, value) {
  return new Promise(function(resolve, reject) {
    MemoryStorage[pref] = value
    resolve()
  })
}

function getHeaders(obj) {
  var x = obj.url.split('/');
  var host = x[2].split(':')[0];
  x.splice(0, 3);
  var resource_url = x.join('/');
  var headers = obj.method + " /" + resource_url + " HTTP/1.1" + "\r\n";
  headers += "Host: " + host + "\r\n";
  for (var i = 0; i < obj.requestHeaders.length; i++) {
    var h = obj.requestHeaders[i];
    headers += h.name + ": " + h.value + "\r\n";
  }
  if (obj.method == "GET") {
    headers += "\r\n";
  } else if (obj.method == 'POST') {
    var formData = obj.requestBody.formData;
    var keys = Object.keys(formData);
    var content = '';
    for (var i = 0; i < keys.length; i++) {
      content += keys[i] + '=' + formData[keys[i]];
      if (i + 1 < keys.length) {
        content += '&';
      }
    }
    //Chrome doesn't expose Content-Length which chokes nginx
    headers += 'Content-Length: ' + parseInt(content.length) + '\r\n\r\n';
    headers += content;
  }
  var port = 443;
  if (obj.url.split(':').length === 3) {
    //the port is explicitely provided in URL
    port = parseInt(obj.url.split(':')[2].split('/')[0]);
  }
  return {
    'headers': headers,
    'server': host,
    'port': port
  };
}




function init() {
  chosen_notary = oracles[Math.random() * (oracles.length) << 0];
  var oracle_hash = ba2hex(sha256(JSON.stringify(chosen_notary)));
  var was_oracle_verified = false;

  return import_reliable_sites()
  .then(() => getPref('verifiedOracles.' + oracle_hash))
  .then(value => {
    // TODO: Is oracles_intact necessary?
    if (value === true) {
      oracles_intact = true;
    } else {
      //async check oracles and if the check fails, sets a global var
      //which prevents notarization session from running
      console.log('checking oracles')
      return check_oracle(chosen_notary, imageID, snapshotID)
      .then(() => {
        return setPref('verifiedOracles.' + oracle_hash, true)
      })
      .then(function() {
        oracles_intact = true
        console.log('checked oracles')
        return true
      })
     }
  })

}


function import_reliable_sites() {
  return import_resource('pubkeys.txt')
    .then(function(text_ba) {
      const t = parse_reliable_sites(ba2str(text_ba))
      console.log('Reliable sites are: ', t.map(s => s.name))
      return t
    });
}


function import_resource(filename) {
  console.log('DEBUG1: import resource', filename)
  return new Promise(function(resolve, reject) {
    fs.readFile(`./${filename}`, (err, data) => {
      resolve(ab2ba(data.buffer))
    })
  })
}

// function fetch(url) {
//   return new Promise(function(resolve, reject) {
//     var xhr = new XMLHttpRequest();
//     xhr.responseType = "arraybuffer";
//     xhr.onreadystatechange = function() {
//       if (xhr.readyState != 4)
//         return;
//
//       if (xhr.response) {
//         resolve(ab2ba(xhr.response));
//       }
//     };
//     xhr.open('get', url, true);
//     xhr.send();
//   });
// }

function parse_reliable_sites(text) {
  var lines = text.split('\n');
  var name = "";
  var expires = "";
  var modulus = [];
  var i = -1;
  var x;
  var mod_str;
  var line;
  while (true) {
    i += 1;
    if (i >= lines.length) {
      return reliable_sites
      break;
    }
    x = lines[i];
    if (x.startsWith('#')) {
      continue;
    } else if (x.startsWith('Name=')) {
      name = x.slice('Name='.length);
    } else if (x.startsWith('Expires=')) {
      expires = x.slice('Expires='.length);
    } else if (x.startsWith('Modulus=')) {
      mod_str = '';
      while (true) {
        i += 1;
        if (i >= lines.length) {
          break;
        }
        line = lines[i];
        if (line === '') {
          break;
        }
        mod_str += line;
      }
      modulus = [];
      var bytes = mod_str.split(' ');
      for (var j = 0; j < bytes.length; j++) {
        if (bytes[j] === '') {
          continue;
        }
        modulus.push(hex2ba(bytes[j])[0]);
      }
      //Don't use pubkeys which expire less than 3 months from now
      var ex = expires.split('/');
      var extime = new Date(parseInt(ex[2]), parseInt(ex[0]) - 1, parseInt(ex[1])).getTime();
      var now = new Date().getTime();
      if ((extime - now) < 1000 * 60 * 60 * 24 * 90) {
        continue;
      }
      reliable_sites.push({
        'name': name,
        'port': 443,
        'expires': expires,
        'modulus': modulus
      });
    }
  }
}


function startNotarizing(headers, server, port) {
  console.log('start notarizing')
  const random_uid = Math.random().toString(36).slice(-10);
  if (!oracles_intact) {
    //NotarizeAfterClick already changed the icon at this point, revert to normal
    // loadNormalIcon();
    sendAlert({
      title: 'PageSigner error',
      text: 'Cannot notarize because something is wrong with PageSigner server. Please try again later'
    });
    return;
  }
  var modulus;
  var certsha256;
  var chain;
  // loadBusyIcon();
  console.log('getting server')
  return get_certificate(server, port)
    .then(function(certchain) {
      chain = certchain;
      if (!verifyCert(chain)) {
        sendAlert({
          title: "PageSigner error",
          text: "This website cannot be audited by PageSigner because it presented an untrusted certificate"
        });
        return
      }
      modulus = getModulus(chain[0]);
      certsha256 = sha256(chain[0]);
      const previous_session_start_time = new Date().getTime();
      //loop prepare_pms 10 times until succeeds
      return new Promise(function(resolve, reject) {
        var tries = 0;
        var loop = function(resolve, reject) {
          tries += 1;
          prepare_pms(modulus, undefined, reliable_sites, chosen_notary, random_uid).then(function(args) {
            resolve(args);
          }).catch(function(error) {
            console.log('caught error', error);
            if (error.startsWith('Timed out')) {
              reject(error);
              return;
            }
            if (error != 'PMS trial failed') {
              reject('in prepare_pms: caught error ' + error);
              return;
            }
            if (tries == 10) {
              reject('Could not prepare PMS after 10 tries');
              return;
            }
            //else PMS trial failed
            loop(resolve, reject);
          });
        };
        loop(resolve, reject);
      });
    })
    .then(function(args) {
      return start_audit(modulus, certsha256, server, port, headers, args[0], args[1], args[2], chosen_notary, random_uid);
    })
    .then(function(args2) {
      return save_session_and_open_data(args2, server);
    })
    .then(function() {
      // FINISHED Succesffully
      console.log('Notarization finished')
      // console.log(ResultsStorage)
      const session = Object.values(ResultsStorage)[0]
      return session
    })
    .catch(function(err) {
      //TODO need to get a decent stack trace
      // loadNormalIcon();
      console.log('There was an error: ' + err);
      if (err === "Server sent alert 2,40") {
        sendAlert({
          title: 'PageSigner error',
          text: 'Pagesigner is not compatible with this website because the website does not use RSA ciphersuites'
        });
      } else if (err.startsWith('Timed out waiting for notary server to respond') &&
        ((new Date().getTime() - previous_session_start_time) < 60 * 1000)) {
        sendAlert({
          title: 'PageSigner error',
          text: 'You are signing pages way too fast. Please retry in 60 seconds'
        });
      } else {
        sendAlert({
          title: 'PageSigner error',
          text: err
        });
      }
    });
}



function save_session_and_open_data(args, server) {
  return new Promise(function(resolve, reject) {
    assert(args.length === 18, "wrong args length");
    var cipher_suite = args[0];
    var client_random = args[1];
    var server_random = args[2];
    var pms1 = args[3];
    var pms2 = args[4];
    var server_certchain = args[5];
    var tlsver = args[6];
    var initial_tlsver = args[7];
    var fullresp_length = args[8];
    var fullresp = args[9];
    var IV_after_finished_length = args[10];
    var IV_after_finished = args[11];
    var notary_modulus_length = args[12];
    var signature = args[13];
    var commit_hash = args[14];
    var notary_modulus = args[15];
    var data_with_headers = args[16];
    var time = args[17];

    var server_chain_serialized = []; //3-byte length prefix followed by cert
    for (var i = 0; i < server_certchain.length; i++) {
      var cert = server_certchain[i];
      server_chain_serialized = [].concat(
        server_chain_serialized,
        bi2ba(cert.length, {
          'fixed': 3
        }),
        cert);
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
      time);

    var commonName = getCommonName(server_certchain[0]);
    var creationTime = getTime();
    var session_dir = makeSessionDir(commonName, creationTime);
    console.log('SAVING SESSION', session_dir)
    writeFile(session_dir, 'creationTime', creationTime)
      .then(function() {
        console.log('wrote file', data_with_headers, session_dir)
        return writeDatafile(data_with_headers, session_dir)
      })
      .then(function() {
        return writePgsg(pgsg, session_dir, commonName);
      })
      .then(function() {
        // return openTabs(session_dir);
      })
      .then(function() {
        updateCache(sha256(pgsg));
        resolve();
      });
    
  });
}


//data_with_headers is a string
function writeDatafile(data_with_headers, session_dir) {
  return new Promise(function(resolve, reject) {
    var rv = data_with_headers.split('\r\n\r\n');
    var headers = rv[0];
    var data = rv.splice(1).join('\r\n\r\n');
    var header_lines = headers.split('\r\n');
    var type = 'unknown';
    for (var i = 0; i < header_lines.length; i++) {
      if (header_lines[i].search(/content-type:\s*/i) > -1) {
        type = get_type(header_lines[i]);
        break;
      }
    }
    
    function get_type(line){
      var t;
      var match = line.match('application/|text/|image/');
      if (!match) {
        t = 'unknown';
      }
      else {
        var afterslash = line.slice(match.index + match[0].length);
        //search until either + , ; or <space> is encountered
        var delimiter = afterslash.match(/\+|;| /);
        if (!delimiter) {
          t = afterslash;
        }
        else {
          t = afterslash.slice(0, delimiter.index);
        }
      }
      if (!t.length) t = 'unknown';
      if (t == 'vnd.ms-excel') t = 'xls';
      if (t == 'vnd.openxmlformats-officedocument.spreadsheetml.sheet') t = 'xlsx';
      if (t == 'plain') t = 'txt';
      return t;
    }
    
    
    if (type === "html") {
      //disabling for now because there are no issues displaying without the marker
      //html needs utf-8 byte order mark
      //data = ''.concat(String.fromCharCode(0xef, 0xbb, 0xbf), data);
    }
    console.log('WRITE DATA FILE', type)
    writeFile(session_dir, 'dataType', type).then(function() {
      return writeFile(session_dir, 'data', str2ba(data));
    }).then(function() {
      return writeFile(session_dir, 'raw.txt', data_with_headers);
    }).then(function() {
      console.log('wrote')
      resolve();
    });

  });
}



function writePgsg(pgsg, session_dir, commonName) {
  return new Promise(function(resolve, reject) {

    var dirname = session_dir.split('/').pop();
    var name = commonName.replace(/\*\./g, "");
    writeFile(dirname, 'pgsg.pgsg', pgsg).then(function() {
      return writeFile(dirname, 'meta', name);
    }).then(function() {
      return writeFile(dirname, 'metaDomainName', commonName);
    }).then(function() {
      resolve();
    });
  });
}

// function download_file(data, message){
//     console.log('view file button clicked');
//     //get the Blob and create an invisible download link
//     var ab = ba2ab(data);
//     var exportedBlob = new Blob([ab]);
//     var exportedBlobUrl = URL.createObjectURL(exportedBlob, {
//       type: 'application/octet-stream'
//     });
//     var fauxLink = document.createElement('a');
//     fauxLink.href = exportedBlobUrl;
//     fauxLink.setAttribute('download', message);
//     document.body.appendChild(fauxLink);
//     fauxLink.click();
// }

function writeFile(dirName, fileName, data) {
  return new Promise(function(resolve, reject) {
    const items = ResultsStorage
    //get the Object, append data and write it back
    var obj = {};
    console.log('OBj', obj, Object.keys(items), Object.keys(ResultsStorage))
    if (Object.keys(items).length > 0) {
      obj = items[dirName];
    }
    console.log('items to write', obj)
    obj[fileName] = data;
    obj['lastModified'] = new Date().toString();
    console.log('WRITING FILE', obj)
    ResultsStorage[dirName] = obj
    console.log('in WriteFile wrote: ', dirName, obj);
    // if(obj['pgsg.pgsg']) {
    //   download_file(obj['pgsg.pgsg'], 'pgsg.pgsg')
    // }
    resolve();
    // chrome.storage.local.set({
    //   [dirName]: obj
    // }, function() {
    //   //lastError undefined on Chrome and null on Firefox
    //   //TODO check error
    //   //if (! chrome.runtime.lastError){
    //   //	console.log('error in storage.local.set: ', chrome.runtime.lastError.message);
    //   //	}
    //   console.log('in WriteFile wrote: ', dirName, obj);
    //   if(obj['pgsg.pgsg']) {
    //     download_file(obj['pgsg.pgsg'], 'pgsg.pgsg')
    //   }
    //   resolve();
    // });
  });
}


//imported_data is an array of numbers
function verify_tlsn(data, from_past) {
  var offset = 0;
  if (ba2str(data.slice(offset, offset += 29)) !== "tlsnotary notarization file\n\n") {
    throw ('wrong header');
  }
  if (data.slice(offset, offset += 2).toString() !== [0x00, 0x02].toString()) {
    throw ('wrong version');
  }
  var cs = ba2int(data.slice(offset, offset += 2));
  var cr = data.slice(offset, offset += 32);
  var sr = data.slice(offset, offset += 32);
  var pms1 = data.slice(offset, offset += 24);
  var pms2 = data.slice(offset, offset += 24);
  var chain_serialized_len = ba2int(data.slice(offset, offset += 3));
  var chain_serialized = data.slice(offset, offset += chain_serialized_len);
  var tlsver = data.slice(offset, offset += 2);
  var tlsver_initial = data.slice(offset, offset += 2);
  var response_len = ba2int(data.slice(offset, offset += 8));
  var response = data.slice(offset, offset += response_len);
  var IV_len = ba2int(data.slice(offset, offset += 2));
  var IV = data.slice(offset, offset += IV_len);
  var sig_len = ba2int(data.slice(offset, offset += 2));
  var sig = data.slice(offset, offset += sig_len);
  var commit_hash = data.slice(offset, offset += 32);
  var notary_pubkey = data.slice(offset, offset += sig_len);
  var time = data.slice(offset, offset += 4);
  assert(data.length === offset, 'invalid .pgsg length');

  offset = 0;
  var chain = []; //For now we only use the 1st cert in the chain
  while (offset < chain_serialized.length) {
    var len = ba2int(chain_serialized.slice(offset, offset += 3));
    var cert = chain_serialized.slice(offset, offset += len);
    chain.push(cert);
  }

  var commonName = getCommonName(chain[0]);
  //verify cert
  if (!verifyCert(chain)) {
    throw ('certificate verification failed');
  }
  var modulus = getModulus(chain[0]);
  //verify commit hash
  if (sha256(response).toString() !== commit_hash.toString()) {
    throw ('commit hash mismatch');
  }
  //verify sig
  var signed_data = sha256([].concat(commit_hash, pms2, modulus, time));
  var signing_key;
  if (from_past) {
    signing_key = notary_pubkey;
  } else {
    signing_key = chosen_notary.modulus;
  }
  if (!verify_commithash_signature(signed_data, sig, signing_key)) {
    throw ('notary signature verification failed');
  }

  //decrypt html and check MAC
  var s = new TLSNClientSession();
  s.__init__();
  s.unexpected_server_app_data_count = response.slice(0, 1);
  s.chosen_cipher_suite = cs;
  s.client_random = cr;
  s.server_random = sr;
  s.auditee_secret = pms1.slice(2, 2 + s.n_auditee_entropy);
  s.initial_tlsver = tlsver_initial;
  s.tlsver = tlsver;
  s.server_modulus = modulus;
  s.set_auditee_secret();
  s.auditor_secret = pms2.slice(0, s.n_auditor_entropy);
  s.set_auditor_secret();
  s.set_master_secret_half(); //#without arguments sets the whole MS
  s.do_key_expansion(); //#also resets encryption connection state
  s.store_server_app_data_records(response.slice(1));
  s.IV_after_finished = IV;
  s.server_connection_state.seq_no += 1;
  s.server_connection_state.IV = s.IV_after_finished;
  html_with_headers = decrypt_html(s);
  return [html_with_headers, commonName, data, notary_pubkey];
}



function makeSessionDir(server, creationTime, is_imported) {

  if (typeof(is_imported) === "undefined") {
    is_imported = false;
  }
  var imported_str = is_imported ? "-IMPORTED" : "";
  var server_sanitized = server;
  if (server.search(/\*/) > -1) {
    var parts = server.split('.');
    server_sanitized = parts[parts.length - 2] + '.' + parts[parts.length - 1];
  }
  var name = 'session-' + creationTime + '-' + server_sanitized + imported_str;
  return name;
}


//imported_data is an array of numbers
function verify_tlsn_and_show_data(imported_data, create) {
  try {
    var a = verify_tlsn(imported_data, create);
  } catch (e) {
    sendAlert({
      title: 'PageSigner failed to import file',
      text: 'The error was: ' + e
    });
    return;
  }
  if (create) {
    var data_with_headers = a[0];
    var commonName = a[1];
    var imported_data = a[2];
    var creationTime = getTime();
    var session_dir = makeSessionDir(commonName, creationTime, true);
    writeFile(session_dir, 'creationTime', creationTime)
      .then(function() {
        return writeDatafile(data_with_headers, session_dir);
      })
      .then(function() {
        console.log('resolved from writeDataFile');
        return writePgsg(imported_data, session_dir, commonName);
      })
      .then(function() {
        console.log('resolved from writePgsg');
        // openTabs(session_dir);
        updateCache(sha256(imported_data));
        // populateTable(); //refresh manager
      })
      .catch(function(error) {
        console.log("got error in vtsh: " + error);
      });
  }
}


// function openTabs(dirname) {
//   var commonName;
//   var dataType;
//   const pathRoot = 'http://localhost:9000/webextension/content/'
//   getFileContent(dirname, "metaDomainName")
//     .then(function(data) {
//       commonName = data;
//       return getFileContent(dirname, "dataType");
//     })
//     .then(function(dt) {
//       dataType = dt;
//       return getFileContent(dirname, 'data');
//     })
//     .then(function(data) {
//       chrome.tabs.create({
//           url: pathRoot + 'viewer.html'
//         },
//         function(t) {
//           setTimeout(function() {
//             chrome.runtime.sendMessage({
//               destination: 'viewer',
//               type: dataType,
//               data: data,
//               sessionId: dirname,
//               serverName: commonName
//             });
//           }, 100);
//         });
//     });
// }



// function getFileContent(dirname, filename) {
//   return new Promise(function(resolve, reject) {
//
//     chrome.storage.local.get(dirname, function(items) {
//       //TODO check if dirname filename exist
//       console.log('in getFileContent got', items);
//       resolve(items[dirname][filename]);
//     });
//   });
// }


function getModulus(cert) {
  var c = Certificate.decode(new Buffer(cert), 'der');
  var pk = c.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey.data;
  var pkba = ua2ba(pk);
  //expected modulus length 256, 384, 512
  var modlen = 256;
  if (pkba.length > 384) modlen = 384;
  if (pkba.length > 512) modlen = 512;
  var modulus = pkba.slice(pkba.length - modlen - 5, pkba.length - 5);
  return modulus;
}


function getCommonName(cert) {
  var c = Certificate.decode(new Buffer(cert), 'der');
  var fields = c.tbsCertificate.subject.value;
  for (var i = 0; i < fields.length; i++) {
    if (fields[i][0].type.toString() !== [2, 5, 4, 3].toString()) continue;
    //first 2 bytes are DER-like metadata
    return ba2str(fields[i][0].value.slice(2));
  }
  return 'unknown';
}


function permutator(inputArr) {
  var results = [];

  function permute(arr, memo) {
    var cur, memo = memo || [];

    for (var i = 0; i < arr.length; i++) {
      cur = arr.splice(i, 1);
      if (arr.length === 0) {
        results.push(memo.concat(cur));
      }
      permute(arr.slice(), memo.concat(cur));
      arr.splice(i, 0, cur[0]);
    }

    return results;
  }

  return permute(inputArr);
}


function verifyCert(chain) {
  var chainperms = permutator(chain);
  for (var i = 0; i < chainperms.length; i++) {
    if (verifyCertChain(chainperms[i])) {
      return true;
    }
  }
  return false;
}



function updateCache(hash) {
  if (!(hash.toString() in valid_hashes)) {
    valid_hashes.push(hash.toString());
    MemoryStorage['valid_hashes'] = valid_hashes
  }
}

function sendAlert(alertData) {
  console.error(alertData)
}

function initNotarization() {
  const notarizeDetails = {"frameId":0,"method":"GET","parentFrameId":-1,"requestHeaders":[{"name":"Upgrade-Insecure-Requests","value":"1"},{"name":"User-Agent","value":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36"},{"name":"Sec-Fetch-Mode","value":"navigate"},{"name":"Sec-Fetch-User","value":"?1"},{"name":"DNT","value":"1"},{"name":"Accept","value":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"}],"requestId":"10228","tabId":425,"timeStamp":1569675481867.121,"type":"main_frame","url":"https://graph.facebook.com/v4.0/me?fields=id%2Cname&access_token=EAAFTXg7DaVIBANhZAgZBIVOeo92pUl3OtsCsoFtIrpiivo40kmuG5ve9Gor0LC8dADbp9pYmJzC0WgpfFz6sqVleKQhQZBrZAnbf4r69CrMZBGDvXdcuekZCsNYgtLZBJWNnN7kaVkjYCGA1g2sdSke4OEB3UcUeqgFDLYYA2AaeuVDl7d5ZC7I80ZAJ2mppHvIMZD","requestBody":null}
  var rv = getHeaders(notarizeDetails);
  //we must return fast hence the async invocation
  console.log('START NOTARIZING', rv.headers, rv.server, rv.port)
  return startNotarizing(rv.headers, rv.server, rv.port);
}

//This must be at the bottom, otherwise we'd have to define each function
//before it gets used.
fixcerts()
init()
.then(res => {
  console.log('initialized')
  initNotarization()
  .then(results => {
    console.log('NOTARIZED SUCCESSFULLY')
    fs.writeFile('notarize2.pgsg', new Buffer(results['pgsg.pgsg']), console.log)
  })
})
