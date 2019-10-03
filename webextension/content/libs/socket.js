const net = require('net')
const {
  ba2int,
  arrayBufferToBufferCycle,
  formatSendData,
  toArrayBuffer
} = require('./utils')

const { ba2str, } = require('./tlns_utils')

/**
 * File: socket.js
 */

function check_complete_records(d) {
  /*'''Given a response d from a server,
  we want to know if its contents represents
  a complete set of records, however many.'''
  */
  var complete_records = [];
  var incomplete_records = [];

  while (d) {
    if (d.length < 5) {
      return {
        'is_complete': false,
        'comprecs': complete_records,
        'incomprecs': d
      };
    }
    var l = ba2int(d.slice(3, 5));
    if (d.length < (l + 5)) {
      return {
        'is_complete': false,
        'comprecs': complete_records,
        'incomprecs': d
      };
    } else if (d.length === (l + 5)) {
      return {
        'is_complete': true,
        'comprecs': [].concat(complete_records, d)
      };
    } else {
      complete_records = [].concat(complete_records, d.slice(0, l + 5));
      d = d.slice(l + 5);
      continue;
    }
  }
}

function Socket(name, port) {
  this.name = name;
  this.port = port;
  this.uid = Math.random().toString(36).slice(-10);
  this.buffer = [];
  this.recv_timeout = 20 * 1000;
  console.log('CREATING NEW SOCKET', this.name, this.port, this.uid)
}

//The only way to determine if the server is done sending data is to check that the receiving
//buffer has nothing but complete TLS records i.e. that there is no incomplete TLS records
//However it was observed that in cases when getting e.g. zip files, some servers first send HTTP header as one
//TLS record followed by the body as another record(s)
//That's why after receiving a complete TLS record we wait to get some more data
//This extra waiting must not be done for the handshake messages to avoid adding latency and having the handshake
//dropped by the server
Socket.prototype.recv = function(is_handshake) {
  if (typeof(is_handshake) === 'undefined') {
    is_handshake = false;
  }
  var that = this;
  return new Promise(function(resolve, reject) {
    var startTime = new Date().getTime();
    var complete_records = [];
    var buf = [];
    var resolved = false;

    var timer = setTimeout(function() {
      reject('recv: socket timed out');
      resolved = true;
    }, that.recv_timeout);

    var check = function() {
      //console.log('check()ing for more data', uid);
      if (resolved) {
        console.log('returning because resolved');
        return;
      }
      if (that.buffer.length === 0) {
        setTimeout(function() {
          check()
        }, 100);
        return;
      }
      console.log('new data in check', that.buffer.length);
      //else got new data
      buf = [].concat(buf, that.buffer);
      that.buffer = [];
      var rv = check_complete_records(buf);
      complete_records = [].concat(complete_records, rv.comprecs);
      if (!rv.is_complete) {
        buf = rv.incomprecs;
        setTimeout(function() {
          check()
        }, 100);
        return;
      } else {
        function finished_receiving() {
          clearTimeout(timer);
          console.log('recv promise resolving', that.uid);
          resolved = true;
          resolve(complete_records);
        };

        console.log("got complete records", that.uid);
        if (is_handshake) {
          finished_receiving();
          return;
        } else {
          console.log("in recv waiting for an extra second", that.uid);
          buf = [];
          //give the server another second to send more data
          setTimeout(function() {
            if (that.buffer.length === 0) {
              finished_receiving();
              return;
            } else {
              console.log('more data received after waiting for a second', that.uid);
              check();
            }
          }, 1000);
        }
      }
    };
    check();
  });
};

Socket.prototype.connect = function() {

  const that = this;
  // NEW SOCKET
  this.netSocket = new net.Socket()
  this.netSocket.setTimeout(300000)
  this.buffer = []

  return new Promise(function(resolve, reject) {
    that.netSocket.connect(that.port, that.name, () => {
      setTimeout(() => { resolve('ready') }, 100)
    })

    that.netSocket.on('data', function (data) {
      const d = toArrayBuffer(data)
      var view = new DataView(d);
      var int_array = [];
      console.log('data', view.byteLength)
      for(var i=0; i < view.byteLength; i++){
          int_array.push(view.getUint8(i));
      }
      var str = ba2str(int_array);
      that.buffer = [].concat(that.buffer, int_array);

    });
    
    that.netSocket.on('end', function (err) {
      reject('connect: socket ended from peer')
    });

    that.netSocket.on('timeout', function (err) {
      console.log('SOCKET TIMEOUT', err)
      reject('connect: socket timed out')
    });

    that.netSocket.on('error', function (err) {
      console.log('SOCKET ERROR', err)
    });

    that.netSocket.on('close', function (err) {
      console.log('CLOSED SOCKET', that.uid)
      reject('connect: socket closed')
    });
  });
};

Socket.prototype.send = function(data_in) {
  return this.netSocket.write(formatSendData(data_in));
}

Socket.prototype.close = function() {
  this.netSocket.end()
  this.netSocket.destroy()
}

module.exports = Socket

