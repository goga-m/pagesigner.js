//converts string to bytearray
function str2ba(str){
	if (typeof(str) !== "string"){
		throw("Only type string is allowed in str2ba");
	}
	ba = [];
	for(var i=0; i<str.length; i++){
		ba.push(str.charCodeAt(i));
	}
	return ba;
}

function ba2str(ba){
	if (typeof(ba) !== "object"){
		throw("Only type object is allowed in ba2str");
	}
	var result = "";
	for (var i = 0; i < ba.length; i++) {
		result += String.fromCharCode(ba[i]);
	}
	return result;	
}


var connections ={}; //uid:{buffer:, socketId:} dictionary

chrome.runtime.onMessage.addListener(
  function(request, sender, sendResponse) {
	  console.log('received command', request.command);
		if (request.command === 'connect'){
			connections[request.uid] = {buffer:[], socketId:0};
			create_socket(request.args.name, request.args.port, sendResponse, request.uid);
			//must explicitely return true, see
			//https://code.google.com/p/chromium/issues/detail?id=343007
			return true;
		}
		else if (request.command === 'send'){
			send_data(request.args.data, connections[request.uid].socketId);
			return true;
		}
		else if (request.command === 'recv'){
			recv(sendResponse, request.uid);
			return true;
		}
		else if (request.command === 'close'){
			close(connections[request.uid].socketId);
			return true;
		}
    });


function recv(resp, uid){
	console.log('in begin recv, length', connections[uid].buffer.length, uid);
	var timer = setInterval(function(){
		if (connections[uid].buffer.length > 0){
			clearInterval(timer);
			var tmp = connections[uid].buffer;
			connections[uid].buffer = [];
			console.log('sending back', tmp);
			resp({'data':tmp});
		}
	}, 100);
	
}


function send_data(data, socketId){
	var ab = new ArrayBuffer(data.length);
	var dv = new DataView(ab);
	for(var i=0; i < data.length; i++){
		dv.setUint8(i, data[i]);
	}
	chrome.sockets.tcp.send(socketId, ab, function(sendInfo){
		if (sendInfo < 0){
			  console.log('socket send error');
		  return;
		}  
		console.log('sent');
	});
}


function create_socket(name, port, resp, uid){
	chrome.sockets.tcp.create(function(createInfo){
		var socketId = createInfo.socketId;
		connections[uid].socketId = socketId;
		chrome.sockets.tcp.connect(socketId, name , port, function(result){
			if (result < 0){
			  console.log('socket connect error');
			  resp({'retval':'socket connect error'});
			  return;
			}
			console.log('connected');
			resp({'retval':'success'});
			chrome.sockets.tcp.onReceive.addListener(function(info){
				if (info.socketId !== socketId){
					return;
				}
				var view = new DataView(info.data);
				var int_array = [];
				for(var i=0; i < view.byteLength; i++){
					int_array.push(view.getUint8(i));
				}
				var str = ba2str(int_array);
				connections[uid].buffer = [].concat(connections[uid].buffer, int_array);
			});
		});
	});
}


function close(socketId){
	chrome.sockets.tcp.close(socketId);
}
