
var net = require("net")
  ,	crypto = require("crypto")
  , EventEmitter = process.EventEmitter
  , flashPolicy = '<cross-domain-policy><allow-access-from domain="*" to-ports="*" /></cross-domain-policy>'
  , id = 0;

exports.createServer = function (websocketListener) {
	var that = this;

	return net.createServer(function (socket) {
		var emitter = new process.EventEmitter()
		  ,	buffer = ''
		  , version;

		socket.id = id++;
		socket.addListener("data", function (data) {
			if(!version) {
				version = handshake(this, data); // because of draft76 handshakes
				console.log(version);
				if(version){
					emitter.emit("connect", socket.id);
				}
			} else{
				if(version=='draft76' || version=='draft75'){
					buffer += data.toString("utf8");
     				var chunks = buffer.split("\ufffd"); 
				
					for(var i = 0, count = chunks.length - 1; i < count; i++) { // last is "" or a partial packet
						var chunk = chunks[i];
						if(chunk[0] == "\u0000") {
							emitter.emit("data", {socketid: socket.id, data: chunk.slice(1)});
						} else {
							socket.end();
							return;
						}
					}
			  
					buffer = chunks[count];
				} else if(version=='13' || version=='8'){
					socket.parser.add(data);
				}
			}
		})
		.addListener("end", function () {
			socket.end();
		})
		.addListener("close", function () {
			if (version) { // don't emit close from policy-requests
				emitter.emit("close", socket.id);
			}
		})
		.addListener("parser", function (packet) {
			emitter.emit("data",  {socketid: socket.id, data: packet});
		})
		.addListener("error", function (exception) {
			if (emitter.listeners("error").length > 0) {
				emitter.emit("error", exception);
			} else {
				throw exception;
			}
		});

		
		emitter.write = function (data) {
			try {
				if(version=='13' || version=='8'){
					var buf = frame(0x81, data);
					socket.write(buf, 'binary');
				}
				else{
					socket.write('\u0000', 'binary');
					socket.write(data, 'utf8');
					socket.write('\uffff', 'binary');
				}
			} catch(e) {
				// Socket not open for writing,
				// should get "close" event just before.
				socket.end();
			}
		};
		
		emitter.end = function () {
			socket.end();
		};
		
		emitter.remoteAddress = socket.remoteAddress;
		websocketListener(emitter); // emits: "connect", "data", "close", provides: write(data), end()
	});
};

function handshake(socket, data) {
	var _headers = data.toString("binary").split("\r\n")
	  , headers = {}
	  , upgradeHead
	  , version
	  , len = _headers.length;

	//console.log(_headers);
	if ( /<policy-file-request.*>/.exec(_headers[0]) ) {
		socket.write('<cross-domain-policy><allow-access-from domain="*" to-ports="*" /></cross-domain-policy>');
		socket.end();
		//console.log('flash policy');
		return;
	}
	  
	if ( _headers[0].match(/^GET /) ) {
		headers["get"] = _headers[0];
	} else {
		socket.end();
		return;
	}
	if ( _headers[ len - 1 ] ) {
		upgradeHead = _headers[ len - 1 ];
		len--;
	}
	
	while (--len) { // _headers[0] will be skipped
		var header = _headers[len];
		if (!header) continue;

		var split = header.split(": ");
		headers[ split[0].toLowerCase() ] = split[1];
	}

	// check if we have all needed headers and fetch data from them
	var match = /^GET (\/[^\s]*)/.exec(headers.get)
	  , source = match[1];

	// draft auto-sensing
	if ( headers["sec-websocket-key1"] && headers["sec-websocket-key2"] && upgradeHead ) { // 76
		version = 'draft76';
		var strkey1 = headers["sec-websocket-key1"]
		  , strkey2 = headers["sec-websocket-key2"]

		  , numkey1 = parseInt(strkey1.replace(/[^\d]/g, ""), 10)
		  , numkey2 = parseInt(strkey2.replace(/[^\d]/g, ""), 10)

		  , spaces1 = strkey1.replace(/[^\ ]/g, "").length
		  , spaces2 = strkey2.replace(/[^\ ]/g, "").length;

		if (spaces1 == 0 || spaces2 == 0 || numkey1 % spaces1 != 0 || numkey2 % spaces2 != 0) {
			socket.end();
			return;
		}

		var hash = crypto.createHash("md5")
		  , key1 = pack(parseInt(numkey1/spaces1))
		  , key2 = pack(parseInt(numkey2/spaces2));
		
		hash.update(key1);
		hash.update(key2);
		hash.update(upgradeHead);

		socket.write([
			'HTTP/1.1 101 WebSocket Protocol Handshake', // note a diff here
			'Upgrade: WebSocket',
			'Connection: Upgrade',
			'Sec-WebSocket-Origin: ' + headers.origin,
			'Sec-WebSocket-Location: ws://' + headers.host + source,
			'',
			hash.digest("binary")
		].join('\r\n'), "binary");
	}
	else if( headers["sec-websocket-key"]){ //version 8/13
		version = headers['sec-websocket-version'];
		var strkey = headers["sec-websocket-key"]
		  , sha1 = crypto.createHash('sha1');
		sha1.update(strkey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
		strkey = sha1.digest('base64');
		var arr = [
			'HTTP/1.1 101 Switching Protocols',
			'Upgrade: websocket',
			'Connection: Upgrade',
			'Sec-WebSocket-Accept: ' + strkey,
		];
		if((version=='13' || version=='8') && headers.origin){
			arr.push((version=='13' ? 'Origin' : 'Sec-WebSocket-Origin') + ': ' + headers.origin);
		}

		socket.write(arr.concat('', '').join('\r\n'), "ascii");
		
		socket.parser = new Parser();
		socket.parser.parent = socket;
		socket.parser.on('parser', function (packet) {
			this.parent.emit("parser", packet);
		});

	}
	else { // 75
		version = 'draft75';
		socket.write([
			'HTTP/1.1 101 Web Socket Protocol Handshake', // note a diff here
			'Upgrade: WebSocket',
			'Connection: Upgrade',
			'WebSocket-Origin: ' + headers.origin,
			'WebSocket-Location: ws://' + headers.host + source,
			'',
			''
		].join('\r\n'), "binary");
	}
	
	socket.setTimeout(0);
	socket.setNoDelay(true);
	return version;
}

function Parser () {
  this.state = {
    activeFragmentedOperation: null,
    lastFragment: false,
    masked: false,
    opcode: 0
  };
  this.overflow = null;
  this.expectOffset = 0;
  this.expectBuffer = null;
  this.expectHandler = null;
  this.currentMessage = '';

  var self = this;  
  this.opcodeHandlers = {
    // text
    '1': function(data) {
      var finish = function(mask, data) {
        self.currentMessage += self.unmask(mask, data);
        if (self.state.lastFragment) {
          self.emit('parser', self.currentMessage);
          self.currentMessage = '';
        }
        self.endPacket();
      }

      var expectData = function(length) {
        if (self.state.masked) {
          self.expect('Mask', 4, function(data) {
            var mask = data;
            self.expect('Data', length, function(data) {
              finish(mask, data);
            });
          });
        }
        else {
          self.expect('Data', length, function(data) { 
            finish(null, data);
          });
        } 
      }

      // decode length
      var firstLength = data[1] & 0x7f;
      if (firstLength < 126) {
        expectData(firstLength);
      }
      else if (firstLength == 126) {
        self.expect('Length', 2, function(data) {
          expectData(unpack(data));
        });
      }
      else if (firstLength == 127) {
        self.expect('Length', 8, function(data) {
          if (unpack(data.slice(0, 4)) != 0) {
            self.error('packets with length spanning more than 32 bit is currently not supported');
            return;
          }
          var lengthBytes = data.slice(4); // note: cap to 32 bit length
          expectData(unpack(data));
        });
      }      
    },
    // binary
    '2': function(data) {
      var finish = function(mask, data) {
        if (typeof self.currentMessage == 'string') self.currentMessage = []; // build a buffer list
        self.currentMessage.push(self.unmask(mask, data, true));
        if (self.state.lastFragment) {
          self.emit('binary', self.concatBuffers(self.currentMessage));
          self.currentMessage = '';
        }
        self.endPacket();
      }

      var expectData = function(length) {
        if (self.state.masked) {
          self.expect('Mask', 4, function(data) {
            var mask = data;
            self.expect('Data', length, function(data) {
              finish(mask, data);
            });
          });
        }
        else {
          self.expect('Data', length, function(data) { 
            finish(null, data);
          });
        } 
      }

      // decode length
      var firstLength = data[1] & 0x7f;
      if (firstLength < 126) {
        expectData(firstLength);
      }
      else if (firstLength == 126) {
        self.expect('Length', 2, function(data) {
          expectData(unpack(data));
        });
      }
      else if (firstLength == 127) {
        self.expect('Length', 8, function(data) {
          if (unpack(data.slice(0, 4)) != 0) {
            self.error('packets with length spanning more than 32 bit is currently not supported');
            return;
          }
          var lengthBytes = data.slice(4); // note: cap to 32 bit length
          expectData(unpack(data));
        });
      }      
    },
    // close
    '8': function(data) {
      self.emit('close');
      self.reset();
    },
    // ping
    '9': function(data) {
      if (self.state.lastFragment == false) {
        self.error('fragmented ping is not supported');
        return;
      }
      
      var finish = function(mask, data) {
        self.emit('ping', self.unmask(mask, data));
        self.endPacket();
      }

      var expectData = function(length) {
        if (self.state.masked) {
          self.expect('Mask', 4, function(data) {
            var mask = data;
            self.expect('Data', length, function(data) {
              finish(mask, data);
            });
          });
        }
        else {
          self.expect('Data', length, function(data) { 
            finish(null, data);
          });
        } 
      }

      // decode length
      var firstLength = data[1] & 0x7f;
      if (firstLength == 0) {
        finish(null, null);        
      }
      else if (firstLength < 126) {
        expectData(firstLength);
      }
      else if (firstLength == 126) {
        self.expect('Length', 2, function(data) {
          expectData(unpack(data));
        });
      }
      else if (firstLength == 127) {
        self.expect('Length', 8, function(data) {
          expectData(unpack(data));
        });
      }      
    }
  }

  this.expect('Opcode', 2, this.processPacket);  
};

/**
 * Inherits from EventEmitter.
 */

Parser.prototype.__proto__ = EventEmitter.prototype;

/**
 * Add new data to the parser.
 *
 * @api public
 */

Parser.prototype.add = function(data) {
  if (this.expectBuffer == null) {
    this.addToOverflow(data);
    return;
  }
  var toRead = Math.min(data.length, this.expectBuffer.length - this.expectOffset);
  data.copy(this.expectBuffer, this.expectOffset, 0, toRead);
  this.expectOffset += toRead;
  if (toRead < data.length) {
    // at this point the overflow buffer shouldn't at all exist
    this.overflow = new Buffer(data.length - toRead);
    data.copy(this.overflow, 0, toRead, toRead + this.overflow.length);
  }
  if (this.expectOffset == this.expectBuffer.length) {
    var bufferForHandler = this.expectBuffer;
    this.expectBuffer = null;
    this.expectOffset = 0;
    this.expectHandler.call(this, bufferForHandler);
  }
}

/**
 * Adds a piece of data to the overflow.
 *
 * @api private
 */

Parser.prototype.addToOverflow = function(data) {
//console.log('addToOverflow');
  if (this.overflow == null) this.overflow = data;
  else {
    var prevOverflow = this.overflow;
    this.overflow = new Buffer(this.overflow.length + data.length);
    prevOverflow.copy(this.overflow, 0);
    data.copy(this.overflow, prevOverflow.length);
  }  
}

/**
 * Waits for a certain amount of bytes to be available, then fires a callback.
 *
 * @api private
 */

Parser.prototype.expect = function(what, length, handler) {
	//console.log('expect');
	this.expectBuffer = new Buffer(length);
  this.expectOffset = 0;
  this.expectHandler = handler;
  if (this.overflow != null) {
    var toOverflow = this.overflow;
    this.overflow = null;
    this.add(toOverflow);
  }
}

/**
 * Start processing a new packet.
 *
 * @api private
 */

Parser.prototype.processPacket = function (data) {
	//console.log('processPacket');
  if ((data[0] & 0x70) != 0) {
    this.error('reserved fields must be empty');
    return;
  } 
  this.state.lastFragment = (data[0] & 0x80) == 0x80; 
  this.state.masked = (data[1] & 0x80) == 0x80;
  var opcode = data[0] & 0xf;
  if (opcode == 0) { 
    // continuation frame
    this.state.opcode = this.state.activeFragmentedOperation;
    if (!(this.state.opcode == 1 || this.state.opcode == 2)) {
      this.error('continuation frame cannot follow current opcode')
      return;
    }
  }
  else {    
    this.state.opcode = opcode;
    if (this.state.lastFragment === false) {
        this.state.activeFragmentedOperation = opcode;
    }
  }
  var handler = this.opcodeHandlers[this.state.opcode];
  if (typeof handler == 'undefined') this.error('no handler for opcode ' + this.state.opcode);
  else handler(data);
}

/**
 * Endprocessing a packet.
 *
 * @api private
 */

Parser.prototype.endPacket = function() {
	//console.log('endPacket');
	this.expectOffset = 0;
  this.expectBuffer = null;
  this.expectHandler = null;
  if (this.state.lastFragment && this.state.opcode == this.state.activeFragmentedOperation) {
    // end current fragmented operation
    this.state.activeFragmentedOperation = null;
  }
  this.state.lastFragment = false;
  this.state.opcode = this.state.activeFragmentedOperation != null ? this.state.activeFragmentedOperation : 0;
  this.state.masked = false;
  this.expect('Opcode', 2, this.processPacket);  
}

/**
 * Reset the parser state.
 *
 * @api private
 */

Parser.prototype.reset = function() {
	//console.log('reset');
	this.state = {
    activeFragmentedOperation: null,
    lastFragment: false,
    masked: false,
    opcode: 0
  };
  this.expectOffset = 0;
  this.expectBuffer = null;
  this.expectHandler = null;
  this.overflow = null;
  this.currentMessage = '';
}

/**
 * Unmask received data.
 *
 * @api private
 */

Parser.prototype.unmask = function (mask, buf, binary) {
	//console.log('unmask');
  if (mask != null) {
    for (var i = 0, ll = buf.length; i < ll; i++) {
      buf[i] ^= mask[i % 4];
    }    
  }
  if (binary) return buf;
  return buf != null ? buf.toString('utf8') : '';
}

/**
 * Concatenates a list of buffers.
 *
 * @api private
 */

Parser.prototype.concatBuffers = function(buffers) {
	//console.log('concatBuffers');
	var length = 0;
  for (var i = 0, l = buffers.length; i < l; ++i) {
    length += buffers[i].length;
  }
  var mergedBuffer = new Buffer(length);
  var offset = 0;
  for (var i = 0, l = buffers.length; i < l; ++i) {
    buffers[i].copy(mergedBuffer, offset);
    offset += buffers[i].length;
  }
  return mergedBuffer;
}

/**
 * Handles an error
 *
 * @api private
 */

Parser.prototype.error = function (reason) {
	//console.log('error');
	this.reset();
  this.emit('error', reason);
  return this;
};


function pack(num) {
	var result = '';
	result += String.fromCharCode(num >> 24 & 0xFF);
	result += String.fromCharCode(num >> 16 & 0xFF);
	result += String.fromCharCode(num >> 8 & 0xFF);
	result += String.fromCharCode(num & 0xFF);
	return result;
}

function unpack(buffer) {
  var n = 0;
  for (var i = 0; i < buffer.length; ++i) {
    n = (i == 0) ? buffer[i] : (n * 256) + buffer[i];
  }
  return n;
}

function frame(opcode, str) {
  var dataBuffer = new Buffer(str)
    , dataLength = dataBuffer.length
    , startOffset = 2
    , secondByte = dataLength;
  if (dataLength > 65536) {
    startOffset = 10;
    secondByte = 127;
  }
  else if (dataLength > 125) {
    startOffset = 4;
    secondByte = 126;
  }
  var outputBuffer = new Buffer(dataLength + startOffset);
  outputBuffer[0] = opcode;
  outputBuffer[1] = secondByte;
  dataBuffer.copy(outputBuffer, startOffset);
  switch (secondByte) {
  case 126:
    outputBuffer[2] = dataLength >>> 8;
    outputBuffer[3] = dataLength % 256;
    break;
  case 127:
    var l = dataLength;
    for (var i = 1; i <= 8; ++i) {
      outputBuffer[startOffset - i] = l & 0xff;
      l >>>= 8;
    }
  }
  return outputBuffer;
};