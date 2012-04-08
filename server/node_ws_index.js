var	ws = require("./ws");
var emitters = {};
var cnt = 0;
ws.createServer(function (emitter) {
	emitter.addListener("connect", function (socketid) { 
		emitters[socketid] = emitter;
		emitter.write("Welcome " + socketid);
		console.log("Welcome " + socketid);
		cnt++;
		console.log(cnt);
	}).addListener("data", function (data) { 
		for(var id in emitters){
			if(id!=data.socketid){
				emitters[id].write(data.socketid + ': ' +data.data);
			};
		};
	}).addListener("close", function (socketid) { 
		for(var key in emitters){
			if(key==socketid){
				emitter.end();
				console.log("delete " + key);
				delete emitters[key];
				cnt--;
				break;
			};
		};
		console.log(cnt);
	});
}).listen(8080);

var antinode = require('./webserver/antinode')
  , fs = require('fs')
  , sys = require('util');

fs.readFile(process.argv[2] || './settings.json', function(err, data) {
    var settings = {};
    if (err) {
        sys.puts('No settings.json found ('+err+'). Using default settings');
    } else {
        try {
            settings = JSON.parse(data.toString('utf8',0,data.length));
        } catch (e) {
            sys.puts('Error parsing settings.json: '+e);
            process.exit(1);
        }
    }
    antinode.start(settings);
});
