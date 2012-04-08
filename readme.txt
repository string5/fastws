http://cnodejs.org/topic/4f81048f827290275d2603ad

非常轻量级的websocket server及client套件，含flash，支持draft75/76，version8/13加密格式
缘起：websocket在未来网站应用里无疑要占据重要地位，而socket.io虽然强大，但二次开发困难，庞大的构架也影响运行效率，其他一些较轻的对加密格式支持度不够全，所以，我“凭凑”出了一个自用websocket套件：

server端，借用antinode处理80端口web请求，其他websocket部分不到20k，支持draft75/76及version8/13。

client端，支持原生websocket。flash socket，用swfobject加载，加密采用draft76，那是一个6k的小文件，外面能找到的都是170k的那种。

测试：ie6,7,8, 最新的firefox, safari, chrome, opera, 360。opera要在config里开通websocket。 ie9装flsh player不成功，没做成。

所有源文件，包括flash的，都在这个压缩包里 http://hdcafe.com/ws.rar

希望得到的帮助： 找一个更简洁的webserver代替antinode 调通ie9 对version8/13加密解密部分的代码囫囵吞枣，不知其详，希望谁能消化并简化之