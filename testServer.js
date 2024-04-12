

const http = require('http')

http.createServer((req, res) => {
	console.log("Connection ")
	res.writeHead(200, {
		'Content-Type':'text/html',
		'Server':'Apache2 3.4.2',
		'SomethingElse':'fucks',
		'X-AspNetMvc-Version':'1.0.0',
		'X-Content-Type-Options':'somethingelse',
		'X-Frame-Options':'allow',
		'Cache-Control':'dontknow',
		'X-Powered-CMS':'WordPress'
	})
	res.write("Test page")
	res.end()

}).listen(8000)
