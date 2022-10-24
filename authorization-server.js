const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
    ******** Server Routes **********
*/
app.get('/authorize', (req, res) => {
	// console.log("\n########\n" );
	let status = 200

	let clientId = req.query['client_id']
	let reqScope = req.query['scope']
	// console.log("clientId + scope *************** > " + req.query['client_id'] + "," + reqScope);

	// check that the clientId exists
	if(clientId in clients) {
		status = 200

		// check scope
		let reqScopes = reqScope.split(" ")
		if(containsAll(clients[clientId].scopes, reqScopes)) {
			// console.log("valid clientID and scope: " + clientID + " : " + scope)
			status = 200

			// store a requestID
			var reqId = randomString()
			requests[reqId] = req.query
			// console.log("*** request ID added (" + reqId + ")")
			
			var params = {
				"client": clients[clientId],
				"scope": req.query.scope,
				requestId: reqId
			}
			res.status(status)
			res.render("login", params)
		}
		else {
			status = 401
		}

	}
	else {
		status = 401
	}

	// complete if something error (!200)
	if(status != 200) {
		res.status(status).end()
	}

  })

 
app.post('/approve', (req, res) => {
	var status = 401
	
	// if no u/p let them through 
	if(!req.body.userName) {
		status = 200
	}
	// verify username/password
	else if(req.body.userName in users && req.body.password == users[req.body.userName]) {
		// console.log("u/p = " + req.body.userName + "/" + req.body.password)
		
		// print out some stuff related to request
		/*
		console.log("reqId = " + reqId)
		console.log("----\nnum requests = " + Object.keys(requests).length)
		console.log("requests = " + Object.keys(requests));
		*/
		// check if reqID exists
		if(req.body.requestId in requests) {
			// delete from requestId requests
			var clientReq = req.body.requestId
			delete requests[req.body.requestId]
			
			// store in authorization code
			var authorizationCode = randomString()
			authorizationCodes[authorizationCode] = {
				'clientReq' : clientReq,
				'userName' : req.body.userName
			}

			// print out the authorizationCodes
			// var str = JSON.stringify(authorizationCodes, null, 4); // beautiful the string		
			// console.log("authorizationCodes = " + str); 

			status = 200	
		}
	}
	else {
		status = 401
	}

	res.status(status).end()
})


const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
