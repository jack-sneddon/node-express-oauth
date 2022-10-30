/**
 * OAuth Lab 
 * 
 * Solution:
 * Soham Kamani (sohamkamani)
 * https://github.com/pluralsight-projects/node-express-oauth/blob/module1-solution/protected-resource.js 
 */
const express = require("express")
const bodyParser = require("body-parser")
const fs = require("fs")
const { timeout } = require("./utils")
const jwt = require("jsonwebtoken")

const config = {
	port: 9002,
	publicKey: fs.readFileSync("assets/public_key.pem"),
}

const users = {
	user1: {
		username: "user1",
		name: "User 1",
		date_of_birth: "7th October 1990",
		weight: 57,
	},
	john: {
		username: "john",
		name: "John Appleseed",
		date_of_birth: "12th September 1998",
		weight: 87,
	},
}

const app = express()
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
/*
	******** Server Routes **********
*/
app.get('/user-info', (req, res) => {

	if (!req.headers.authorization) {
		res.status(401).send("Error: user not authorized")
		return
	}

	var bearerToken = req.headers.authorization.slice("bearer ".length)
	var tokenData = null

	if (!bearerToken) {
		res.status(401).send("Error: no bearer token provided")
		return
	}
	try {
		tokenData = jwt.verify(bearerToken, config.publicKey, {
			algorithms: ["RS256"],
		})

	}
	catch {
		res.status(401).send("Error: client did not provide bearer token")
		return
	}

	// make sure we have the data 
	if (!tokenData) {
		res.status(401).send("Error: client did not provide token info")
		return
	}

	const user = users[tokenData.userName]
	const userWithRestrictedFields = {}
	const scope = tokenData.scope.split(" ")
	for (let i = 0; i < scope.length; i++) {
		const field = scope[i].slice("permission:".length)
		userWithRestrictedFields[field] = user[field]
	}

	res.json(userWithRestrictedFields)

})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes
module.exports = {
	app,
	server,
}
