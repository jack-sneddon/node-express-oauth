const crypto = require("crypto")
const querystring = require("querystring")

function randomString() {
	const randomBytes = crypto.randomBytes(20)
	return randomBytes.toString("base64")
}

function containsAll(arr1, arr2) {
	const arr1Set = new Set()
	for (let i = 0; i < arr1.length; i++) {
		arr1Set.add(arr1[i])
	}

	for (let i = 0; i < arr2.length; i++) {
		if (!arr1Set.has(arr2[i])) {
			return false
		}
	}
	return true
}

function decodeAuthCredentials(auth) {
	var clientCredentials = Buffer.from(auth.slice("basic ".length), "base64")
		.toString()
		.split(":")
	var clientId = querystring.unescape(clientCredentials[0])
	var clientSecret = querystring.unescape(clientCredentials[1])
	return { clientId, clientSecret }
}

function logAuthorizationCodes(authorizationCodes) {
	if(!authorizationCodes) {
		console.log("no authorization codes provided")
		return
	}

	// print out the authorizationCodes
	console.log("----\nNum authorizationCodes = " + Object.keys(authorizationCodes).length)
	var str = JSON.stringify(authorizationCodes, null, 4); // beautiful the string		
	console.log("authorizationCodes = " + str); 
	return
}


function deleteAllKeys(obj) {
	Object.keys(obj).forEach((k) => {
		delete obj[k]
	})
}

function timeout(req, res, next) {
	res.setTimeout(400, function () {
		res.status(408).end()
	})

	next()
}

module.exports = {
	randomString,
	containsAll,
	decodeAuthCredentials,
	deleteAllKeys,
	timeout,
}
