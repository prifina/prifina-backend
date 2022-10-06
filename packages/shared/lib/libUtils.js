const { urlToHttpOptions } = require("url");

const timeout = (ms) => new Promise((res) => setTimeout(res, ms));
function sliceIntoChunks(arr, chunkSize) {
  const res = [];
  for (let i = 0; i < arr.length; i += chunkSize) {
    const chunk = arr.slice(i, i + chunkSize);
    res.push(chunk);
  }
  return res;
}

function uCfirst(string) {
  return string.charAt(0).toUpperCase() + string.slice(1).toLowerCase();
}

function randomNumbers(string_length = 6) {
  const chars = "1234567890";
  let randomstring = "";
  for (let i = 0; i < string_length; i++) {
    let rnum = Math.floor(Math.random() * chars.length);
    randomstring += chars.substring(rnum, rnum + 1);
  }

  return randomstring;
}

function parseJwt(token) {
  var base64Url = token.split(".")[1];
  var base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  var jsonPayload = decodeURIComponent(
    Buffer.from(base64, "base64")
      .toString("utf-8")
      .split("")
      .map(function (c) {
        return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
      })
      .join("")
  );

  return JSON.parse(jsonPayload);
}

function addS3HiveSyntax(dateStr, dateHour) {
  //dataJSON.sleep.dateOfSleep.replace(/-/g, "/")
  const keys = ["year", "month", "day", "hour"];
  const parts = dateStr.split("/");
  let s3Key = parts.map((k, i) => {
    return keys[i] + "=" + parseInt(k);
  });
  if (typeof dateHour !== "undefined") {
    s3Key.push("hour=" + parseInt(dateHour));
  }

  return s3Key.join("/");
}

function uniqueFileName() {
  const CRYPTO = require("crypto");
  return CRYPTO.randomBytes(16).toString("hex");
}
function createNonce(len = 10) {
  const CRYPTO = require("crypto");
  return CRYPTO.randomBytes(len).toString("hex");
}
function getRequest(requestUrl, oAuth, query = "") {
  //const URL = require("url");
  const HTTPS = require("https");
  //const options = URL.parse(requestUrl);

  let options = urlToHttpOptions(new URL(requestUrl));

  options.method = "GET";

  options.headers = {
    Authorization: oAuth,
    "Content-Type": "application/json",
  };
  if (query !== "") {
    options.query = query;
  }
  /*
  ["protocol", "host", "hostname", "pathname", "href", "port"].forEach((o) => {
    options[o] = urlOptions[o];
  });
  options.path = options.pathname;
*/
  console.log("OPTIONS ", options);

  return new Promise(function (resolve, reject) {
    const req = HTTPS.request(options, (res) => {
      console.log(`statusCode: ${res.statusCode}`);
      console.log("RES ", res);
      //Handle the response
      const chunks = [];
      res.setEncoding("utf8");
      res.on("data", function (chunk) {
        chunks.push(chunk);
      });
      res.on("end", function () {
        resolve(chunks.join(""));
      });
    });

    req.on("error", (error) => {
      console.error(error);
      reject(error);
    });

    req.end();
  });
}
function postRequest(requestUrl, oAuth, body, header = {}) {
  //const body = JSON.stringify(message);
  //const URL = require("url");
  const HTTPS = require("https");
  //const options = URL.parse(requestUrl);

  let options = urlToHttpOptions(new URL(requestUrl));

  options.method = "POST";
  options.headers = {
    Authorization: oAuth,
    "Content-Type": "application/x-www-form-urlencoded",
    "Content-Length": Buffer.byteLength(body),
  };
  if (Object.keys(header).length > 0) {
    Object.keys(header).forEach(key => {
      options.headers[key] = header[key];
    })
  }
  /*
  ["protocol", "host", "hostname", "pathname", "href", "port"].forEach((o) => {
    options[o] = urlOptions[o];
  });
  options.path = options.pathname;
  */
  console.log("OPTIONS ", options);

  return new Promise(function (resolve, reject) {
    var postReq = HTTPS.request(
      options,
      function (res) {
        console.log(`POST statusCode: ${res.statusCode}`);
        //console.log("RES ", res);
        //Handle the response
        const chunks = [];
        res.setEncoding("utf8");
        res.on("data", function (chunk) {
          console.log("RES DATA ", chunk);
          chunks.push(chunk);
        });
        res.on("end", function () {
          resolve(chunks.join(""));
        });
      },
      function (err) {
        console.log("Error  " + err);
        reject(err);
      }
    );
    postReq.write(body);
    postReq.end();
  });
}
module.exports = {
  uCfirst,
  randomNumbers,
  createNonce,
  parseJwt,
  addS3HiveSyntax,
  uniqueFileName,
  getRequest,
  postRequest,
  timeout,
  sliceIntoChunks,
};
