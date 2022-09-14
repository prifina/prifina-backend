const { parseJwt, getRequest, postRequest } = require("./libUtils");
const { putS3Object, addNotification } = require("./serviceUtils.js");

function getBaseString(httpMethod, apiUrl, p) {
  const oAuthParameters = Object.keys(p)
    .sort()
    .map((k) => {
      return `${k}=${p[k]}`;
    });

  console.log(oAuthParameters);
  return [
    httpMethod,
    encodeURIComponent(apiUrl),
    encodeURIComponent(oAuthParameters.join("&")),
  ].join("&");
}
function getEncodedSignature(encodedBaseString, key, token = "") {
  const CRYPTO = require("crypto");
  const hash = CRYPTO.createHmac("sha1", key + "&" + token)
    .update(encodedBaseString)
    .digest("base64");

  return encodeURIComponent(hash);
}
function getHeaderOAuth(p) {
  const oAuthParameters = Object.keys(p)
    .sort()
    .map((k) => {
      return `${k}="${p[k]}"`;
    });

  //console.log(oAuthParameters);
  return "OAuth " + oAuthParameters.join(", ");
}
function refreshFitbitAccessToken(clientID, clientSecret, refreshToken) {
  try {
    const oAuth =
      "Basic " + Buffer.from(clientID + ":" + clientSecret).toString("base64");
    const parts = ["grant_type=refresh_token", "refresh_token=" + refreshToken];
    console.log(parts.join("&"));
    console.log(oAuth);
    const apiUrl = "https://api.fitbit.com/oauth2/token";
    return postRequest(apiUrl, oAuth, parts.join("&"));
  } catch (e) {
    console.log("ERR ", e);
    return Promise.reject(e);
  }
}

async function checkFitbitToken(tokens, tokenKey, dataBucket) {
  try {
    let jwt = parseJwt(tokens.access_token);
    //console.log("JWT ", jwt);
    jwt.exp = jwt.exp * 1000;
    console.log(jwt);
    const ts = new Date().getTime();
    if (ts > jwt.exp) {
      console.log("GET REFRESH TOKEN...");
      const newTokens = await refreshFitbitAccessToken(
        tokens.ClientId,
        tokens.ClientSecret,
        tokens.refresh_token
      );
      console.log(newTokens);
      let tokenJSON = JSON.parse(newTokens);
      tokenJSON = { ...tokens, ...tokenJSON };

      await putS3Object({
        Bucket: dataBucket,
        Key: tokenKey,
        Body: JSON.stringify(tokenJSON),
        ContentType: "application/json",
      });
      await addNotification({
        type: "FITBIT-TOKEN-UPDATE",
        body: JSON.stringify({
          service: "fitbit",
          action: "new access token received",
        }),
        status: 0,
        event: "DATA-SOURCE",
        prifinaID: tokenJSON.prifinaId,
      });
      return Promise.resolve(tokenJSON);
    }
  } catch (err) {
    await addNotification({
      type: "FITBIT-TOKEN-UPDATE-ERROR",
      body: JSON.stringify({
        service: "fitbit",
        action: "access token refresh failed",
      }),
      status: 0,
      event: "DATA-SOURCE",
      prifinaID: tokens.prifinaId,
    });
    return Promise.reject(err);
  }

  return Promise.resolve(tokens);
}
function refreshOuraAccessToken(clientID, clientSecret, refreshToken) {
  try {
    const oAuth =
      "Basic " + Buffer.from(clientID + ":" + clientSecret).toString("base64");
    const parts = ["grant_type=refresh_token", "refresh_token=" + refreshToken];
    console.log(parts.join("&"));
    console.log(oAuth);
    const apiUrl = "https://api.ouraring.com/oauth/token";
    return postRequest(apiUrl, oAuth, parts.join("&"));
  } catch (e) {
    console.log("ERR ", e);
    return Promise.reject(e);
  }
}

async function checkOuraToken(tokens, tokenKey, dataBucket) {
  try {
    /*
    let jwt = parseJwt(tokens.access_token);
    jwt.exp = jwt.exp * 1000;

    console.log(jwt);
    */
    // Access token is not jwt
    /*
{
  "access_token": "35RXMIU7KUXBQONVFTGH4LNTYXI5UMA7",
  "token_type": "Bearer",
  "expires_in": 86400,
  "refresh_token": "COPMFQPO47Z4LBT3FTHLMUMICX6LFF45",
  "prifinaId": "6145b3af07fa22f66456e20eca49e98bfe35",
  "ClientId": "3OFQV2FZMV566W7Y",
  "ClientSecret": "I6C2JQMDWMVBJ4YZDKZ2FHTZNMOXJQFF",
  "exp": 1636126980888,
  "user_id": "OURA"
}

*/
    if (
      tokens.hasOwnProperty("token_type") &&
      tokens.token_type === "Personal"
    ) {
      return Promise.resolve(tokens);
    }
    //Key: ["integrations", "oura", prifinaID, "tokens"].join("/") + ".json",
    const prifinaID = tokenKey.split("/")[2];

    const ts = new Date().getTime();
    if (ts > tokens.exp) {
      console.log("GET REFRESH TOKEN...");
      const newTokens = await refreshOuraAccessToken(
        tokens.ClientId,
        tokens.ClientSecret,
        tokens.refresh_token
      );
      console.log(newTokens);
      let tokenJSON = JSON.parse(newTokens);
      if (tokenJSON.hasOwnProperty("access_token")) {
        tokenJSON.exp = ts + tokenJSON.expire_in * 1000;
        tokenJSON = { ...tokens, ...tokenJSON };

        await putS3Object({
          Bucket: dataBucket,
          Key: tokenKey,
          Body: JSON.stringify(tokenJSON),
          ContentType: "application/json",
        });

        await addNotification({
          type: "OURA-TOKEN-UPDATE",
          body: JSON.stringify({
            service: "oura",
            action: "new access token received",
          }),
          status: 0,
          event: "DATA-SOURCE",
          prifinaID: prifinaID,
        });

        return Promise.resolve(tokenJSON);
      } else {
        await addNotification({
          type: "OURA-TOKEN-UPDATE-ERROR",
          body: JSON.stringify({
            service: "oura",
            action: "access token refresh failed",
          }),
          status: 0,
          event: "DATA-SOURCE",
          prifinaID: prifinaID,
        });

        return Promise.reject("INVALID_GRANT");
      }
    }
  } catch (err) {
    return Promise.reject(err);
  }

  return Promise.resolve(tokens);
}

module.exports = {
  checkFitbitToken,
  refreshFitbitAccessToken,
  refreshOuraAccessToken,
  checkOuraToken,
  getBaseString,
  getEncodedSignature,
  getHeaderOAuth,
};
