const axios = require("axios");
const CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const GATEWAY_URL = process.env.GATEWAY_URL;

async function getAccessToken(code) {
  const res = await axios.post(
    "https://github.com/login/oauth/access_token",
    {
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code: code,
      redirect_uri: `${GATEWAY_URL}/api/auth/github/callback`,
    },
    {
      headers: { Accept: "application/json" },
    }
  );

  return res.data.access_token;
}

async function getGithubUser(accessToken) {
  const res = await axios.get("https://api.github.com/user", {
    headers: {
      Authorization: `token ${accessToken}`,
    },
  });

  return res.data;
}

module.exports = { getAccessToken, getGithubUser };