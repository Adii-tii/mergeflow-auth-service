const User = require("../model/user");
const { encrypt } = require("../services/encryptionService");
const { generateToken } = require("../services/tokenService");
const { getAccessToken, getGithubUser } = require("../services/githubService");

// redirect to github
exports.githubLogin = (req, res) => {
  const url = `https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}&scope=user repo`;
  res.redirect(url);
};

// callback 
exports.githubCallback = async (req, res) => {
  try {
    const code = req.query.code;

    // get token from github
    const accessToken = await getAccessToken(code);

    // get user info
    const githubUser = await getGithubUser(accessToken);

    const encryptedToken = encrypt(accessToken);

    // check if user exists
    let user = await User.findOne({ githubId: githubUser.id });

    if (!user) {
      user = await User.create({
        githubId: githubUser.id,
        username: githubUser.login,
        email: githubUser.email,
        avatarUrl: githubUser.avatar_url,
        accessTokenEncrypted: encryptedToken,
      });
    } else {
      user.accessTokenEncrypted = encryptedToken;
      await user.save();
    }

    // create jwt
    const jwtToken = generateToken(user);

    console.log("cookie set!");

    // redirect frontend
    res.redirect(`${process.env.GATEWAY_URL}/api/auth/success?token=${jwtToken}`);
  } catch (error) {
    console.log(error);
    res.send("Login failed");
  }
};