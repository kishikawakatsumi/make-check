"use strict";

if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

const { createAppAuth } = require("@octokit/auth-app");
const { Octokit } = require("@octokit/rest");

const express = require("express");
const compression = require("compression");

const IpFilter = require("express-ipfilter").IpFilter;
const ips = process.env["IP_ALLOW_LIST"].split(",");

const privateKey = Buffer.from(process.env.PRIVATE_KEY, "base64").toString();

run().catch((err) => console.log(err));

async function run() {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(compression());

  app.get("/", (req, res) => {
    res.json({ status: "pass" });
  });

  app.post("/webhook", (req, res) => {
    res.sendStatus(200);
  });

  app.post(
    "/repos/:owner/:repo/check-runs",
    IpFilter(ips, {
      mode: "allow",
      detectIp: (req, res) =>
        req.headers["x-real-ip"] || req.connection.remoteAddress,
    }),
    async (req, res, next) => {
      try {
        const owner = req.params.owner;
        const repo = req.params.repo;

        if (owner !== req.body.owner || repo !== req.body.repo) {
          console.error("Invalid owner or repo");
          res.status(400).send("Invalid owner or repo");
          return;
        }

        const appClient = await makeAppClient();
        const installation = await appClient.rest.apps.getRepoInstallation({
          owner,
          repo,
        });
        const installationId = installation.data.id;
        const installationClient = await makeInstallationClient(installationId);

        if (!req.body.head_sha) {
          console.error("Missing head_sha");
          res.status(400).send("Missing head_sha");
          return;
        }

        const checkRun = await installationClient.rest.checks.create(req.body);
        res.sendStatus(checkRun.status);
      } catch (error) {
        console.error(error);
        if (error.status) {
          res.sendStatus(error.status);
        } else {
          next(error);
        }
      }
    }
  );

  const port = process.env.PORT || 3000;
  app.listen(port);
}

async function makeAppClient() {
  const auth = createAppAuth({
    appId: process.env.APP_ID,
    privateKey,
    clientId: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
  });
  const { token } = await auth({ type: "app" });
  return new Octokit({ auth: token });
}

async function makeInstallationClient(installationId) {
  const auth = createAppAuth({
    appId: process.env.APP_ID,
    privateKey,
    installationId,
    clientId: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
  });
  const { token } = await auth({ type: "installation" });
  return new Octokit({ auth: token });
}
