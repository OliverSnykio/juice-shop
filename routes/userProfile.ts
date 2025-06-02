/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'

import { UserModel } from '../models/user'
import challengeUtils = require('../lib/challengeUtils')
import config from 'config'
import * as utils from '../lib/utils'
const security = require('../lib/insecurity')
const challenges = require('../data/datacache').challenges
const pug = require('pug')
const themes = require('../views/themes/themes').themes
const Entities = require('html-entities').AllHtmlEntities
const entities = new Entities()

module.exports = function getUserProfile () {
  return (req: Request, res: Response, next: NextFunction) => {
    fs.readFile('views/userProfile.pug', function (err, buf) {
      if (err != null) throw err
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        UserModel.findByPk(loggedInUser.data.id).then((user: UserModel | null) => {
          let template = buf.toString()
          let username = user?.username
          if (username?.match(/#{(.*)}/) !== null && !utils.disableOnContainerEnv()) {
            req.app.locals.abused_ssti_bug = true
            const code = username?.substring(2, username.length - 1)
            try {
              if (!code) {
                throw new Error('Username is null')
              }
              username = eval(code) // eslint-disable-line no-eval
            } catch (err) {
              username = '\\' + username
            }
          } else {
            username = '\\' + username
          }
          const theme = themes[config.get<string>('application.theme')]
          if (username) {
            template = template.replace(/_username_/g, username)
          }
          template = template.replace(/_emailHash_/g, security.hash(user?.email))
          template = template.replace(/_title_/g, entities.encode(config.get('application.name')))
          template = template.replace(/_favicon_/g, favicon())
          template = template.replace(/_bgColor_/g, theme.bgColor)
          template = template.replace(/_textColor_/g, theme.textColor)
          template = template.replace(/_navColor_/g, theme.navColor)
          template = template.replace(/_primLight_/g, theme.primLight)
          template = template.replace(/_primDark_/g, theme.primDark)
          template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))
          const fn = pug.compile(template)
          const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval' https://code.getmdl.io http://ajax.googleapis.com`
          // @ts-expect-error FIXME type issue with string vs. undefined for username
          challengeUtils.solveIf(challenges.usernameXssChallenge, () => { return user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>') })

          res.set({
            'Content-Security-Policy': CSP
          })

          res.send(fn(user))
        }).catch((error: Error) => {
          next(error)
        })
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      }
    })
  }

  function favicon () {
    return utils.extractFilename(config.get('application.favicon'))
  }
}

async function updateUser(userId, requestBody) {
  const userData = await db.loadUserData(userId);
  merge(userData, requestBody);

  log("Saving userData " + userData.toString());
  await db.saveUserData(userId, userData);
  return userData;
}

async function getRole(userId) {
  const userPermissions = await db.loadUserPermissions(userId);

  let role = "user";
  if (userPermissions.role) {
    role = userPermissions.role;
  }

  return { role };
}

/**
 * Sets or updates all attributes of the source object on the target object.
 *
 * For example if `target` is {a: 1, b: 2} and `source` is {a: 3, c: 4},
 * after calling this function `target` becomes {a: 3, b: 2, c: 4}.
 */
function merge(target, source) {
  for (const attr in source) {
    if (
      typeof target[attr] === "object" &&
      typeof source[attr] === "object"
    ) {
      merge(target[attr], source[attr])
    } else {
      target[attr] = source[attr]
    }
  }
}
